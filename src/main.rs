use std::{collections::{BTreeMap, HashMap, HashSet}, env, ffi::OsStr, fs::{DirEntry, OpenOptions}, io::{BufReader, Read, Write}, ops::Range, path::PathBuf, process::Command, str::FromStr, sync::atomic::AtomicBool};

use cargo_metadata::{camino::Utf8PathBuf, Message, MetadataCommand, Target};
use clap::Parser;
use miette::IntoDiagnostic;
use quote::ToTokens;
use syn::{punctuated::Punctuated, spanned::Spanned, visit::Visit, ItemMod, PathSegment};

const FILE_ANNOTATION_IDENTIFIER: &str = "__included_from_file";

#[derive(Debug, Parser)]
struct Args {
    /// Allow proc macro crates to be optimized as well (ignored by default)
    #[clap(long)]
    allow_proc_macro_crates: bool,
    /// Allow to run tests that aren't inside a `cfg(test)` module or a integation test
    #[clap(long)]
    allow_outside_test_mod: bool,
    /// Allow failing tests to be optimized - this will double the current values until the test succeeds
    #[clap(long)]
    allow_failing: bool,
    /// The tests to optimize
    test_paths: Vec<String>,
}

#[derive(Debug)]
struct TargetConfiguration<'a> {
    target: &'a Target,
    require_test_cfg: bool,
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
enum AppError {
    #[error("Could not find the containing folder for the module path {0}")]
    #[diagnostic(help = "This is an error and should be reported to the developers")]
    FolderNotFound(std::path::PathBuf),
    #[error("Failed to build test binaries for current project")]
    TestBuildFailed,
    #[error("Failed to find test binary for target under path {0:?}")]
    BinaryNotFound(Utf8PathBuf),
    #[error("The test {0} failed in it's initial execution and --allow-failing wasn't set ({1})")]
    InitialTestRunFailed(String, PathBuf),
    #[error("Tried increasing a tests knobs but reached the upper limit without sucess")]
    IncreaseLimitReached,
}

#[derive(Default)]
struct BuilderVisitor {
    found_literals: Vec<(proc_macro2::Span, syn::LitInt)>
}

struct CallChainVisitor {
    expected_source: syn::ExprCall,
    found_call: bool
}

impl CallChainVisitor {
    fn new(expected_source: syn::ExprCall) -> Self {
        Self { expected_source, found_call: false }
    }
}

impl<'ast> syn::visit::Visit<'ast> for CallChainVisitor {
    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        if i == &self.expected_source {
            self.found_call = true
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for BuilderVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        if i.method != "with_max_stack_size" {
            return syn::visit::visit_expr_method_call(self, i);
        }

        let mut chain_visitor = CallChainVisitor::new(syn::ExprCall {
            attrs: Vec::new(),
            func: Box::new(syn::Expr::Path(syn::ExprPath {
                attrs: Vec::new(),
                qself: None,
                path: syn::Path {
                    leading_colon: None,
                    segments: Punctuated::from_iter([
                        syn::PathSegment {
                            ident: syn::Ident::new("PushState", proc_macro2::Span::mixed_site()),
                            arguments: syn::PathArguments::None,
                        },
                        syn::PathSegment {
                            ident: syn::Ident::new("builder", proc_macro2::Span::mixed_site()),
                            arguments: syn::PathArguments::None,
                        },
                    ]),
                },
            })),
            paren_token: syn::token::Paren(proc_macro2::Span::mixed_site()),
            args: Punctuated::new(),
        });
        chain_visitor.visit_expr(&i.receiver);
        if !chain_visitor.found_call {
            return syn::visit::visit_expr_method_call(self, i);
        }
        let arg = i.args.first().unwrap();
        match arg {
            syn::Expr::Lit(syn::ExprLit{lit: lit@syn::Lit::Int(i@syn::LitInt {..}), ..}) => {
                self.found_literals.push((lit.span(), i.clone()))
            },
            _ => todo!(),
        }
        
        syn::visit::visit_expr_method_call(self, i);
    }
}

fn build_tests() -> miette::Result<HashMap<Target, Utf8PathBuf>>{
    let cargo = env::var("CARGO").map(PathBuf::from).ok()
        .unwrap_or_else(|| PathBuf::from("cargo"));

    let mut build_tests_cmd = Command::new(cargo);
    build_tests_cmd.args(["test", "--no-run", "--message-format","json","--workspace"]);
    let output = build_tests_cmd.output().into_diagnostic()?;

    if !output.status.success() {
        return Err(AppError::TestBuildFailed.into());
    }
    let out_reader = BufReader::new(&output.stdout[..]);
    Ok(Message::parse_stream(out_reader).collect::<Result<Vec<_>,_>>().into_diagnostic()?.into_iter().filter_map(|message| match message  {
        Message::CompilerArtifact(a) => Some((a.target, a.executable?)),
        _ => None,
    }).collect::<HashMap<_,_>>())
}

fn main() -> miette::Result<()> {
    let Args {
        allow_outside_test_mod,
        test_paths,
        allow_proc_macro_crates,
        allow_failing,
    } = Args::parse();

    let metadata = MetadataCommand::new().exec().into_diagnostic()?;
    let mut artifacts = build_tests()?;

    let mut file_write_offsets: HashMap<std::path::PathBuf, BTreeMap<usize, Range<usize>>> = HashMap::new();
    let mut targets_changed: AtomicBool = false.into();

    let mut update_artifacts_if_needed = |artifacts: &mut HashMap<Target, Utf8PathBuf>| -> miette::Result<()> {
        if targets_changed.load(std::sync::atomic::Ordering::Relaxed) {
            *artifacts = build_tests()?;
        }

        Ok(())
    };

    let targets = metadata
        .workspace_members
        .iter()
        .flat_map(|wm| metadata.packages.iter().find(|p| &p.id == wm))
        .flat_map(|p| &p.targets)
        .filter(|t| {
            t.kind
                .iter()
                .any(|k| allow_proc_macro_crates || *k != "proc-macro")
        })
        .filter(|t| t.test)
        .map(|t| TargetConfiguration {
            target: t,
            require_test_cfg: t.test
                && !t.kind.iter().any(|k| *k == "test")
                && !allow_outside_test_mod,
        });

    for TargetConfiguration {
        target,
        require_test_cfg,
    } in targets
    {

        println!("Starting to optimize file {}", target.src_path);
        let mut entrypoint =
            syn::parse_file(&std::fs::read_to_string(&target.src_path).into_diagnostic()?)
                .into_diagnostic()?;

        let root_folder = target.src_path.parent().ok_or_else(|| {
            AppError::FolderNotFound(target.src_path.to_owned().into_std_path_buf())
        })?;

        miette::ensure!(root_folder.is_dir(), "Parent should be a directory");

        recursively_resolve_modules(
            &mut entrypoint,
            root_folder,
            ContainingModule::Root,
        )?;

        // println!("{}", entrypoint.to_token_stream());

        let mut test_cases: HashMap<(syn::Path, std::path::PathBuf),  Vec<(Range<usize>, syn::LitInt)>> =
            HashMap::new();

        walk_module_tree(
            &target.src_path,
            &syn::Path {
                leading_colon: None,
                segments: Punctuated::new(),
            },
            !require_test_cfg || contains_test_cfg(&entrypoint.attrs),
            &syn::ItemMod {
                vis: syn::Visibility::Public(syn::Token![pub](proc_macro2::Span::mixed_site())),
                attrs: entrypoint.attrs,
                unsafety: None,
                mod_token: syn::Token![mod](proc_macro2::Span::mixed_site()),
                ident: syn::Ident::new("__root", proc_macro2::Span::mixed_site()),
                content: Some((
                    syn::token::Brace(proc_macro2::Span::mixed_site()),
                    entrypoint.items,
                )),
                semi: None,
            },
            &mut |item, current_path, test_cfg_passed, file| {
                match item {
                    syn::Item::Fn(syn::ItemFn { attrs, sig: syn::Signature { ident, ..}, block, .. }) if 
                    attrs.iter().any(|a| 
                        matches!(a, syn::Attribute {  meta: syn::Meta::Path(path), .. } if path.to_token_stream().to_string() == "test" || path.to_token_stream().to_string() == "proptest")
                    ) && test_cfg_passed => {
                        let mut test_path = current_path.clone();
                        test_path.segments.push(PathSegment { ident: ident.clone(), arguments: syn::PathArguments::None});
                        if !test_paths.is_empty() && !test_paths.iter().any(|path| syn::parse_str::<syn::Path>(path).unwrap() == test_path) {
                            return Ok(())
                        }

                        let mut visitor = BuilderVisitor::default();
                        visitor.visit_block(block);

                        for (span, lit) in visitor.found_literals {
                            let test_cases_entry = test_cases.entry((test_path.clone(), file.to_path_buf())).or_default();

                            test_cases_entry.push((span.byte_range(), lit))
                            // let current_file_offset = file_write_offsets.entry(file.to_path_buf()).or_default();
                            // let replacement = syn::LitInt::new("0xAABBCCDD", span);
                            // let mut file_buf = std::fs::File::open(file).into_diagnostic()?;
                            // let mut file_contents = Vec::new();
                            // file_buf.read_to_end(&mut file_contents).into_diagnostic()?;
                            // let mut exisiting_span = span.byte_range();
                            // exisiting_span.end = exisiting_span.end.saturating_add_signed(*current_file_offset);
                            // exisiting_span.start = exisiting_span.start.saturating_add_signed(*current_file_offset);
                            // let span_len = exisiting_span.end - exisiting_span.start;
                            // let byte_replacement = replacement.to_string().into_bytes();
                            // *current_file_offset = current_file_offset.saturating_add((byte_replacement.len()  - span_len) as isize);
                            // let (start, remainder) = file_contents.split_at(exisiting_span.start);
                            // let (_replaced, end) = remainder.split_at(span_len);
                            // let _replaced_str = String::from_utf8_lossy(_replaced);
                            // let mut file_mut = OpenOptions::new().write(true).truncate(true).open(file).into_diagnostic()?;
                            // file_mut.write_all(start).into_diagnostic()?;
                            // file_mut.write_all(replacement.to_token_stream().to_string().as_bytes()).into_diagnostic()?;
                            // file_mut.write_all(end).into_diagnostic()?;
                        }
                        // let pos = ifn.span().start();
                        // let path_str = test_path.to_token_stream().to_string();
                        // let mut file_str = file.to_string_lossy().to_string();
                        // file_str += &format!(":{}:{}", pos.line, pos.column);
                        // let block_str = block.to_token_stream().to_string();
                        // dbg!(path_str, file_str, block_str);


                        Ok(())
                    },
                    _ => Ok(()),
                }
            },
        )?;


        for ((_,file), knobs) in &test_cases {
            let this_file_offsets = file_write_offsets.entry(file.clone()).or_default();
            for knob in knobs {
                this_file_offsets.entry(knob.0.start).or_insert_with(|| knob.0.clone());
            }
            
        }

        for ((path, file), knobs) in test_cases {
            let path = format_path(&path);
            println!(" - Optimizing test {path}");

            let mut get_current_test_state = || -> miette::Result<bool>{
                update_artifacts_if_needed(&mut artifacts)?;
                let mut command = Command::new(artifacts.get(target).ok_or_else(|| AppError::BinaryNotFound(target.src_path.clone()))?);
                command.arg("--exact");
                command.arg(&path);
                Ok(command.output().into_diagnostic()?.status.success())
            };
            
            let initial_state = get_current_test_state()?;

            if !initial_state && !allow_failing  {
                return Err(AppError::InitialTestRunFailed(path, file).into());
            }

            let mut knob_values = knobs.iter().map(|knob| {
                let value = knob.1.base10_parse::<u128>()?;
                Ok::<_,syn::Error>((knob, (0u128, value)))
            }).collect::<Result<HashMap<_,_>, _>>().into_diagnostic()?;

            let mut value_under_limit = true;
            while !get_current_test_state()?  {
                if !value_under_limit {
                    return Err(AppError::IncreaseLimitReached.into());
                }
                
                value_under_limit = !knobs.is_empty();
                for knob in &knobs {
                    let (_,  ref mut upper_bound) = *knob_values.get_mut(knob).unwrap();
                    // TODO: make this depend on the type of knob.1
                    if *upper_bound == u64::MAX.into() {
                        value_under_limit = false;
                    }
                    *upper_bound = std::cmp::min(u64::MAX.into(), *upper_bound * 2);
                    let new_lit = syn::LitInt::new(&format!("{upper_bound}"), proc_macro2::Span::call_site());
                    change_knob( &mut file_write_offsets,knob ,new_lit, &file)?;
                    targets_changed.store(true, std::sync::atomic::Ordering::Relaxed);
                    println!("   - Increasing max_size at {}:{}, trying {upper_bound}", knob.1.span().start().line, knob.1.span().start().column);
                }
            }

            while knob_values.values().any(|(lower, upper)| lower.abs_diff(*upper) != 0) {
                if let Some((knob,(lower, upper))) = knob_values.iter_mut().find(|(_,(lower, upper))| lower.abs_diff(*upper) != 0) {
                    let pivot = *lower + (lower.abs_diff(*upper) / 2);
                    let new_lit = syn::LitInt::new(&format!("{pivot}"), proc_macro2::Span::call_site());
                    change_knob( &mut file_write_offsets,knob ,new_lit, &file)?;
                    targets_changed.store(true, std::sync::atomic::Ordering::Relaxed);
                    println!("   - Decreasing max_size at {}:{}, trying {pivot}", knob.1.span().start().line, knob.1.span().start().column);
                    if get_current_test_state()? {
                        *upper = pivot;
                    } else {
                        *lower = pivot + 1;
                    }
                }
            }

            for (knob, (_, final_value)) in knob_values.iter() {
                println!("   - Found optimal max_size at {}:{}: {final_value}", knob.1.span().start().line, knob.1.span().start().column);
                let new_lit = syn::LitInt::new(&format!("{final_value}"), proc_macro2::Span::call_site());
                change_knob(&mut file_write_offsets,knob ,new_lit, &file)?;
                targets_changed.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

    }

    Ok(())
}

fn change_knob(file_offsets: &mut HashMap<PathBuf, BTreeMap<usize,Range<usize>>>, knob: &(Range<usize>, syn::LitInt), new_value: syn::LitInt, path: &PathBuf) -> miette::Result<()> {
    let current_file_offset = file_offsets.get_mut(path).unwrap();

    let mut file_buf = std::fs::File::open(path).into_diagnostic()?;
    let mut file_contents = Vec::new();
    file_buf.read_to_end(&mut file_contents).into_diagnostic()?;

    let current_span = current_file_offset.get_mut(&knob.0.start).unwrap();
    let span_len = current_span.end - current_span.start;

    let byte_replacement = new_value.to_string().into_bytes();

    let offset = byte_replacement.len() as isize  - span_len as isize;
    current_span.end = current_span.end.saturating_add_signed(offset);
    let current_span = current_span.clone();

    for (_, range) in current_file_offset.iter_mut().skip_while(|(k, _)| **k <= knob.0.start) {
       range.start = range.start.saturating_add_signed(offset);
       range.end = range.end.saturating_add_signed(offset);
    }

let (start, remainder) = file_contents.split_at(current_span.start);
    let (_, end) = remainder.split_at(span_len);
    let mut file_mut = OpenOptions::new().write(true).truncate(true).open(path).into_diagnostic()?;
    file_mut.write_all(start).into_diagnostic()?;
    file_mut.write_all(&byte_replacement).into_diagnostic()?;
    file_mut.write_all(end).into_diagnostic()?;
    Ok(())
}


fn format_path(path: &syn::Path) -> String {
    let mut out = String::new();
    if let Some(leading_col) = &path.leading_colon {
        out.push_str(&leading_col.to_token_stream().to_string());
    }

    for (segment, sep) in path.segments.pairs().map(syn::punctuated::Pair::into_tuple) {
        out.push_str(&segment.to_token_stream().to_string());

        if let Some(leading_col) = &sep {
            out.push_str(&leading_col.to_token_stream().to_string());
        }
    }


    out
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
enum WalkingModTreeError {
    #[error("Encountered non-local module while waliking the module tree")]
    #[diagnostic(help = "Call recursively_resolve_modules first")]
    EmptyModule,
}

fn walk_module_tree<F>(
    file: impl AsRef<std::path::Path>,
    current_path: &syn::Path,
    test_cfg_passed: bool,
    module: &syn::ItemMod,
    to_do: &mut F,
) -> miette::Result<()>
where
    F: FnMut(&syn::Item, &syn::Path, bool, &std::path::Path) -> miette::Result<()>,
{
    for item in module.content.iter().flat_map(|c| &c.1) {
        match item {
            syn::Item::Mod(
                imod @ syn::ItemMod {
                    ref attrs,
                    ref ident,
                    content: Some((_, _)),
                    ..
                },
            ) => {
                let test_cfg_passed = test_cfg_passed || contains_test_cfg(attrs);
                let mut current_path = current_path.clone();
                current_path.segments.push(syn::PathSegment {
                    ident: ident.clone(),
                    arguments: syn::PathArguments::None,
                });
                let file = extract_file_path(attrs).unwrap_or_else(|_| file.as_ref().to_owned());

                walk_module_tree::<F>(file, &current_path, test_cfg_passed, imod, to_do)?;
            }
            syn::Item::Mod(_) => return Err(WalkingModTreeError::EmptyModule.into()),
            item => to_do(item, current_path, test_cfg_passed, file.as_ref())?,
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
enum FilePathExtractError {
    #[error("There was no attribute found indicating the file path")]
    #[diagnostic(help = "Use the recursively_resolve_modules function to resolve file modules")]
    NoFileAttr,
    #[error(
        "There was an attribute found but it wasn't a file path annotation or it was malformed"
    )]
    #[diagnostic(
        help = "Make sure the file path annotation is the last one in the list and it isn't malformed"
    )]
    FileAttrNotLast,
}

fn extract_file_path(attrs: &[syn::Attribute]) -> miette::Result<std::path::PathBuf> {
    let possible_file_attr = attrs.last().ok_or(FilePathExtractError::NoFileAttr)?;

    let syn::Meta::NameValue(syn::MetaNameValue { path, value, .. }) = &possible_file_attr.meta
    else {
        return Err(FilePathExtractError::FileAttrNotLast.into());
    };

    if path.to_token_stream().to_string() != "doc" {
        return Err(FilePathExtractError::FileAttrNotLast.into());
    }

    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(lit),
        ..
    }) = value
    else {
        return Err(FilePathExtractError::FileAttrNotLast.into());
    };

    let annotation_str = lit.value();

    let annotation_str = annotation_str
        .strip_prefix(&format!("[//]: # \"{FILE_ANNOTATION_IDENTIFIER} = "))
        .ok_or(FilePathExtractError::FileAttrNotLast)?;

    let file_path_str = annotation_str
        .strip_suffix("\" ")
        .ok_or(FilePathExtractError::FileAttrNotLast)?;

    Ok(match std::path::PathBuf::from_str(file_path_str) {
        Ok(o) => o,
        Err(_) => unreachable!("Error is infallible"),
    })
}

fn contains_test_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !matches!(a.style, syn::AttrStyle::Outer) {
            return false;
        }

        let syn::Meta::List(syn::MetaList { path, tokens, .. }) = &a.meta else {
            return false;
        };

        if path.to_token_stream().to_string() != "cfg" {
            return false;
        }

        let Ok(ident): Result<syn::Ident, _> = syn::parse2(tokens.clone()) else {
            return false;
        };

        ident == "test"
    })
}

enum ContainingModule {
    Root,
    Module(String),
}

impl ContainingModule {
    fn from_file_name(name: &OsStr) -> Self {
        if name.to_ascii_lowercase() == "mod.rs" {
            Self::Root
        } else {
            let module_name = name.to_string_lossy();
            let stripped_module_name = module_name
                .strip_suffix(".rs")
                .unwrap_or_else(|| &module_name[..]);
            Self::Module(stripped_module_name.to_owned())
        }
    }

    fn get_lookup_location(
        &self,
        containing_folder: impl AsRef<std::path::Path>,
    ) -> std::path::PathBuf {
        match self {
            Self::Root => containing_folder.as_ref().to_owned(),
            ContainingModule::Module(m) => containing_folder.as_ref().to_owned().join(m),
        }
    }
}

fn recursively_resolve_modules(
    file: &mut syn::File,
    containing_folder: impl AsRef<std::path::Path>,
    containing_module: ContainingModule,
) -> miette::Result<()> {
    for item in file.items.iter_mut().filter_map(|i| match i {
        syn::Item::Mod(mod_item @ ItemMod { content: None, .. }) => Some(mod_item),
        _ => None,
    }) {
        let file_path = resolve_file_path(&containing_folder, &containing_module, &item.ident)?;

        let mut file_contents =
            syn::parse_file(&std::fs::read_to_string(&file_path).into_diagnostic()?)
                .into_diagnostic()?;

        let folder = file_path
            .as_ref()
            .parent()
            .ok_or_else(|| AppError::FolderNotFound(file_path.as_ref().to_owned()))?;

        miette::ensure!(folder.is_dir(), "Parent should be a directory");

        recursively_resolve_modules(
            &mut file_contents,
            folder,
            ContainingModule::from_file_name(file_path.as_ref().file_name().unwrap()),
        )?;

        item.content = Some((syn::token::Brace(file_contents.span()), file_contents.items));
        item.attrs
            .extend(file_contents.attrs.into_iter().filter_map(|mut attr| {
                if !matches!(attr.style, syn::AttrStyle::Inner(_)) {
                    return None;
                }

                attr.style = syn::AttrStyle::Outer;

                Some(attr)
            }));

        item.attrs.push(syn::Attribute {
            pound_token: syn::Token![#](proc_macro2::Span::mixed_site()),
            style: syn::AttrStyle::Outer,
            bracket_token: syn::token::Bracket(proc_macro2::Span::mixed_site()),
            meta: syn::Meta::NameValue(syn::MetaNameValue {
                path: syn::parse_quote!(doc),
                eq_token: syn::Token![=](proc_macro2::Span::mixed_site()),
                value: syn::Expr::Lit(syn::PatLit {
                    attrs: Vec::new(),
                    lit: syn::Lit::new(proc_macro2::Literal::string(&format!(
                        "[//]: # \"{FILE_ANNOTATION_IDENTIFIER} = {}\" ",
                        file_path.as_ref().to_string_lossy()
                    ))),
                }),
            }),
        })
    }
    Ok(())
}

fn entry_matches_ident(entry: &DirEntry, ident: &syn::Ident) -> std::io::Result<bool> {
    let metadata = entry.metadata()?;

    Ok((!metadata.is_dir()
        && entry.file_name().to_string_lossy().to_uppercase()
            == format!("{ident}.rs").to_uppercase())
        || (metadata.is_dir()
            && entry.file_name().to_string_lossy().to_uppercase()
                == ident.to_string().to_uppercase()))
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
enum FileResolveError {
    #[error("Could not resolve module {0}")]
    #[diagnostic(help = "Create missing module")]
    NotFound(String),
    #[error("Multiple matching entries found for module {0}: {1:?}")]
    #[diagnostic(help = "rename one of the conflicting modules")]
    MultipleEntries(String, Vec<DirEntry>),
}

fn resolve_file_path(
    containing_folder: impl AsRef<std::path::Path>,
    containing_module: &ContainingModule,
    ident: &syn::Ident,
) -> miette::Result<impl AsRef<std::path::Path>> {
    let lookup_location = containing_module.get_lookup_location(containing_folder);

    let relevant_dir_entries = lookup_location
        .read_dir()
        .into_diagnostic()?
        .filter(|entry| {
            let Ok(entry) = entry.as_ref() else {
                return true;
            };

            entry_matches_ident(entry, ident).unwrap_or(false)
        })
        .collect::<Result<Vec<_>, _>>()
        .into_diagnostic()?;

    if relevant_dir_entries.len() > 1 {
        return Err(
            FileResolveError::MultipleEntries(ident.to_string(), relevant_dir_entries).into(),
        );
    }

    let Some(entry) = relevant_dir_entries.first() else {
        return Err(FileResolveError::NotFound(ident.to_string()).into());
    };

    let path = entry.path();

    Ok(if path.is_dir() {
        path.join("mod.rs")
    } else {
        path
    })
}
