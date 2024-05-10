# capacity-optimizer

This tool searches for tests that use `PushState::builder().<foo>().with_max_stack_size(<int_literal>)` and reduces the max size to the minimum value

> [!CAUTION]
> This tool is still very early in development and needs major refactors. The current script is a prototype, and the next task is a rewrite making readable - it currently is not at all.


> [!WARNING]
> Although I am fairly confident that this script won't break any code, it **does** modify code in your project. It is highly recommended to only run it after a commit has been done and the current git state is clean.

## Usage
```
capacity-optimizer [Arguments] [Tests]
```

### Arguments
- `--allow-proc-macro-crates` Also search in crates that are of type `proc_macro` for tests
- `--allow-outside-test-mod` By default all tests that are searched for must be either in a target of type `test` (meaning: integration test, in the tests/ folder) or behind a module with the `#[cfg(test)]` attribute. This allows tests in modules that don't have that attribute as well
- `--allow-failing` Try to make failing tests compile by raising the limit, up to `u64::MAX`.

### Tests
Optionally provide a list of rust paths to tests you wish to optimize.
