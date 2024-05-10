# capacity-optimizer

This tool searches for tests that use `PushState::builder().<foo>().with_max_stack_size(<int_literal>)` and reduces the max size to the minimum value

> [!CAUTION]
> This tool is still very early in development and needs major refactors. The current script is a prototype, and the next task is a rewrite making readable - it currenly is not at all.


> [!WARNING]
> Although I am fairly confident that this script won't break any code, it **does** modify code in your project. It is highly recommended to only run it after a comiit has been done and the current state is clean.
