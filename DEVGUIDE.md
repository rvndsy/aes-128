## Using neovim with clangd and clang is not finding Qt includes?
Run `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1` in `build` and move the generated `compile_commands.json` file to root of this repository.
You have to redo this every time a new C/C++ file containing Qt includes is added to the project.
`compile_commands.json` is not included with the repo, you must generate it yourself.
