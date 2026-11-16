# Night Owl for VS Code

Runs the `nightowl` CLI on your workspace and shows findings as diagnostics (squiggles and the Problems panel).

1. Install the CLI (`scripts/install.sh`) and make sure `nightowl` is on your PATH.
2. Run **Night Owl: Scan workspace** from the command palette.
3. Optional: set `nightowl.scanOnSave`.

Package with `npx @vscode/vsce package`. This extension only reads SARIF from the CLI; no code leaves your machine.
