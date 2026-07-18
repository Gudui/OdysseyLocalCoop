# Contributing

Thank you for helping improve Odyssey Local Co-op. Bug reports, documentation corrections, focused fixes, and carefully bounded gameplay improvements are welcome.

## Before opening an issue

1. Read [KNOWN_ISSUES.md](KNOWN_ISSUES.md) and search existing issues.
2. Reproduce on Super Mario Odyssey 1.0.0 in normal 1P mode.
3. Record the mod version, emulator or hardware target, stage, controller setup, exact steps, expected result, and actual result.
4. Retest with unrelated gameplay mods disabled when practical.
5. Redact personal paths, usernames, tokens, and unrelated information from logs.

Never upload game executables, RomFS archives, title keys, encryption keys, firmware, save data containing personal information, or other copyrighted game files.

## Pull requests

- Keep each pull request focused on one problem.
- Explain the user-visible behavior before and after the change.
- For executable hooks, identify the Super Mario Odyssey 1.0.0 function or instruction involved and explain how the hook was verified. Do not submit offsets copied from another game version.
- Guard pointers and preserve vanilla behavior when P2 is absent.
- Do not add development-only diagnostics, machine-specific paths, credentials, game dumps, analysis databases, or investigative records to public source.
- Add or update user-facing documentation when behavior or configuration changes.
- Run the complete public pipeline before requesting review:

  ```powershell
  .\scripts\build.ps1 -DevkitProRoot PATH_TO_DEVKITPRO
  .\scripts\package.ps1
  .\scripts\verify.ps1
  ```

Maintainers import public pull requests into the private development workspace for integration and gameplay testing, then regenerate the public tree. The disposable export checkout is not edited directly.

## Licensing

By contributing, you agree that your contribution may be distributed under the repository's [GPL-2.0-only license](LICENSE). Only submit work you have the right to license.
