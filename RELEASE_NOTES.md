# v0.1.0-alpha.2 release notes

This follow-up alpha adds the directly bundled competition HUD to Odyssey Local Co-op's two-player same-screen experience for Super Mario Odyssey 1.0.0.

## Highlights

- Separate P1 and P2 controller routing with a distinct green P2 costume.
- Shared co-op camera with midpoint framing, adaptive zoom, and right-stick input from either player.
- Recovery bubbles that return a separated or fallen player toward the partner.
- Tested support for regular stage transitions, selected 2D valves, captures, and cap ownership.
- Independent P2 health display.
- Directly bundled optional coin and Moon competition HUD with no separate asset preparation.
- Reproducible pinned build, deterministic ZIP, SHA-256 checksums, and a Ryujinx-first installer.

## Important alpha limitations

- Requires Super Mario Odyssey 1.0.0 and normal in-game 1P mode.
- Ryujinx is the primary packaged target. Actual-Switch gameplay and Cascade-to-Sand travel are verified with the corrected Atmosphere payload; the public alpha ZIP does not yet automate installation of the generated `main.npdm` required by that hardware setup.
- The competition scoreboard is included but remains disabled by default while known scoring and persistence gaps are worked on.
- Terminal-death recovery, some P2 health events, event-Moon scenes, and recovery placement still have known defects. Read [KNOWN_ISSUES.md](KNOWN_ISSUES.md) before playing.

## Integrity

Use the `.sha256` file published beside the release ZIP to verify the download before installation. The installer then checks each packaged file again before copying it.

This release contains no game executable, keys, firmware, save data, or complete stock Nintendo archive. The bundled custom HUD layout uses resources derived from Super Mario Odyssey; Nintendo retains all rights to its game content.
