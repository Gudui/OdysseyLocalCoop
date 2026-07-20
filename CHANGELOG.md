# Changelog

All notable public changes will be documented here.

## v0.1.0-alpha.2

- Include the optional competition scoreboard directly in the normal release package.
- Remove the planned user-side stock-file preparation workflow.
- Verify the HUD archive hash and installation path for both Ryujinx and Atmosphere packages.

## v0.1.0-alpha.1

Initial alpha release.

### Added

- Native second-player actor creation with a separate controller and distinct game-provided costume.
- Shared midpoint camera, adaptive separation zoom, and right-stick control from either player.
- Partner-directed recovery bubbles with distance-based recovery.
- P2 support for tested stage-transition areas and 2D valves.
- Tested capture isolation and cap-owner return behavior.
- Independent P2 health display and safer HUD teardown during kingdom changes.
- Runtime configuration for camera, costume, recovery, and future competition settings.
- Reproducible ExLaunch build, deterministic package, checksums, Ryujinx-first installer, and pinned CI dependencies.

### Release limitations

- Super Mario Odyssey 1.0.0 and Ryujinx are the supported combination.
- Competition and its custom HUD are disabled and not distributed.
- Atmosphere support is experimental. Actual-Switch gameplay and Cascade-to-Sand travel are verified with the corrected payload, while clean public packaging of the generated `main.npdm` remains unfinished.
- See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for gameplay defects and workarounds.
