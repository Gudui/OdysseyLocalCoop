# Changelog

All notable public changes will be documented here.

## v0.1.0-alpha.5

### Added

- Odyssey's pause-menu `Two Players` and `One Player` actions now control the full-player co-op lifecycle. Normal startup remains P1-only; starting co-op rebuilds safely with P2, and ending co-op returns to P1-only without stale player state or co-op HUDs.
- P2 can open the shared map, move its cursor, and confirm checkpoint warps.
- P2 can receive NPC talk prompts, start conversations, and advance dialogue.

### Improved

- Co-op mode keeps Odyssey's native Mario-and-Cappy Separate Play state disabled, preserving independent full-player controller routing.
- Repeated 1P/2P switching cleans up P2 health state and scene-owned HUD objects before rebuilding.

## v0.1.0-alpha.4

### Resolved

- The release package now includes and verifies ExLaunch's generated `main.npdm` beside `subsdk9`, fixing incomplete installer-only Atmosphere deployments.

## v0.1.0-alpha.3

### Resolved

- P1 and P2 now complete independent native death, delayed respawn, health restoration, and partner-directed recovery on the verified ordinary and cliff/abyss paths.
- A surviving player no longer triggers a full miss while only their partner is down.
- The shared camera now follows the surviving player through terminal falls, the respawn delay, bubble travel, and landing for both player roles.
- Two players can no longer claim the same capture target and corrupt its owner state.
- Grounded captured actors can now permit distance recovery while airborne capture travel remains protected.

### Improved

- Cliff-camera handoff now uses Odyssey's native reachable-ground state, reducing false handoffs during lower-platform traversal.
- Distance-bubble camera priority now begins before recovery fires, avoiding focus theft and residual interpolation during capture-assisted recovery.
- Capture-aware recovery now handles grounded and configured in-water destinations separately from unsafe airborne captures.

### Added

- Added `bubble.water_counts_as_ground` to control whether a captured actor in water is a valid recovery destination.

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
