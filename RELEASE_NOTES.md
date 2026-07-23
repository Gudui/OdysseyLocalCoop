# v0.1.0-alpha.3 release notes

## Resolved

- Independent native death, delayed respawn, health restoration, and partner-directed recovery for P1 and P2 on verified ordinary and cliff/abyss paths.
- A full miss no longer activates while one player is still alive.
- The shared camera no longer focuses on a dead or recovering player instead of the surviving partner.
- Same-target capture ownership conflicts that could leave stale capture state.
- Distance recovery being blocked by a grounded captured actor.

## Improved

- Survivor-focused camera behavior through terminal falls, respawn delay, bubble travel, and landing.
- Cliff-camera classification during reachable lower-platform traversal.
- Capture-assisted distance bubbling so grounded destinations can recover while unsafe airborne captures remain protected.
- Bubble camera priority during capture-assisted recovery to reduce focus theft and leftover interpolation.

## Added

- `bubble.water_counts_as_ground` setting for treating captured actors in water as valid recovery destinations.
