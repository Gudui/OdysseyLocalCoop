# Known issues

These limitations apply to `v0.1.0-alpha.5`. They summarize currently observed behavior without exposing private investigation records.

## Critical progression issues

- **Defeating the Metro Kingdom boss can enter an endless white loading screen.** The transition never completes, and restarting may not save the boss victory, leaving progression blocked. This has been observed on physical Switch and is awaiting a diagnostic Ryujinx trace. Until fixed, keep a backup of the save before the boss.
- **The Lake Kingdom painting can enter an infinite loading loop.** A candidate transition-owner fix exists but still needs verification on the affected save.

## Platform and setup

- **Only Super Mario Odyssey 1.0.0 is supported.** Other revisions have different executable layouts and must not be used with this build.
- **Start co-op from the pause menu.** Choose `Two Players` to add P2 and `One Player` to return to solo play. The mod uses these menu actions but keeps Odyssey's Mario-and-Cappy Separate Play behavior disabled internally.
- **Physical Switch support remains experimental.** The package now installs ExLaunch's generated `main.npdm`, and Cascade-to-Sand travel has completed successfully on actual hardware, but broader hardware coverage is still limited.
- **Competition is optional and disabled by default.** The HUD is bundled, but some scoring paths and persistence behavior remain incomplete.

## Gameplay

- **Lost Kingdom purple lava has two severe recovery failures.** P2 can bubble back at zero health and remain stuck after terminal lava damage; letting P1 die may recover the session. If both players fall into the lava together, they can repeatedly bubble toward each other while airborne and both die instead of returning to safe ground.
- **Recovery destinations are not terrain-safe everywhere.** A bubble can place the returning player below uneven or void-adjacent terrain, causing damage or another recovery. Keep the receiving player away from cliffs, steep slopes, and moving void-adjacent surfaces when possible.
- **A 2D-to-3D bubble transfer can visibly fall through the world once.** The player becomes usable in 3D afterward and no health loss was observed in the verified case; this is currently treated as cosmetic debt.
- **Kingdom-event Moon scenes are still Mario-centric.** Some event Moons can move the bystander and frame P1 rather than the collector. Regular Moon collection is less affected.
- **P2 cap activation of the required Cap Kingdom electrical wire may stall travel.** The report is not yet reproduced on a current release build. Use P1's cap for that wire as a precaution.
- **P2 health events are incomplete.** A heart may convert to coins when P1 is full even if P2 is injured; Power Moon healing may update P1 without updating P2; and a Life-Up collected while captured can leave P2's maximum health out of sync.
- **Cloud Kingdom Bowser-hat control always goes to P1.** Even when P2 strikes Bowser's hat with P2's own hat, P1 receives control.
- **Two captured tanks cannot aim independently.** The game currently does not provide two independently moving crosshairs. A split-screen fallback is being considered but is not implemented.

## Kingdom-specific co-op limitations

- **Wooden Kingdom's boss encounter has only one required NPC/capture target.** If P1 claims it, P2 has no equivalent role. A safe second spawn still needs to be designed.
- **Metro Kingdom has only one bike in the reported area.** The rider can quickly outrun the on-foot partner. A second-bike solution still needs lifecycle and ownership testing.
- **Climbing the long tree grown from a Wooden Kingdom seed can count as collecting coins.** The issue affects both P1 and P2; the exact counter and event source are still being investigated.

## Deferred competition work

The following defects do not affect the default configuration because competition is disabled:

- the custom scoreboard omits Odyssey's remaining-Moons-to-fuel cue; and
- sidecar persistence on physical Switch still needs stronger save-commit validation.

## Reporting something new

Before opening an issue, test on Super Mario Odyssey 1.0.0 with the intended `One Player` or `Two Players` menu state, two configured controllers, and other gameplay mods disabled. Include the mod version, Ryujinx version, exact stage, reproduction steps, expected result, actual result, and a redacted Ryujinx log when available.
