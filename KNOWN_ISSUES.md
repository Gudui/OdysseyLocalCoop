# Known issues

These limitations apply to `v0.1.0-alpha.4`. They summarize currently observed behavior without exposing private investigation records.

## Platform and setup

- **Only Super Mario Odyssey 1.0.0 is supported.** Other revisions have different executable layouts and must not be used with this build.
- **Use Odyssey's normal 1P mode.** The mod currently creates P2 whenever a second controller is available and does not follow the game's native 1P/2P lifecycle. Entering native 2P mode can make P1 control both actors or route Cappy to the wrong player. Restart in normal 1P mode to recover.
- **Physical Switch support remains experimental.** The package now installs ExLaunch's generated `main.npdm`, and Cascade-to-Sand travel has completed successfully on actual hardware, but broader hardware coverage is still limited.
- **Competition is optional and disabled by default.** The HUD is bundled, but some scoring paths and persistence behavior remain incomplete.

## Gameplay

- **A terminal P2 death can softlock recovery.** In some damage paths, recovery can overwrite the terminal-death state. P2 may turn in place but cannot move or respawn, and a boss scene may stop progressing. Letting the surviving player die can trigger a full reload; otherwise restart from the last save.
- **Recovery destinations are not terrain-safe everywhere.** A bubble can place the returning player below uneven or void-adjacent terrain, causing damage or another recovery. Keep the receiving player away from cliffs, steep slopes, and moving void-adjacent surfaces when possible.
- **A 2D-to-3D bubble transfer can visibly fall through the world once.** The player becomes usable in 3D afterward and no health loss was observed in the verified case; this is currently treated as cosmetic debt.
- **Kingdom-event Moon scenes are still Mario-centric.** Some event Moons can move the bystander and frame P1 rather than the collector. Regular Moon collection is less affected.
- **P2 cap activation of the required Cap Kingdom electrical wire may stall travel.** The report is not yet reproduced on a current release build. Use P1's cap for that wire as a precaution.
- **P2 health events are incomplete.** A heart may convert to coins when P1 is full even if P2 is injured; Power Moon healing may update P1 without updating P2; and a Life-Up collected while captured can leave P2's maximum health out of sync.

## Deferred competition work

The following defects do not affect the default configuration because competition is disabled:

- the custom scoreboard omits Odyssey's remaining-Moons-to-fuel cue; and
- sidecar persistence on physical Switch still needs stronger save-commit validation.

## Reporting something new

Before opening an issue, test on Super Mario Odyssey 1.0.0 in normal 1P mode with two controllers and other gameplay mods disabled. Include the mod version, Ryujinx version, exact stage, reproduction steps, expected result, actual result, and a redacted Ryujinx log when available.
