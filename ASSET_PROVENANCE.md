# Asset provenance

## Competition scoreboard

The development build uses `OCoopScoreBoard.szs`, a custom Yaz0-compressed SARC layout archive. A format-aware inventory of the final development archive found:

- one nested `layout.lyarc` SARC;
- a modified `blyt/OCoopScoreBoard.bflyt` layout;
- a Nintendo-derived `timg/__Combined.bntx` texture/font resource; and
- six inherited `Init*.byml` layout metadata files.

Development archive fingerprint: 12,980 bytes, SHA-256 `EE828417DE626FFB2C2A861EC247223654D3784CF9D754ED04691EE9F871C4E8`.

The retained build tooling shows that the layout began from a stock layout and reused native layout resources. A later format-aware dependency audit found that the final visible pane graph is text-only: it has 33 text panes, no picture panes, and its two used materials do not reference the bundled texture list. The coin and Moon symbols are rendered through fonts supplied by the installed game.

Decision for `v0.1.0-alpha.5`: distribute the complete, runtime-confirmed 12,980-byte archive directly in the normal release package. Users do not need to provide stock archives, run a patcher, or prepare assets. The package and installer verify the archive by SHA-256.

The project code license does not grant rights to Nintendo-owned material. Super Mario Odyssey and its game resources remain copyright Nintendo. The archive is supplied only as part of this unofficial interoperability mod and requires a legally obtained installation of Super Mario Odyssey 1.0.0.

## Showcase media

The README screenshot and linked gameplay video were captured by the project author from the mod running in Ryujinx. They are used solely to demonstrate the mod in action. Super Mario Odyssey, its characters, environments, interface, audio, and other game content shown in the capture remain copyright Nintendo.

The screenshot is included in this repository. The gameplay video is hosted on Vimeo; the original capture and any local transcodes remain in the private development workspace and are not distributed in the source repository.
