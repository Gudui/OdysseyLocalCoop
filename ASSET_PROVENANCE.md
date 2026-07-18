# Asset provenance and distribution decision

## Competition scoreboard

The development build uses `OCoopScoreBoard.szs`, a custom Yaz0-compressed SARC layout archive. A format-aware inventory of the final development archive found:

- one nested `layout.lyarc` SARC;
- a modified `blyt/OCoopScoreBoard.bflyt` layout;
- a Nintendo-derived `timg/__Combined.bntx` texture/font resource; and
- six inherited `Init*.byml` layout metadata files.

Development archive fingerprint: 12,980 bytes, SHA-256 `EE828417DE626FFB2C2A861EC247223654D3784CF9D754ED04691EE9F871C4E8`.

The retained build tooling shows that the layout began from a stock layout and reused native picture-font/material data, but the exact original stock archive and its SHA-256 fingerprint were not retained. That makes a reproducible user-side binary patch impossible to validate at this stage.

Decision for `v0.1.0-alpha.1`: omit the competition scoreboard archive and do not publish an xdelta patch. The release profile and package must keep the competition HUD disabled when the asset is absent. Gate I will add a user-side builder after the exact Super Mario Odyssey 1.0.0 stock inputs and output hash are established; the builder will enable competition only after producing the verified archive.

This decision affects only distribution. The private development workspace keeps the existing archive for continued development and testing.
