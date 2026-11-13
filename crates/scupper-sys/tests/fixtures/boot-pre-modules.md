`boot-pre-modules.json` is the byte-for-byte `run/boot.json` emitted by
`crates/scupper-sys/src/boot.rs` at pre-module release commit `f357157`.
It was captured by running `Fixture::new().run(None)` from the boot integration
suite with the fake host's conntrack module already loaded. The capture used the
old writer and its eight checkpoints, not a new report with Modules filtered out.
The namespace device/inode are from the capture; restart tests replace only
that runtime identity to match their held namespace. Keep all other fixture
fields, including step outcomes and owned link indices, unchanged.
