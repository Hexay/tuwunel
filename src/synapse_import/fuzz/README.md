# Fuzzing the Synapse importer

cargo-fuzz targets for the importer's parsing of what Synapse stored. They call
the entry points in `../fuzz.rs`, which the importer compiles only with its
`fuzzing` feature, and need no database. A broken invariant panics, which
libFuzzer reports as a crash. Nothing here runs in CI; the unit tests replay
the committed seeds through the same entry points.

This directory is a workspace of its own, so the main one never builds
libFuzzer. Its `[patch]` entries mirror the root `Cargo.toml`'s and must be
kept in step with them.

## Targets

- `event_row`: an `event_json` row through the conversion to a stored PDU,
  under its own ID and the one its content hashes to, with its sender erased
  and not. A converted event must convert the same way again, read back from
  its stored bytes, and still hash to its ID.
- `event_struct`: events built field by field, so wrong types, odd numbers and
  deep nesting reach every field in every room version.
- `redaction`: redacting is idempotent and keeps the event ID.
- `push_rule`: a `push_rules` row replayed onto the default ruleset, which must
  read back.
- `synapse_config`: `homeserver.yaml`, or an appservice registration.
- `json_columns`: the other JSON columns the importer parses.

Input formats are documented on each function in `../fuzz.rs`.

## Running

```sh
cargo install cargo-fuzz
cd src/synapse_import/fuzz
mkdir -p corpus/event_row
cargo fuzz run --target x86_64-unknown-linux-gnu -s none event_row corpus/event_row seeds/event_row
```

- `-s none` turns off the sanitizers, so the repository's pinned stable
  toolchain builds it. The sanitizers need nightly (`cargo +nightly fuzz run`
  without `-s none`).
- Name the target explicitly; the harness is tested on
  `x86_64-unknown-linux-gnu`.
- `seeds/` holds a few hand-written inputs and is committed. libFuzzer grows
  `corpus/`, which is ignored, as are `artifacts/` and `coverage/`. To start
  from real data, put rows from your own Synapse database in `corpus/<target>/`,
  one input per file in the target's format.
