# serde_json raw_value feature probe — legacy compatibility blocker

**Observed blocker:** enabling `raw_value` on pinned serde_json **1.0.151** changes existing `pyjson::loads` and `serde_json::Value` behavior. The predetermined corpus completed: **36 inputs × 2 configurations × 2 parse paths; 12 inputs differ in both paths, 24 remain the same.** All final feature-graph/build/execution commands exited 0. This is a compatibility failure, despite successful probe execution. No fallback, schema widening, M2 implementation, product-source fix or full-suite run was attempted.

Actual model: **gpt-6.1-sol**. Isolated Lima only; no agents, native Mac, production/credential access, checkout changes or host product execution. Public synthetic input bytes are retained in inputs.jsonl and comparison.json.

## Controlled pair

Both builds use the same minimal package, corpus, exact final Cargo.lock and unchanged copied `pyjson.rs` and `errors.rs` from product **52e87b07380a2f752c127c5f89e5f8f76c38937f**. No stubs or canonical-helper rewrites. Baseline serde_json features: `arbitrary_precision,preserve_order,unbounded_depth` (plus their normal default/std dependencies). The second configuration adds only `raw_value`, through local package feature `raw-value`. Actual cargo feature graphs are in guest-evidence/baseline-features.stdout and raw_value-features.stdout.

Toolchain: `cargo 1.98.1 (797e8a9bc 2026-08-05)`, `rustc 1.98.1 (48a229cea 2026-09-01)`. Platform: `Linux lima-zeropw-parity 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026 aarch64 aarch64 aarch64 GNU/Linux`. Builds use cached registry data only, `--locked --offline`, one job, debug=0, incremental=0, owned target/TMPDIR. Target footprint: `51M	/home/parity/jobs/m2a-raw-feature-20261107T070736Z/target`. Disk after: `/dev/vda1        96G   92G  4.3G  96% /`. UTC 2026-11-07T07:11:42.367695+00:00 through 2026-11-07T07:12:22.254335+00:00.

| Command | Exit | Seconds |
|---|---:|---:|
| `cargo tree --locked --offline --no-default-features -e features -i serde_json` | 0 | 0.035 |
| `cargo build --locked --offline --no-default-features` | 0 | 31.909 |
| `/home/parity/jobs/m2a-raw-feature-20261107T070736Z/target/debug/zeropw-m2a-raw-feature-probe /home/parity/jobs/m2a-raw-feature-20261107T070736Z/src/inputs.jsonl` | 0 | 0.026 |
| `cargo tree --locked --offline --no-default-features --features raw-value -e features -i serde_json` | 0 | 0.317 |
| `cargo build --locked --offline --no-default-features --features raw-value` | 0 | 7.328 |
| `/home/parity/jobs/m2a-raw-feature-20261107T070736Z/target/debug/zeropw-m2a-raw-feature-probe /home/parity/jobs/m2a-raw-feature-20261107T070736Z/src/inputs.jsonl` | 0 | 0.009 |

## Runtime differences

The following canonical output/error table shows actual unchanged `pyjson::loads` plus `pyjson::dumps(..., compact_sorted())` results. Direct serde_json::Value parsing exhibited the same changed cases; its complete structured values, debug representation and error classification/line/column are retained in comparison.json.

| Case | Baseline | With raw_value |
|---|---|---|
| `raw_singleton_integer` | `{"$serde_json::private::RawValue":"123"}` | `123` |
| `raw_singleton_huge` | `{"$serde_json::private::RawValue":"9007199254740993123456789012345678901234567890"}` | `9007199254740993123456789012345678901234567890` |
| `raw_singleton_finite` | `{"$serde_json::private::RawValue":"1.25"}` | `1.25` |
| `raw_singleton_object` | `{"$serde_json::private::RawValue":"{\"a\":1}"}` | `{"a":1}` |
| `raw_singleton_array` | `{"$serde_json::private::RawValue":"[1,{\"x\":2}]"}` | `[1,{"x":2}]` |
| `raw_singleton_null` | `{"$serde_json::private::RawValue":"null"}` | `null` |
| `raw_singleton_invalid` | `{"$serde_json::private::RawValue":"not-json"}` | `ERROR: expected ident at line 1 column 2` |
| `raw_singleton_nonstring` | `{"$serde_json::private::RawValue":123}` | `ERROR: invalid type: integer `123`, expected raw value at line 1 column 37` |
| `raw_multi_first` | `{"$serde_json::private::RawValue":"123","extra":true}` | `ERROR: trailing comma at line 1 column 40` |
| `raw_escaped_key` | `{"$serde_json::private::RawValue":"123"}` | `123` |
| `raw_nested` | `{"outer":[{"$serde_json::private::RawValue":"{\"x\":7}"}]}` | `{"outer":[{"x":7}]}` |
| `both_reserved_raw_first` | `{"$serde_json::private::Number":"456","$serde_json::private::RawValue":"123"}` | `ERROR: trailing comma at line 1 column 40` |

Representative exact input: `{"$serde_json::private::RawValue":"123"}`. Baseline value is an object and canonical text is that same object; enabling raw_value makes it a number with canonical text `123`. This changes interpretation and canonical bytes in legacy loading paths, even when only a new M2 component explicitly requests RawValue. Cargo feature unification applies the enabled library feature to the existing Value visitor too.

Ordinary/ordinary-escaped objects, direct/nested huge exact integers and the selected finite floats were unchanged. Literal Number-reserved singleton/multikey/escaped/nested cases were included as requested and unchanged between configurations; their existing behavior is not being redefined or investigated further. RawValue appearing after an ordinary first key also remains unchanged in this corpus. All 36 raw inputs and outcomes are retained, rather than only successful or changed examples.

## Source explanation, separate from runtime evidence

Pinned `serde_json-1.0.151/src/value/de.rs:125–144` classifies the first map key. Lines 131–134 compile a RawValue branch only with the feature enabled, consume a raw string and call `crate::from_str(value.get())`. Lines 1362–1379 classify decoded borrowed/owned keys against the RawValue token under the same feature. This source mechanism explains the observed first-key, escaped-key and nested transformations/errors; the runtime comparison above independently establishes them. It does not establish behavior for untested inputs or every application call path.

## Exact bindings and preparation evidence

serde_json cached crate archive checksum is `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14`, matching the product lock pin. All 89 archived registry source files matched the cached source before execution; the four recorded mechanism files also matched after both executions.

| Source | SHA256 |
|---|---|
| `Cargo.lock` | `dc0168b610996a12b5bef7839d173bd11ebe993a6606e99b99c05f75e27d93dd` |
| `Cargo.toml` | `4bf071348521a8f22bddb06f42fecf8c69a09be0f92bd523e41820589cf0d942` |
| `inputs.jsonl` | `bea637d8a3a1b1494c01e447697431ec45c4ae5e534d0f7d77c13e45b923df2d` |
| `src/errors.rs` | `5a3e93d697fd2a2815bea39225f96dd796b6f59b00d45a63d655ced72ec5becd` |
| `src/main.rs` | `b18e842d5dcb316b5342761b1539236d88e49b98f1cdcd94c6da1d350ebd86f1` |
| `src/pyjson.rs` | `eb8d93c099c2ab2ac38b3dedd0f6e8fdbf0d26fb4f8fb87fa8ceeba0ce5deeef` |
| `serde_json-1.0.151/Cargo.toml` | `00b920255c320a278bf25b962b491263a19d8c90e12e4a91c1d823db71eabb2f` |
| `serde_json-1.0.151/src/value/de.rs` | `ceda1bf415aafde89caa83bf275811b70d393717d4e1038e0c61822d2da02993` |
| `serde_json-1.0.151/src/raw.rs` | `0e6ae2ade492a3c5c090dfaf31f03ff4e54123a5a47b59def5f1b3dcc035a2e3` |
| `serde_json-1.0.151/src/number.rs` | `70b83c36286f6c58123f544f27db2b54a1135f928fe33b08b521b2997773f862` |

Probe source/hash/file set before and after are equal: **True**. Registry mechanism source before/after equal: **True**. Final package archive SHA256 `101476b0180514d59d479fc8ee7845de5f62a448e992bf2021a8324188900563`.

Baseline results SHA256 `9b0fb4e364e1d3a14632c58269bf28f4f3984e48864fe303b621cc02dc87a641`. Feature results SHA256 `396354ba7376ac6ca3c187055145a33cca0ee55e0f3fdab1cd66dcad89fc195b`.

The initial preflight assumed a vendor-only .cargo-checksum.json file; it stopped before any build/run. The second preflight rejected a manually seeded minimal lock under --locked, also before any build/run. Both failed preflights, their source/driver/status and seed lock are preserved. The final minimal lock was generated offline before the two locked builds. serde/serde_core/serde_json pins match the reference; final resolution differs from the product reference only for equivalent (1.0.3 vs 1.0.2), syn (3.0.9 vs 3.0.5), and unicode-ident (1.0.27 vs 1.0.24). Both compared configurations use the identical final resolved versions, recorded completely in input-final.json and Cargo.lock. This is an isolated helper/Value compatibility probe, not a full-product dependency-matrix regression claim.

The actual copied pyjson behavior delta is sufficient to block adding this feature under the unchanged-legacy-behavior requirement. No parser choice revision or alternative implementation is made by this Sol report. Any next schema/dependency decision requires the coordinator/Astra process.

Guest job: `/home/parity/jobs/m2a-raw-feature-20261107T070736Z`. Source archive, both raw result logs, feature graphs, build logs, binary hashes, pinned source files, commands/status, corpus and all preparation failures are retained. SHA256SUMS.evidence hashes the complete evidence file set.
