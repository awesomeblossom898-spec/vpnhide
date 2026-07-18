# Phase 3 — Rust activator JSON schema + Kotlin parity (implementation plan)

**Feature:** vpnhide global IPv6 prefix/CIDR filter
**Arbiter:** `docs/superpowers/specs/2026-07-18-ipv6-prefix-filter-design.md` (§9 activator/JSON, §8 parity, §17 roadmap item 3, Appendix B)
**Prior phases:** Phase 1 (shared C + Rust protocol + oracle) and Phase 2 (kernel `.ko` hooks) are DONE + CI-verified. On-device Task 7 runs in parallel with this plan's execution.
**Branch:** `feat/ipv6-prefix-filter` on fork `awesomeblossom898-spec/vpnhide` (NEVER push to `origin`/upstream)
**Base commit for Task 1:** record `git rev-parse HEAD` in the ledger before dispatch.
**Execution:** subagent-driven-development — one brief per task in `.superpowers/sdd/task-p3-*-brief.md` (self-contained, exact code), fresh implementer subagent per task, orchestrator spec-review + quality-review per task, batched fork CI as the only build/test gate (no local toolchain).

---

## 0. Scope (this phase only)

Per design spec §17 item 3: "Rust + Kotlin parity + activator JSON schema (diff oracle green)". Rust *protocol* parity (PrefixRule/parse/format/oracle) already landed in Phase 1. What remains:

1. **Activator JSON schema** (`crates/activator`): canonical JSON gains a global `ipv6PrefixRules: [{iface, prefix, prefixLen}]` array; the kmod/KPM/zygisk native projections emit `prefix <ifname> <addr32hex> <plen_hex>` wire lines.
2. **Kotlin wire parity** (`lsposed/`): `Protocol.kt` parses the `prefix` record (the golden-vector test has prefix rows since Phase 1 and cannot render them until this lands).
3. **Kotlin canonical-JSON parity** (`lsposed/`): `StorageConfig.kt` reads/writes `ipv6PrefixRules` so an app Save never silently drops the user's prefix rules.
4. **Docs + changelog:** `docs/protocol.md` §4.3/§4.4 pin the `prefix` record; `docs/storage.md` documents the JSON field; changelog fragment (feature becomes user-visible this phase).
5. **Fork CI:** extend the fork-only verification workflow to gate the activator crate + Kotlin unit tests on stock ubuntu runners.

**NOT in scope (later phases):** v6 route hooks (Phase 4), KPM *hiding* parity (Phase 5 — KPM already *parses* prefix lines safely via the shared C parser and simply does not act on them), Zygisk hiding parity (Phase 6 — the zygisk Rust parser already parses + ignores `prefix` lines safely), LSPosed UI to author rules + sentinel-UID stats row special-casing (Phase 7), upstream PR (Phase 8).

## 1. Design pins (do not re-litigate)

- JSON shape (spec §9): `"ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 32 } ]` — top-level, global (NOT per-app). `prefix` is colon-notation IPv6 in JSON; the activator normalises to 32 lowercase hex chars when projecting to the wire.
- Wire record (spec §5, frozen): `prefix <ifname> <addr32hex> <plen_hex>`; addr = exactly 32 hex chars (no `0x`), liberal-in case / lowercase-out; plen = `0x0`..`0x80`. Wire stays **version 1** (old readers skip `prefix` lines via the unknown-keyword rule).
- Rule cap: `MAX_PREFIX_RULES = 8`. Over-cap ⇒ warn to stderr + truncate (mirrors the `MAX_NATIVE_TARGETS` behaviour), never fail the whole projection.
- Activator validation is **strict** (mirrors `validate_port_policies`): any bad rule fails `parse_canonical` with a descriptive error. Kotlin parse is **best-effort** (mirrors `parsePortPolicy`'s `runCatching`: a malformed entry is skipped, never unwinds the whole config).
- Emitted wire goes to ALL native projections (kernel + zygisk families, and the KPM bin reuses the kernel projector). Zygisk and KPM consumers parse-and-ignore safely today; hiding parity comes in Phases 5/6.
- No `version` bump in JSON or wire; no `VERSION` bump; no `#NN` in commit messages.
- Kotlin `canonicalConfigJson` emits the `ipv6PrefixRules` key **only when non-empty** (empty-config output stays byte-identical for existing round-trip tests).
- Global prefix hits by non-target UIDs surface in the module `stats` read under sentinel UID `0xFFFFFFFF` (`VPNHIDE_GLOBAL_STATS_UID`, Phase 2 Fix-A). The app currently renders it as "unknown uid" — acceptable; document in protocol.md (Task 4); UI special-casing is Phase 7.

## 2. Verification model (fork)

No local toolchain on the orchestrator box. Gates, in order:
1. Per-task: orchestrator reviews the committed diff (spec compliance, then code quality).
2. Batched fork CI (`.github/workflows/prefix-phase1-check.yml`, extended by Task 0): gcc host tests, `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` (protocol + diff + **activator**), ktlint 1.8.0, gradle `:app:detekt :app:testDebugUnitTest`.
3. `.github/workflows/prefix-kmod-build.yml` stays green (activator binary still builds via cargo-ndk; the kmod zip now embeds the prefix-capable activator).
4. Kotlin unit tests run the shared golden vectors incl. the `;pfx:` rows (red until Task 2 lands — that is expected and is the task's red→green proof).

---

## Task 0 (orchestrator, no subagent): extend fork CI

Extend `.github/workflows/prefix-phase1-check.yml` (fork-only, excluded from the upstream PR — rename header comment to "Phase 1+3 verification"):

- In job `phase1`, after the existing protocol-crate steps, widen the three Rust steps to include the activator:
  - `cargo fmt --check -p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator`
  - `cargo clippy -p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator --all-targets -- -D warnings`
  - `cargo test -p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator`
- Add a new job `kotlin` (runs on `ubuntu-latest`, needs nothing — runs in parallel):
  - `actions/checkout@v4`
  - `actions/setup-java@v4` with `distribution: temurin`, `java-version: '17'`
  - Install ktlint pinned to the CI image's version (`KTLINT_VERSION=1.8.0` in `.github/docker/ci/Dockerfile`):
    `curl -fsSL -o /usr/local/bin/ktlint https://github.com/pinterest/ktlint/releases/download/1.8.0/ktlint && chmod +x /usr/local/bin/ktlint` (via sudo)
  - `ktlint "lsposed/app/src/**/*.kt"`
  - Rust target + cargo-ndk (the app's `buildRustProbe` gradle task invokes `cargo ndk`; mirror the proven `prefix-kmod-build.yml` activator recipe): `rustup target add aarch64-linux-android && cargo install cargo-ndk --locked`, with `ANDROID_NDK_HOME="${ANDROID_NDK_LATEST_HOME:-$ANDROID_NDK_HOME}"` exported.
  - Defensive SDK step: `yes | sdkmanager --licenses >/dev/null; sdkmanager "platforms;android-37" "build-tools;36.0.0"` (compileSdk = 37; GH runner images usually pre-provision, install only if missing — use `sdkmanager --list_installed | grep -q "platforms;android-37" || sdkmanager ...`).
  - Cache gradle: `actions/cache@v4` on `~/.gradle/caches` + `~/.gradle/wrapper`, key `gradle-${{ runner.os }}-${{ hashFiles('lsposed/gradle/wrapper/gradle-wrapper.properties', 'lsposed/**/build.gradle.kts') }}`.
  - `cd lsposed && ./gradlew :app:detekt :app:testDebugUnitTest` (fork gate; upstream's `cpdCheck :app:lintDebug` run in upstream CI at PR time).

Commit as `ci: extend fork verification to activator crate + Kotlin unit tests`. This commit may ride along in the Task 1 push batch.

## Task 1 (implementer): Rust activator — JSON schema + projection + tests + changelog

**Files:** `crates/protocol/src/lib.rs`, `crates/activator/src/lib.rs`, `crates/activator/src/model.rs`, `crates/activator/src/tests.rs`, `changelog.d/` (new fragment).

### 1a. `crates/protocol/src/lib.rs` — shared cap constant

Next to `MAX_TARGET_UIDS` (line ~27), same doc-comment style:

```rust
/// Maximum number of `prefix` records a native backend will store. The kernel
/// backend keeps a fixed `prefix_rules[MAX_PREFIX_RULES]` array, so a config
/// carrying more rules is truncated on projection (with a warning). Single
/// source of truth on the wire boundary; the C backends mirror it as
/// `#define MAX_PREFIX_RULES` in kmod/shared/vpnhide_logic.h — keep in sync.
pub const MAX_PREFIX_RULES: usize = 8;
```

### 1b. `crates/activator/src/lib.rs` — imports only

```rust
use vpnhide_protocol::PrefixRule;
use vpnhide_protocol::hook_ids::{HOOK_NAMES, KERNEL_HOOK_MASK, ZYGISK_HOOK_MASK};
use vpnhide_protocol::{Kind, MAX_PREFIX_RULES, MAX_TARGET_UIDS, format_config_ex, parse_config, peek_kind};
```
(drop the now-unused `format_config` import; keep everything else)

### 1c. `crates/activator/src/model.rs` — model + validation + projection

1. New struct (after `Settings`, before `AppConfig`), same derive/serde style:

```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6PrefixRule {
    pub iface: String,
    pub prefix: String,
    pub prefix_len: u8,
}
```

No `#[serde(default)]` on any field: a rule missing `iface`/`prefix`/`prefixLen` is a hard parse error (strict producer side — a silently-defaulted `prefixLen: 0` would hide every v6 address on the iface).

2. `CanonicalConfig` gains (after `settings`):

```rust
    #[serde(default)]
    pub ipv6_prefix_rules: Vec<Ipv6PrefixRule>,
```

3. `parse_canonical` — add `validate_ipv6_prefix_rules(&cfg)?;` after the port-policies call, plus:

```rust
fn validate_ipv6_prefix_rules(cfg: &CanonicalConfig) -> Result<()> {
    for rule in &cfg.ipv6_prefix_rules {
        // The wire space-joins tokens, so an iface must be a single printable
        // ASCII token of 1..=15 chars (mirrors the parser's parse_ifname, and
        // IFNAMSIZ-1); anything else would corrupt or be rejected on the wire.
        if rule.iface.is_empty()
            || rule.iface.len() > 15
            || !rule.iface.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(format!(
                "{}: ipv6PrefixRules.iface must be 1..15 printable ASCII chars, no spaces",
                rule.iface
            )
            .into());
        }
        if rule.prefix.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!(
                "{}: ipv6PrefixRules.prefix must be a valid IPv6 address",
                rule.prefix
            )
            .into());
        }
        if rule.prefix_len > 128 {
            return Err(format!(
                "{}: ipv6PrefixRules.prefixLen must be within 0..=128",
                rule.iface
            )
            .into());
        }
    }
    Ok(())
}
```

4. Prefix projection helper (place near `project_native_with_resolver_for_family`):

```rust
/// Project validated JSON rules to wire `PrefixRule`s (colon-notation →
/// 16 network-order bytes). Bounded by MAX_PREFIX_RULES; over-cap warns and
/// truncates (mirrors the native-target cap above) instead of failing the
/// whole activation.
fn project_prefix_rules(rules: &[Ipv6PrefixRule]) -> Vec<PrefixRule> {
    if rules.len() > MAX_PREFIX_RULES {
        eprintln!(
            "vpnhide: WARNING: {} ipv6PrefixRules exceed the backend cap of {}; \
             dropping the {} last rule(s)",
            rules.len(),
            MAX_PREFIX_RULES,
            rules.len() - MAX_PREFIX_RULES,
        );
    }
    rules
        .iter()
        .take(MAX_PREFIX_RULES)
        .map(|rule| PrefixRule {
            ifname: rule.iface.clone(),
            addr: rule
                .prefix
                .parse::<std::net::Ipv6Addr>()
                .map(|v6| v6.octets())
                .unwrap_or([0u8; 16]), // unreachable: parse_canonical validated
            prefix_len: rule.prefix_len,
        })
        .collect()
}
```

5. `project_native_with_pm_wait` — prefix-only configs must not short-circuit. Replace the early return so BOTH paths flow through the resolver-based projector (prefix rules need no resolver; an empty resolver is fine):

```rust
pub(crate) fn project_native_with_pm_wait(
    json: &str,
    family: NativeHookFamily,
    wait: PmReadyWait,
) -> Result<String> {
    let cfg = parse_canonical(json)?;
    if !has_native_targets(&cfg, family) {
        // No app targets: still emit any global prefix rules (they resolve no
        // packages), via the one projector path.
        return Ok(project_native_with_resolver_for_family(
            &cfg,
            &PackageUidMap::default(),
            family,
        ));
    }
    let resolver = PackageUidMap::from_pm_with_wait(wait)?;
    Ok(project_native_with_resolver_for_family(
        &cfg, &resolver, family,
    ))
}
```

6. `project_native_with_resolver_for_family` — final line becomes:

```rust
    let prefixes = project_prefix_rules(&cfg.ipv6_prefix_rules);
    format_config_ex(cfg.debug, &targets, &prefixes)
```

### 1d. `crates/activator/src/tests.rs` — new tests

- Fix the one `CanonicalConfig` struct literal (line ~469, `projection_is_bounded_to_backend_target_capacity`): add `ipv6_prefix_rules: Vec::new(),` to it.
- Append these tests (style: raw-JSON + `assert_eq!` on exact wire strings):

```rust
#[test]
fn parses_and_projects_ipv6_prefix_rules() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "debug": true,
          "ipv6PrefixRules": [
            { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 32 },
            { "iface": "wlan0", "prefix": "fe80::abcd", "prefixLen": 64 }
          ]
        }"#,
    )
    .unwrap();
    assert_eq!(cfg.ipv6_prefix_rules.len(), 2);
    assert_eq!(cfg.ipv6_prefix_rules[0].prefix_len, 32);
    // Prefix rules need no app targets and no package resolver at all.
    assert_eq!(
        project_native_with_resolver(&cfg, &PackageUidMap::default()),
        "vpnhide 1 config\n\
         debug 1\n\
         prefix rmnet_data1 24014900000000000000000000000000 0x20\n\
         prefix wlan0 fe8000000000000000000000000000abcd 0x40\n",
    );
}

#[test]
fn prefix_rules_come_after_targets_on_the_wire() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": { "com.example.app": { "native": true } },
          "ipv6PrefixRules": [
            { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 32 }
          ]
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages("package:com.example.app uid:10123\n");
    assert_eq!(
        project_native_with_resolver(&cfg, &resolver),
        "vpnhide 1 config\n\
         debug 0\n\
         target 0x278b 0x3ff\n\
         prefix rmnet_data1 24014900000000000000000000000000 0x20\n",
    );
}

#[test]
fn prefix_rule_validation_rejects_bad_entries() {
    // 16-char iface (IFNAMSIZ is 16 incl. NUL).
    assert!(parse_canonical(
        r#"{ "ipv6PrefixRules": [ { "iface": "abcdefghijklmnop", "prefix": "2401:4900::", "prefixLen": 32 } ] }"#,
    )
    .is_err());
    // iface with a space would corrupt the space-joined wire line.
    assert!(parse_canonical(
        r#"{ "ipv6PrefixRules": [ { "iface": "rmnet data1", "prefix": "2401:4900::", "prefixLen": 32 } ] }"#,
    )
    .is_err());
    // Not an IPv6 address.
    assert!(parse_canonical(
        r#"{ "ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900", "prefixLen": 32 } ] }"#,
    )
    .is_err());
    // prefixLen out of range.
    assert!(parse_canonical(
        r#"{ "ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 129 } ] }"#,
    )
    .is_err());
    // Missing prefixLen is a hard error (a defaulted 0 would hide everything).
    assert!(parse_canonical(
        r#"{ "ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900::" } ] }"#,
    )
    .is_err());
}

#[test]
fn prefix_projection_is_bounded_to_backend_capacity() {
    let rules = (0..10)
        .map(|i| {
            format!(
                "{{ \"iface\": \"if{}\", \"prefix\": \"2401:4900::\", \"prefixLen\": 32 }}",
                i
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let cfg = parse_canonical(&format!(
        "{{ \"ipv6PrefixRules\": [ {rules} ] }}"
    ))
    .unwrap();
    let wire = project_native_with_resolver(&cfg, &PackageUidMap::default());
    assert_eq!(
        wire.lines().filter(|line| line.starts_with("prefix ")).count(),
        8
    );
}

#[test]
fn empty_prefix_rule_list_changes_nothing() {
    let cfg = parse_canonical(r#"{ "version": 1, "debug": false }"#).unwrap();
    assert!(cfg.ipv6_prefix_rules.is_empty());
    assert_eq!(
        project_native_with_resolver(&cfg, &PackageUidMap::default()),
        "vpnhide 1 config\ndebug 0\n",
    );
}
```

(The `mixed-case colon notation normalises to lowercase 32-hex` case: `"prefix": "2401:4900:ABCD::"` wire-renders as `24014900abcd0000...` — fold into `parses_and_projects_ipv6_prefix_rules` or add a fifth small test; implementer's choice, pin the expectation either way.)

### 1e. Changelog fragment (CLAUDE.md workflow rule)

Orchestrator runs locally (python is available):
`./scripts/changelog.py added "Hide selected IPv6 prefixes per interface from apps (kernel backend, configured via ipv6PrefixRules in the canonical config)" "<RU translation of the same>"`
Commit the produced `changelog.d/added-*.md` fragment in the same commit as 1a–1d.

### 1f. Acceptance

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` all clean for `-p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator` on fork CI (Task 0 job).
- `prefix-kmod-build.yml` still green (activator binary builds; zip packages).
- Wire expectations match the golden-vector conventions (`;pfx:` rows already shared with C/Rust since Phase 1).

## Task 2 (implementer): Kotlin wire parity — `Protocol.kt` + vector renderer

**Files:** `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/Protocol.kt`, `lsposed/app/src/test/kotlin/dev/okhsunrog/vpnhide/ProtocolTest.kt`.

### 2a. `Protocol.kt`

1. New model (next to `Target`):

```kotlin
    /** One `prefix <ifname> <addr32hex> <plen>` record (§4.3, global scope).
     * [addrHex] is the normalised lowercase 32-hex form of the 16 network-order
     * bytes (liberal-in case on the wire, normalised at parse). */
    data class PrefixRule(
        val ifname: String,
        val addrHex: String,
        val prefixLen: Long,
    )
```

2. `Config` gains `val prefixes: List<PrefixRule>` (update the constructor call in `parseConfig`).

3. Helpers (next to `parseHex`): `parseIfname(tok: String): String?` = `tok.takeIf { it.isNotEmpty() && it.length < 16 }`; `parseAddr32(tok: String): String?` = lowercase-normalised `tok` iff `tok.length == 32 && tok.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }`.

4. `parseConfig` gains a `"prefix"` arm mirroring the Rust (skip line on any malformation; `plen > 128` skips):

```kotlin
                "prefix" -> {
                    val ifname = toks.getOrNull(1)?.let(::parseIfname)
                    val addr = toks.getOrNull(2)?.let(::parseAddr32)
                    val plen = toks.getOrNull(3)?.let { parseHex(it, 32) }
                    if (ifname != null && addr != null && plen != null && plen <= 128) {
                        prefixes += PrefixRule(ifname, addr, plen)
                    }
                }
```

5. `formatConfig` gains `prefixes: List<PrefixRule> = emptyList()`; after the target loop:

```kotlin
            for (p in prefixes) {
                append("prefix ").append(p.ifname).append(' ')
                    .append(p.addrHex).append(' ')
                    .append(hex(p.prefixLen)).append('\n')
            }
```

### 2b. `ProtocolTest.kt`

- `runCfg` renders prefix rows so the shared vectors pass (this is the red→green fix): after the targets loop add

```kotlin
                for (p in cfg.prefixes) append(";pfx:").append(p.ifname).append(':').append(p.addrHex).append(':').append(p.prefixLen)
```

(matches the vector format `;pfx:<iface>:<32hex-lowercase>:<plen-decimal>` exactly).
- Extend `configRoundTrips` with a prefixes round-trip: `Protocol.formatConfig(debug = true, targets = targets, prefixes = listOf(Protocol.PrefixRule("rmnet_data1", "24014900000000000000000000000000", 32)))` → assert exact wire string `vpnhide 1 config\ndebug 1\ntarget 0x27fa 0x3ff\ntarget 0x2947 0x4\nprefix rmnet_data1 24014900000000000000000000000000 0x20\n`, then parse it back and `assertEquals(prefixes, parsed.prefixes)`.

### 2c. Acceptance

- `ktlint "lsposed/app/src/**/*.kt"` clean; `:app:detekt` clean; `:app:testDebugUnitTest` green — **including the golden-vector rows 86-102** (they fail before this task; that failure is the red half of the proof).

## Task 3 (implementer): Kotlin canonical-JSON parity — `StorageConfig.kt` + tests

**Files:** `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/StorageConfig.kt`, `lsposed/app/src/test/kotlin/dev/okhsunrog/vpnhide/StorageConfigTest.kt`.

### 3a. Model + parse + emit

1. New data class (top-level, near `CanonicalSettings`):

```kotlin
internal data class CanonicalIpv6PrefixRule(
    val iface: String,
    val prefix: String,
    val prefixLen: Int,
)
```

2. `CanonicalConfig` gains `val ipv6PrefixRules: List<CanonicalIpv6PrefixRule> = emptyList(),` (after `settings`).

3. `parseCanonicalConfig`: parse best-effort, mirroring the `parsePortPolicy` runCatching philosophy (a malformed entry is skipped, never unwinds the whole config):

```kotlin
private fun parseIpv6PrefixRules(root: JSONObject): List<CanonicalIpv6PrefixRule> {
    val array = root.optJSONArray("ipv6PrefixRules") ?: return emptyList()
    return (0 until array.length()).mapNotNull { idx ->
        val obj = array.optJSONObject(idx) ?: return@mapNotNull null
        runCatching {
            val iface = obj.optString("iface", "")
            val prefix = obj.optString("prefix", "")
            val prefixLen = obj.optInt("prefixLen", -1)
            require(iface.isNotBlank() && iface.length < 16) { "bad iface" }
            require(prefix.isNotBlank()) { "bad prefix" }
            require(prefixLen in 0..128) { "bad prefixLen" }
            CanonicalIpv6PrefixRule(iface, prefix, prefixLen)
        }.getOrNull()
    }
}
```
and pass `ipv6PrefixRules = parseIpv6PrefixRules(root),` into the returned `CanonicalConfig`.

4. `canonicalConfigJson`: emit ONLY when non-empty (empty-config output stays byte-identical). Insert after the `"debugSwitch"` line, before `"apps"`:

```kotlin
        if (config.ipv6PrefixRules.isNotEmpty()) {
            append("  \"ipv6PrefixRules\": [\n")
            config.ipv6PrefixRules.forEachIndexed { index, rule ->
                append("    { \"iface\": ")
                appendJsonString(rule.iface)
                append(", \"prefix\": ")
                appendJsonString(rule.prefix)
                append(", \"prefixLen\": ")
                append(rule.prefixLen)
                append(" }")
                if (index != config.ipv6PrefixRules.size - 1) append(',')
                append('\n')
            }
            append("  ],\n")
        }
```

5. **Carry-through on rebuild (critical):** `buildCanonicalConfig` returns `CanonicalConfig(...)` — add `ipv6PrefixRules = existing?.ipv6PrefixRules ?: emptyList(),` so a Save / auto-hide rebuild never silently drops the user's prefix rules. (Same treatment as `settings`.)

### 3b. `StorageConfigTest.kt` — new tests

- Parse: JSON with a valid `ipv6PrefixRules` array → rules land on the model; absent key → `emptyList()`; a malformed entry (bad prefixLen / 16-char iface) is skipped while valid siblings survive.
- Round-trip: `canonicalConfigJson(parseCanonicalConfig(raw)!!)` contains the `ipv6PrefixRules` block with identical iface/prefix/prefixLen values; empty list ⇒ key absent from output.
- Carry-through: `buildCanonicalConfig(..., existing = configWithRules)` keeps the rules.
- Do NOT extend `testdata/storage_config_v1.json` (it pins the default-empty path on both the Rust and Kotlin sides).

### 3c. Acceptance

- ktlint + detekt clean; `:app:testDebugUnitTest` green (all new tests + existing round-trips byte-identical).

## Task 4 (implementer): docs — protocol.md + storage.md

**Files:** `docs/protocol.md`, `docs/storage.md`.

1. `docs/protocol.md` §4.3 (Records): add the `prefix` record to the config-record list — `prefix <ifname> <addr32hex> <plen_hex>`; global scope (matches regardless of uid); semantics: "a v6 address on interface `ifname` whose first `plen` bits equal the rule's prefix is hidden from the caller"; parse rules: ifname 1..15 ASCII chars; addr = **documented §4.4 deviation** — exactly 32 hex chars with NO `0x` prefix, liberal-in case, lowercase-out (same contract as `/proc/net/if_inet6`); plen = `0x0`..`0x80`, >128 ⇒ skip line; malformed line ⇒ skip (§4.5). Backends that don't implement prefix filtering MUST still parse-and-ignore the record (unknown-keyword forward compat keeps them safe anyway). Producer order: `prefix` lines after `target` lines (§4.1: order not guaranteed — pin as convention only).
2. `docs/protocol.md` §4.3 stats: note that GLOBAL prefix-filter hits by non-target uids are reported under the sentinel uid `0xFFFFFFFF` (`VPNHIDE_GLOBAL_STATS_UID`) so they never consume the 64-row per-uid stats table; readers should treat that uid as "global, not attributable to one app".
3. `docs/storage.md` §2: add `ipv6PrefixRules` to the illustrative JSON block (matching spec Appendix B) + one paragraph: global (not per-app), colon-notation `prefix`, `prefixLen` 0..128, cap 8 (over-cap ⇒ activator warns + truncates), activator validates strictly, Kotlin skips malformed entries on read, emitted for all native backends (kmod acts on it; KPM/zygisk parse-ignore until Phases 5/6).
4. Update the stale cross-reference if present: docs that say `/proc/net/if_inet6` is unhooked (detection-vectors.md gap note) — now hooked as hook id 25 (`if6_seq_show`). One-line factual fix only.

**Acceptance:** docs-only; no CI gate beyond the existing suites; orchestrator proof-reads against the spec (§5, §9, Appendix B) word for word.

---

## 3. Execution order + CI batching

1. **T0** (orchestrator): CI extension commit.
2. **T1** (implementer, Rust): brief `task-p3-t1-brief.md` → implement → spec-review → quality-review → orchestrator runs nothing locally (no cargo) — the batch push IS the gate. Push T0+T1 together → both fork workflows must go GREEN before T2.
3. **T2** (implementer, Kotlin Protocol): brief `task-p3-t2-brief.md` → reviews → push → `kotlin` job GREEN (vector rows pass).
4. **T3** (implementer, Kotlin StorageConfig): brief `task-p3-t3-brief.md` → reviews → push → `kotlin` job GREEN.
5. **T4** (implementer, docs): brief `task-p3-t4-brief.md` → orchestrator proof-read → push → full suite GREEN.
6. Final whole-phase review subagent (range T0..T4) → record verdict in the ledger.

Ledger: record base commit before each dispatch (never `HEAD~1`); one line per task in `.superpowers/sdd/progress.md` with commit + review + CI run ids.

## 4. Hard contract for every implementer brief

- No local gcc/clang/rust/cargo/java on this box — EDIT + COMMIT ONLY; CI is the compiler. (Kotlin: no local ktlint either — match the existing file's style byte-for-byte: 4-space indent, trailing commas where the file uses them, `internal` visibility, kdoc style.)
- Locate edits by code anchors (function/struct names), never line numbers.
- Conventional commit message (`activator:`, `protocol:`, `lsposed:`, `docs:` prefixes per git log); no `#NN`; no AI-tool mentions.
- Never push; the orchestrator pushes after review.
- Temp fork-only files (docs/superpowers/**, .superpowers/**, prefix-*.yml workflows) must never be touched by implementer tasks except the orchestrator's T0 workflow commit.
