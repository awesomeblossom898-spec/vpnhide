use super::*;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalConfig {
    #[serde(default = "schema_version")]
    pub version: u32,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub apps: BTreeMap<String, AppConfig>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub ipv6_prefix_rules: Vec<Ipv6PrefixRule>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default)]
    pub remember_superkey: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6PrefixRule {
    pub iface: String,
    pub prefix: String,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    // `java` selects LSPosed (system_server) hooks and is owned entirely by the
    // LSPosed self-read path; the native activator never inspects it. It must
    // still *parse*: the app writes it as a bool (all / none) or — for a
    // per-hook Java selection — a JSON array of hook names, the same shape as
    // `native`. Accept both so a partial Java selection never breaks the native
    // config read (a bool-only field would error on the array form).
    #[serde(default, deserialize_with = "de_bool_or_hook_list")]
    pub java: bool,
    #[serde(default)]
    pub native: NativeSelection,
    #[serde(default)]
    pub app_hiding: bool,
    #[serde(default)]
    pub ports: bool,
    #[serde(default)]
    pub port_policy: Option<PortPolicy>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortPolicy {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub rules: Vec<PortRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub struct PortRule {
    pub start: u16,
    #[serde(default)]
    pub end: Option<u16>,
    #[serde(default = "default_port_protocol")]
    pub protocol: PortProtocol,
}

#[derive(Debug)]
pub struct PortsActivationReport {
    pub target_count: usize,
    pub log: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    Both,
    Tcp,
    Udp,
}

impl PortRule {
    pub(crate) fn end_port(self) -> u16 {
        self.end.unwrap_or(self.start)
    }

    pub(crate) fn normalized(self) -> Self {
        if self.end_port() == self.start {
            Self { end: None, ..self }
        } else {
            self
        }
    }
}

fn default_port_protocol() -> PortProtocol {
    PortProtocol::Both
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum NativeSelection {
    Enabled(bool),
    Hooks(Vec<String>),
    Detailed(NativeSelectionDetail),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NativeSelectionDetail {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub kernel: Option<Vec<String>>,
    #[serde(default)]
    pub zygisk: Option<Vec<String>>,
}

impl Default for NativeSelection {
    fn default() -> Self {
        Self::Enabled(false)
    }
}

fn default_enabled() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeHookFamily {
    Kernel,
    Kpm,
    Zygisk,
}

impl NativeHookFamily {
    fn full_mask(self) -> u32 {
        match self {
            NativeHookFamily::Kernel => KERNEL_HOOK_MASK,
            NativeHookFamily::Kpm => KPM_HOOK_MASK,
            NativeHookFamily::Zygisk => ZYGISK_HOOK_MASK,
        }
    }
}

impl NativeSelection {
    pub(crate) fn hookmask(&self, family: NativeHookFamily) -> Option<u32> {
        match self {
            NativeSelection::Enabled(false) => None,
            NativeSelection::Enabled(true) => Some(family.full_mask()),
            NativeSelection::Hooks(names) => {
                if names.is_empty() {
                    return None;
                }
                let mask = match family {
                    // Same deduped shape as the Detailed arm below: Kernel and
                    // KPM differ only in the ownership mask, so fold once and
                    // project through the family's own full mask.
                    NativeHookFamily::Kernel | NativeHookFamily::Kpm => {
                        names.iter().fold(0u32, |acc, name| acc | hook_bit(name))
                            & family.full_mask()
                    }
                    NativeHookFamily::Zygisk => ZYGISK_HOOK_MASK,
                };
                (mask != 0).then_some(mask)
            }
            NativeSelection::Detailed(detail) => {
                if !detail.enabled {
                    return None;
                }
                let selected = match family {
                    // KPM shares the kernel-family selection: the canonical
                    // config stays kernel-family-level and the KPM projection
                    // drops what KPM cannot install (e.g. if6_seq_show).
                    NativeHookFamily::Kernel | NativeHookFamily::Kpm => &detail.kernel,
                    NativeHookFamily::Zygisk => &detail.zygisk,
                };
                let Some(names) = selected else {
                    return Some(family.full_mask());
                };
                let mask =
                    names.iter().fold(0u32, |acc, name| acc | hook_bit(name)) & family.full_mask();
                (mask != 0).then_some(mask)
            }
        }
    }
}

fn schema_version() -> u32 {
    1
}

/// Deserialize a hook-role field that the app writes as either a bool (all /
/// none) or a JSON array of hook names (partial selection), collapsing it to
/// "is this role enabled". Used for `java`, which the native activator parses
/// but does not act on — the LSPosed self-read path owns Java hook selection.
fn de_bool_or_hook_list<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrHookList {
        Bool(bool),
        Hooks(Vec<String>),
    }
    Ok(match BoolOrHookList::deserialize(deserializer)? {
        BoolOrHookList::Bool(enabled) => enabled,
        BoolOrHookList::Hooks(hooks) => !hooks.is_empty(),
    })
}

fn hook_bit(name: &str) -> u32 {
    HOOK_NAMES
        .iter()
        .position(|known| *known == name)
        .map(|id| 1u32 << id)
        .unwrap_or(0)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageUidMap {
    packages: BTreeMap<String, Vec<u32>>,
}

impl PackageUidMap {
    pub fn from_pm() -> Result<Self> {
        Self::from_pm_with_wait(PmReadyWait::Bounded(PM_READY_ATTEMPTS))
    }

    fn from_pm_with_wait(wait: PmReadyWait) -> Result<Self> {
        wait_for_pm_ready(wait)?;
        let stdout = pm_list_packages(&["list", "packages", "-U", "--user", "all"])?;
        Ok(parse_pm_packages(&stdout))
    }

    pub(crate) fn uids_for(&self, package: &str) -> &[u32] {
        self.packages.get(package).map(Vec::as_slice).unwrap_or(&[])
    }
}

pub fn parse_pm_packages(output: &str) -> PackageUidMap {
    let mut packages = BTreeMap::<String, Vec<u32>>::new();
    for line in output.lines() {
        let mut pkg: Option<&str> = None;
        let mut uid_csv: Option<&str> = None;
        for token in line.split_whitespace() {
            if let Some(rest) = token.strip_prefix("package:") {
                pkg = Some(rest);
            } else if let Some(rest) = token.strip_prefix("uid:") {
                uid_csv = Some(rest);
            }
        }
        let (Some(pkg), Some(uid_csv)) = (pkg, uid_csv) else {
            continue;
        };
        let uids = uid_csv
            .split(',')
            .filter_map(|s| s.parse::<u32>().ok())
            .collect::<Vec<_>>();
        if !uids.is_empty() {
            packages.insert(pkg.to_owned(), uids);
        }
    }
    PackageUidMap { packages }
}

pub fn parse_canonical(json: &str) -> Result<CanonicalConfig> {
    let cfg: CanonicalConfig = serde_json::from_str(json)?;
    if cfg.version > schema_version() {
        return Err(format!("unsupported vpnhide config version {}", cfg.version).into());
    }
    validate_port_policies(&cfg)?;
    validate_ipv6_prefix_rules(&cfg)?;
    Ok(cfg)
}

fn validate_port_policies(cfg: &CanonicalConfig) -> Result<()> {
    for (pkg, app) in &cfg.apps {
        let Some(policy) = &app.port_policy else {
            continue;
        };
        if policy.rules.is_empty() {
            return Err(format!("{pkg}: portPolicy.rules must not be empty").into());
        }
        for rule in &policy.rules {
            let end = rule.end_port();
            if rule.start == 0 || end == 0 {
                return Err(format!("{pkg}: port ranges must be within 1..65535").into());
            }
            if rule.start > end {
                return Err(format!("{pkg}: port range start must not exceed end").into());
            }
        }
    }
    Ok(())
}

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

pub fn project_native(json: &str) -> Result<String> {
    project_native_with_pm_wait(
        json,
        NativeHookFamily::Kernel,
        PmReadyWait::Bounded(PM_READY_ATTEMPTS),
    )
}

pub(crate) fn project_native_with_pm_wait(
    json: &str,
    family: NativeHookFamily,
    wait: PmReadyWait,
) -> Result<String> {
    let cfg = parse_canonical(json)?;
    if !has_native_targets(&cfg, family) {
        // No app targets: still emit any global prefix rules via the one
        // projector path (they need no package resolver).
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

pub(crate) fn project_native_with_resolver_for_family(
    cfg: &CanonicalConfig,
    resolver: &PackageUidMap,
    family: NativeHookFamily,
) -> String {
    let mut by_uid = BTreeMap::<u32, u32>::new();
    for (pkg, app) in &cfg.apps {
        let Some(mask) = app.native.hookmask(family) else {
            continue;
        };
        for uid in resolver.uids_for(pkg) {
            by_uid
                .entry(*uid)
                .and_modify(|existing| *existing |= mask)
                .or_insert(mask);
        }
    }
    // `by_uid` is a BTreeMap, so iteration is ascending by UID; truncating would
    // silently drop the highest-UID (typically most-recently-installed) apps with
    // no diagnostic. Warn so a user with more native targets than the backend can
    // hold learns their protection is partial, instead of failing closed silently.
    if by_uid.len() > MAX_NATIVE_TARGETS {
        eprintln!(
            "vpnhide: WARNING: {} native targets exceed the backend cap of {}; \
             dropping the {} highest-UID app(s) from native protection",
            by_uid.len(),
            MAX_NATIVE_TARGETS,
            by_uid.len() - MAX_NATIVE_TARGETS,
        );
    }
    let targets = by_uid
        .into_iter()
        .take(MAX_NATIVE_TARGETS)
        .map(|(uid, hookmask)| Target { uid, hookmask })
        .collect::<Vec<_>>();
    let prefixes = project_prefix_rules(&cfg.ipv6_prefix_rules);
    format_config_ex(cfg.debug, &targets, &prefixes)
}

pub fn project_native_with_resolver(cfg: &CanonicalConfig, resolver: &PackageUidMap) -> String {
    project_native_with_resolver_for_family(cfg, resolver, NativeHookFamily::Kernel)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortsRuleset {
    pub ipv4: String,
    pub ipv6: String,
    pub target_count: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PortUidPolicy {
    pub(crate) all_ports: bool,
    pub(crate) rules: BTreeSet<PortRule>,
}

impl PortUidPolicy {
    fn merge_app(&mut self, app: &AppConfig) {
        if self.all_ports {
            return;
        }
        let Some(policy) = &app.port_policy else {
            self.all_ports = true;
            self.rules.clear();
            return;
        };
        self.rules
            .extend(policy.rules.iter().copied().map(PortRule::normalized));
    }
}

pub fn project_ports(json: &str) -> Result<PortsRuleset> {
    project_ports_with_pm_wait(json, PmReadyWait::Bounded(PM_READY_ATTEMPTS))
}

pub(crate) fn project_ports_with_pm_wait(json: &str, wait: PmReadyWait) -> Result<PortsRuleset> {
    let cfg = parse_canonical(json)?;
    if !has_ports_targets(&cfg) {
        return Ok(project_ports_with_resolver(&cfg, &PackageUidMap::default()));
    }
    let resolver = PackageUidMap::from_pm_with_wait(wait)?;
    Ok(project_ports_with_resolver(&cfg, &resolver))
}

pub fn project_ports_with_resolver(
    cfg: &CanonicalConfig,
    resolver: &PackageUidMap,
) -> PortsRuleset {
    let mut targets = BTreeMap::<u32, PortUidPolicy>::new();
    for (pkg, app) in &cfg.apps {
        if !app.ports {
            continue;
        }
        for uid in resolver.uids_for(pkg) {
            if *uid >= 10_000 {
                targets.entry(*uid).or_default().merge_app(app);
            }
        }
    }
    PortsRuleset {
        // Match the whole IPv4 loopback block, not just 127.0.0.1: a localhost
        // proxy/VPN daemon bound to the wildcard 0.0.0.0 (the common allow-lan /
        // TUN config for Clash, sing-box, V2Ray) is reachable on every 127.x.x.x
        // alias, so an observer could `connect(127.0.0.2:port)` and still get a
        // handshake — a positive fingerprint — if only 127.0.0.1 were rejected.
        // (::1 already is the entire IPv6 loopback.)
        ipv4: build_ports_ruleset(
            PORTS_CHAIN4,
            "127.0.0.0/8",
            "icmp-port-unreachable",
            &targets,
        ),
        ipv6: build_ports_ruleset(PORTS_CHAIN6, "::1", "icmp6-port-unreachable", &targets),
        target_count: targets.len(),
    }
}
