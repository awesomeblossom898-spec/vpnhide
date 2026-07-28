use super::*;
use std::os::unix::process::ExitStatusExt;

#[test]
fn parses_pm_package_uids_for_all_profiles() {
    let map = parse_pm_packages(
        "package:com.example.one uid:10123,1010123\n\
         package:com.example.two uid:10234\n\
         package:bad.without.uid\n",
    );
    assert_eq!(map.uids_for("com.example.one"), &[10123, 1010123]);
    assert_eq!(map.uids_for("com.example.two"), &[10234]);
    assert!(map.uids_for("bad.without.uid").is_empty());
}

#[test]
fn projects_native_roles_to_wire() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "debug": true,
          "apps": {
            "com.example.disabled": { "native": false },
            "com.example.full": { "native": true },
            "com.example.partial": { "native": ["sock_ioctl"] }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages(
        "package:com.example.full uid:10123,1010123\n\
         package:com.example.partial uid:10234\n\
         package:com.example.disabled uid:10345\n",
    );
    assert_eq!(
        project_native_with_resolver(&cfg, &resolver),
        "vpnhide 1 config\n\
         debug 1\n\
         target 0x278b 0x20003ff\n\
         target 0x27fa 0x40\n\
         target 0xf69cb 0x20003ff\n",
    );
}

#[test]
fn native_projection_ignores_non_kernel_hook_names() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "debug": false,
          "apps": {
            "com.example.java": { "native": ["lsposed_network"] }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages("package:com.example.java uid:10123\n");

    assert_eq!(
        project_native_with_resolver(&cfg, &resolver),
        "vpnhide 1 config\ndebug 0\n",
    );
}

#[test]
fn projects_backend_specific_native_hook_overrides() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.app": {
              "native": {
                "enabled": true,
                "kernel": ["sock_ioctl"],
                "zygisk": ["zygisk_ioctl", "zygisk_recvfrom_chk"]
              }
            }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages("package:com.example.app uid:10234\n");

    assert_eq!(
        project_native_with_resolver(&cfg, &resolver),
        "vpnhide 1 config\n\
         debug 0\n\
         target 0x27fa 0x40\n",
    );
    assert_eq!(
        project_native_with_resolver_for_family(&cfg, &resolver, NativeHookFamily::Zygisk),
        "vpnhide 1 config\n\
         debug 0\n\
         target 0x27fa 0x1040000\n",
    );
}

#[test]
fn legacy_native_hook_list_is_kernel_only_and_zygisk_defaults_to_all() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.app": { "native": ["sock_ioctl"] }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages("package:com.example.app uid:10234\n");

    assert_eq!(
        project_native_with_resolver(&cfg, &resolver),
        "vpnhide 1 config\n\
         debug 0\n\
         target 0x27fa 0x40\n",
    );
    assert_eq!(
        project_native_with_resolver_for_family(&cfg, &resolver, NativeHookFamily::Zygisk),
        "vpnhide 1 config\n\
         debug 0\n\
         target 0x27fa 0x1fc0000\n",
    );
}

#[test]
fn empty_legacy_native_hook_list_is_disabled_for_every_backend() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.app": { "native": [] }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages("package:com.example.app uid:10234\n");

    assert_eq!(
        project_native_with_resolver(&cfg, &resolver),
        "vpnhide 1 config\ndebug 0\n",
    );
    assert_eq!(
        project_native_with_resolver_for_family(&cfg, &resolver, NativeHookFamily::Zygisk),
        "vpnhide 1 config\ndebug 0\n",
    );
}

#[test]
fn kpm_family_hookmask_uses_the_kpm_owned_set() {
    // Enabled(true) selects every KPM-owned hook (0x3ff — no if6_seq_show).
    assert_eq!(
        NativeSelection::Enabled(true).hookmask(NativeHookFamily::Kpm),
        Some(0x3ff),
    );
    // A hook the .ko owns but KPM cannot install is dropped as unownable.
    assert_eq!(
        NativeSelection::Hooks(vec!["if6_seq_show".to_owned()]).hookmask(NativeHookFamily::Kpm),
        None,
    );
    assert_eq!(
        NativeSelection::Hooks(vec!["dev_ioctl".to_owned()]).hookmask(NativeHookFamily::Kpm),
        Some(0x20),
    );
    // Detailed with no kernel override means "all kernel hooks" → the KPM-owned
    // subset; a kernel override KPM cannot install leaves nothing.
    let detail = |kernel: Option<Vec<&str>>| {
        NativeSelection::Detailed(NativeSelectionDetail {
            enabled: true,
            kernel: kernel.map(|names| names.into_iter().map(str::to_owned).collect()),
            zygisk: None,
        })
    };
    assert_eq!(detail(None).hookmask(NativeHookFamily::Kpm), Some(0x3ff),);
    assert_eq!(
        detail(Some(vec!["if6_seq_show"])).hookmask(NativeHookFamily::Kpm),
        None,
    );
}

#[test]
fn kpm_wire_projection_drops_hooks_kpm_cannot_install() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.full": { "native": true },
            "com.example.if6only": { "native": ["if6_seq_show"] }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages(
        "package:com.example.full uid:10234\n\
         package:com.example.if6only uid:10345\n",
    );

    assert_eq!(
        project_native_with_resolver_for_family(&cfg, &resolver, NativeHookFamily::Kpm),
        "vpnhide 1 config\n\
         debug 0\n\
         target 0x27fa 0x3ff\n",
    );
}

#[test]
fn parses_shared_storage_fixture() {
    let cfg = parse_canonical(include_str!("../../../testdata/storage_config_v1.json")).unwrap();

    assert!(cfg.debug);
    assert!(cfg.settings.remember_superkey);
    assert_eq!(
        cfg.apps.get("com.example.bank").unwrap().native,
        NativeSelection::Enabled(true),
    );
    let proxy = cfg.apps.get("org.example.proxy").unwrap();
    assert_eq!(
        proxy.native,
        NativeSelection::Hooks(vec![
            "fib_route_seq_show".to_owned(),
            "sock_ioctl".to_owned()
        ]),
    );
    // Per-hook Java selection in the fixture: the array form must parse and
    // collapse to "java enabled" without breaking the native config read.
    assert!(proxy.java);
}

#[test]
fn parses_per_hook_java_selection_without_breaking_native() {
    // The canonical the app writes when a user picks individual Java hooks:
    // "java" is a string array, not a bool. A bool-only field used to make
    // serde reject the whole config, silently disabling every native target.
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.partialjava": {
              "java": ["lsposed_network", "lsposed_network_info"],
              "native": true
            },
            "com.example.emptyjava": { "java": [], "native": true }
          }
        }"#,
    )
    .unwrap();
    assert!(cfg.apps.get("com.example.partialjava").unwrap().java);
    // An empty array means no Java hooks -> role disabled.
    assert!(!cfg.apps.get("com.example.emptyjava").unwrap().java);

    let resolver = parse_pm_packages(
        "package:com.example.partialjava uid:10123\n\
         package:com.example.emptyjava uid:10124\n",
    );
    // Native projection is unaffected: both apps still get the kernel mask.
    assert_eq!(
        project_native_with_resolver(&cfg, &resolver),
        "vpnhide 1 config\n\
         debug 0\n\
         target 0x278b 0x20003ff\n\
         target 0x278c 0x20003ff\n",
    );
}

#[test]
fn projects_ports_roles_to_iptables_rulesets() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.disabled": { "ports": false },
            "com.example.ports": { "ports": true },
            "com.example.system": { "ports": true }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages(
        "package:com.example.ports uid:10123,1010123\n\
         package:com.example.system uid:999\n\
         package:com.example.disabled uid:10345\n",
    );

    let rules = project_ports_with_resolver(&cfg, &resolver);

    assert_eq!(rules.target_count, 2);
    assert_eq!(
        rules.ipv4,
        "*filter\n\
         :vpnhide_out - [0:0]\n\
         -A vpnhide_out -m owner --uid-owner 10123 -d 127.0.0.0/8 -p tcp -j REJECT --reject-with tcp-reset\n\
         -A vpnhide_out -m owner --uid-owner 10123 -d 127.0.0.0/8 -p udp -j REJECT --reject-with icmp-port-unreachable\n\
         -A vpnhide_out -m owner --uid-owner 1010123 -d 127.0.0.0/8 -p tcp -j REJECT --reject-with tcp-reset\n\
         -A vpnhide_out -m owner --uid-owner 1010123 -d 127.0.0.0/8 -p udp -j REJECT --reject-with icmp-port-unreachable\n\
         -A vpnhide_out -j RETURN\n\
         COMMIT\n",
    );
    assert_eq!(
        rules.ipv6,
        "*filter\n\
         :vpnhide_out6 - [0:0]\n\
         -A vpnhide_out6 -m owner --uid-owner 10123 -d ::1 -p tcp -j REJECT --reject-with tcp-reset\n\
         -A vpnhide_out6 -m owner --uid-owner 10123 -d ::1 -p udp -j REJECT --reject-with icmp6-port-unreachable\n\
         -A vpnhide_out6 -m owner --uid-owner 1010123 -d ::1 -p tcp -j REJECT --reject-with tcp-reset\n\
         -A vpnhide_out6 -m owner --uid-owner 1010123 -d ::1 -p udp -j REJECT --reject-with icmp6-port-unreachable\n\
         -A vpnhide_out6 -j RETURN\n\
         COMMIT\n",
    );
}

#[test]
fn projects_custom_ports_policy_to_dport_rules() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.proxy": {
              "ports": true,
              "portPolicy": {
                "mode": "custom",
                "rules": [
                  { "protocol": "tcp", "start": 7890, "end": 7892 },
                  { "protocol": "udp", "start": 5353 },
                  { "start": 1080 }
                ]
              }
            }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages("package:com.example.proxy uid:10123\n");

    let rules = project_ports_with_resolver(&cfg, &resolver);

    assert_eq!(rules.target_count, 1);
    assert_eq!(
        rules.ipv4,
        "*filter\n\
         :vpnhide_out - [0:0]\n\
         -A vpnhide_out -m owner --uid-owner 10123 -d 127.0.0.0/8 -p tcp --dport 1080 -j REJECT --reject-with tcp-reset\n\
         -A vpnhide_out -m owner --uid-owner 10123 -d 127.0.0.0/8 -p udp --dport 1080 -j REJECT --reject-with icmp-port-unreachable\n\
         -A vpnhide_out -m owner --uid-owner 10123 -d 127.0.0.0/8 -p udp --dport 5353 -j REJECT --reject-with icmp-port-unreachable\n\
         -A vpnhide_out -m owner --uid-owner 10123 -d 127.0.0.0/8 -p tcp --dport 7890:7892 -j REJECT --reject-with tcp-reset\n\
         -A vpnhide_out -j RETURN\n\
         COMMIT\n",
    );
}

#[test]
fn shared_uid_full_ports_policy_wins_over_ranges() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "apps": {
            "com.example.full": { "ports": true },
            "com.example.range": {
              "ports": true,
              "portPolicy": {
                "mode": "custom",
                "rules": [{ "protocol": "tcp", "start": 7890 }]
              }
            }
          }
        }"#,
    )
    .unwrap();
    let resolver = parse_pm_packages(
        "package:com.example.full uid:10123\n\
         package:com.example.range uid:10123\n",
    );

    let rules = project_ports_with_resolver(&cfg, &resolver);

    assert_eq!(rules.target_count, 1);
    assert!(
        rules
            .ipv4
            .contains("-p tcp -j REJECT --reject-with tcp-reset")
    );
    assert!(!rules.ipv4.contains("--dport"));
}

#[test]
fn rejects_invalid_ports_policy_ranges() {
    assert!(
        parse_canonical(
            r#"{
              "version": 1,
              "apps": {
                "com.example.bad": {
                  "ports": true,
                  "portPolicy": {
                    "mode": "custom",
                    "rules": [{ "start": 0 }]
                  }
                }
              }
            }"#,
        )
        .is_err(),
    );
    assert!(
        parse_canonical(
            r#"{
              "version": 1,
              "apps": {
                "com.example.bad": {
                  "ports": true,
                  "portPolicy": {
                    "mode": "custom",
                    "rules": [{ "start": 9000, "end": 8000 }]
                  }
                }
              }
            }"#,
        )
        .is_err(),
    );
}

#[test]
fn projects_shared_fixture_ports_role() {
    let cfg = parse_canonical(include_str!("../../../testdata/storage_config_v1.json")).unwrap();
    let resolver = parse_pm_packages(
        "package:org.example.proxy uid:10177\n\
         package:com.example.bank uid:10178\n",
    );

    let rules = project_ports_with_resolver(&cfg, &resolver);

    assert_eq!(rules.target_count, 1);
    assert!(rules.ipv4.contains("--uid-owner 10177"));
    assert!(!rules.ipv4.contains("--uid-owner 10178"));
}

#[test]
fn absent_canonical_projects_to_empty_config_without_pm() {
    assert_eq!(
        project_native(empty_canonical_json()).unwrap(),
        "vpnhide 1 config\ndebug 0\n",
    );
}

#[test]
fn pm_ready_check_matches_literal_package_token() {
    assert!(pm_output_has_package(
        "package:dev.privtools.veil uid:10123\n",
        APP_PACKAGE,
    ));
    assert!(!pm_output_has_package(
        "package:dev.privtools.veil.extra uid:10123\n",
        APP_PACKAGE,
    ));
}

#[test]
fn apatch_supercall_command_keeps_kpm_command_in_low_bits() {
    assert_eq!(
        supercall_cmd(
            ApatchCommandStyle::Versioned(APATCH_SUPERCALL_DEFAULT_VERSION_CODE),
            SUPERCALL_KPM_CONTROL,
        ),
        (APATCH_SUPERCALL_DEFAULT_VERSION_CODE << 32)
            | (APATCH_SUPERCALL_MAGIC << 16)
            | SUPERCALL_KPM_CONTROL,
    );
    assert_eq!(
        supercall_cmd(
            ApatchCommandStyle::Versioned(0x000c02),
            SUPERCALL_KPM_CONTROL
        ) & 0xffff,
        0x1022,
    );
    assert_eq!(
        supercall_cmd(ApatchCommandStyle::Raw, SUPERCALL_KPM_CONTROL),
        0x1022
    );
    assert_eq!(
        supercall_cmd(ApatchCommandStyle::Versioned(0x000c02), SUPERCALL_HELLO) & 0xffff,
        0x1000,
    );
    assert_eq!(SUPERCALL_HELLO_MAGIC, 0x11581158);
}

#[test]
fn apatch_command_candidates_include_current_and_folkpatch_versions() {
    let candidates = apatch_command_candidates();
    assert_eq!(
        candidates.first(),
        Some(&ApatchCommandStyle::Versioned(0x000d00))
    );
    assert!(candidates.contains(&ApatchCommandStyle::Versioned(0x000d02)));
    assert!(candidates.contains(&ApatchCommandStyle::Versioned(0x000d01)));
    assert!(candidates.contains(&ApatchCommandStyle::Versioned(0x000d00)));
    assert_eq!(
        candidates
            .iter()
            .filter(|style| **style == ApatchCommandStyle::Versioned(0x000d01))
            .count(),
        1,
    );
}

#[test]
fn apatch_kernel_version_hint_parses_dmesg() {
    let log = "\
[    0.000000] KP KernelPatch Version: c02
[    0.000000] KP KernelPatch Config: 2
";
    assert_eq!(parse_apatch_kernel_version_hint(log), Some(0xc02));
}

#[test]
fn projection_is_bounded_to_backend_target_capacity() {
    let apps = (0..70)
        .map(|i| {
            (
                format!("com.example.{i:02}"),
                AppConfig {
                    native: NativeSelection::Enabled(true),
                    ..AppConfig::default()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let cfg = CanonicalConfig {
        version: 1,
        debug: false,
        apps,
        settings: Settings::default(),
        ipv6_prefix_rules: Vec::new(),
        ipv4_rules: Vec::new(),
    };
    let pm = (0..70)
        .map(|i| format!("package:com.example.{i:02} uid:{}", 10_000 + i))
        .collect::<Vec<_>>()
        .join("\n");
    let wire = project_native_with_resolver(&cfg, &parse_pm_packages(&pm));

    assert_eq!(
        wire.lines()
            .filter(|line| line.starts_with("target "))
            .count(),
        64
    );
}

#[test]
fn kpatch_ctl0_accepts_config_target_count_exit_codes() {
    let one_target = "vpnhide 1 config\ndebug 0\ntarget 0x123 0x1\n";
    assert!(kpatch_ctl0_config_status_ok(
        std::process::ExitStatus::from_raw(0),
        "vpnhide 1 config\ndebug 0\n"
    ));
    assert!(kpatch_ctl0_config_status_ok(
        std::process::ExitStatus::from_raw(1 << 8),
        one_target
    ));
    assert!(!kpatch_ctl0_config_status_ok(
        std::process::ExitStatus::from_raw(2 << 8),
        one_target
    ));
    assert!(!kpatch_ctl0_config_status_ok(
        std::process::ExitStatus::from_raw(1 << 8),
        "not vpnhide config\n"
    ));
    assert!(!kpatch_ctl0_config_status_ok(
        std::process::ExitStatus::from_raw(255 << 8),
        one_target
    ));
    assert!(!kpatch_ctl0_config_status_ok(
        std::process::ExitStatus::from_raw(15),
        one_target
    ));
}

#[test]
fn kpm_readback_marks_truncated_complete_line_prefixes() {
    let complete = "vpnhide 1 stats\n0x1 0x0:0x2\n";
    assert_eq!(
        normalize_kpm_reply("vpnhide 1 stats", complete.to_owned()).unwrap(),
        complete,
    );

    let partial = "vpnhide 1 stats\n0x1 0x0:0x2";
    assert_eq!(
        normalize_kpm_reply("vpnhide 1 stats", partial.to_owned()).unwrap(),
        "vpnhide 1 stats\n0x1 0x0:0x2\n# vpnhide truncated\n",
    );
}

#[test]
fn kpm_readback_rejects_empty_or_wrong_kind_replies() {
    assert!(normalize_kpm_reply("vpnhide 1 stats", String::new()).is_err());
    assert!(
        normalize_kpm_reply(
            "vpnhide 1 stats",
            "vpnhide 1 status\nbackend 0x1\n".to_owned(),
        )
        .is_err(),
    );
}

#[test]
fn parses_and_projects_ipv6_prefix_rules() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "debug": true,
          "ipv6PrefixRules": [
            { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 32 },
            { "iface": "wlan0", "prefix": "fe80::abcd", "prefixLen": 64 },
            { "iface": "eth0", "prefix": "2401:4900:ABCD::", "prefixLen": 128 }
          ]
        }"#,
    )
    .unwrap();
    assert_eq!(cfg.ipv6_prefix_rules.len(), 3);
    assert_eq!(cfg.ipv6_prefix_rules[0].prefix_len, 32);
    // Prefix rules need no app targets and no package resolver at all.
    assert_eq!(
        project_native_with_resolver(&cfg, &PackageUidMap::default()),
        "vpnhide 1 config\n\
         debug 1\n\
         prefix rmnet_data1 24014900000000000000000000000000 0x20\n\
         prefix wlan0 fe80000000000000000000000000abcd 0x40\n\
         prefix eth0 24014900abcd00000000000000000000 0x80\n",
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
         target 0x278b 0x20003ff\n\
         prefix rmnet_data1 24014900000000000000000000000000 0x20\n",
    );
}

#[test]
fn prefix_rule_validation_rejects_bad_entries() {
    // 16-char iface (IFNAMSIZ is 16 incl. NUL).
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "abcdefghijklmnop", "prefix": "2401:4900::", "prefixLen": 32 } ] }"#,
        )
        .is_err(),
    );
    // iface with a space would corrupt the space-joined wire line.
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "rmnet data1", "prefix": "2401:4900::", "prefixLen": 32 } ] }"#,
        )
        .is_err(),
    );
    // Not an IPv6 address.
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900", "prefixLen": 32 } ] }"#,
        )
        .is_err(),
    );
    // prefixLen out of range.
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 129 } ] }"#,
        )
        .is_err(),
    );
    // Missing prefixLen is a hard error (a defaulted 0 would hide everything).
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900::" } ] }"#,
        )
        .is_err(),
    );
}

#[test]
fn prefix_projection_is_bounded_to_backend_capacity() {
    let rules = (0..10)
        .map(|i| {
            format!("{{ \"iface\": \"if{i}\", \"prefix\": \"2401:4900::\", \"prefixLen\": 32 }}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let cfg = parse_canonical(&format!("{{ \"ipv6PrefixRules\": [ {rules} ] }}")).unwrap();
    let wire = project_native_with_resolver(&cfg, &PackageUidMap::default());
    assert_eq!(
        wire.lines()
            .filter(|line| line.starts_with("prefix "))
            .count(),
        8
    );
}

#[test]
fn projects_v6_rewrite_and_v4_rules_onto_the_wire() {
    let cfg = parse_canonical(
        r#"{
          "version": 1,
          "ipv6PrefixRules": [
            { "iface": "ccmni1", "prefix": "2401:4900::", "prefixLen": 32,
              "mode": "rewrite", "fake": "2401:4900:7f3a:9c21:5e88:1b4d:a2f0:6c19" },
            { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 32 }
          ],
          "ipv4Rules": [
            { "iface": "ccmni0", "prefix": "100.64.0.0", "prefixLen": 10, "fake": "100.87.23.45" }
          ]
        }"#,
    )
    .unwrap();
    // The rewrite rule carries its fake as the fourth token; the hide rule
    // serialises exactly as before; prefix4 lines come after prefix lines.
    assert_eq!(
        project_native_with_resolver(&cfg, &PackageUidMap::default()),
        "vpnhide 1 config\n\
         debug 0\n\
         prefix ccmni1 24014900000000000000000000000000 0x20 240149007f3a9c215e881b4da2f06c19\n\
         prefix rmnet_data1 24014900000000000000000000000000 0x20\n\
         prefix4 ccmni0 64400000 0xa 6457172d\n",
    );
}

#[test]
fn old_config_without_rewrite_fields_projects_unchanged() {
    // Backward compat: absent mode/fake/ipv4Rules ⇒ hide semantics, wire
    // byte-identical to the pre-feature format.
    let cfg = parse_canonical(
        r#"{ "ipv6PrefixRules": [ { "iface": "ccmni1", "prefix": "2401:4900::", "prefixLen": 32 } ] }"#,
    )
    .unwrap();
    assert_eq!(cfg.ipv6_prefix_rules[0].mode, crate::model::RuleMode::Hide);
    assert_eq!(cfg.ipv6_prefix_rules[0].fake, None);
    assert!(cfg.ipv4_rules.is_empty());
    assert_eq!(
        project_native_with_resolver(&cfg, &PackageUidMap::default()),
        "vpnhide 1 config\n\
         debug 0\n\
         prefix ccmni1 24014900000000000000000000000000 0x20\n",
    );
}

#[test]
fn rewrite_validation_rejects_bad_entries() {
    // rewrite without a fake is a hard error (never silently degrade).
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "ccmni1", "prefix": "2401:4900::", "prefixLen": 32, "mode": "rewrite" } ] }"#,
        )
        .is_err(),
    );
    // fake that is not an IPv6 address.
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "ccmni1", "prefix": "2401:4900::", "prefixLen": 32, "mode": "rewrite", "fake": "not-an-addr" } ] }"#,
        )
        .is_err(),
    );
    // fake outside the rule prefix (top-32 bits differ).
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "ccmni1", "prefix": "2401:4900::", "prefixLen": 32, "mode": "rewrite", "fake": "2401:4a00::1" } ] }"#,
        )
        .is_err(),
    );
    // fake set with mode hide (would be silently dropped on the wire).
    assert!(
        parse_canonical(
            r#"{ "ipv6PrefixRules": [ { "iface": "ccmni1", "prefix": "2401:4900::", "prefixLen": 32, "fake": "2401:4900::1" } ] }"#,
        )
        .is_err(),
    );
}

#[test]
fn ipv4_rule_validation_rejects_bad_entries() {
    // Missing fake is a serde-level hard error (the record is rewrite-only).
    assert!(
        parse_canonical(
            r#"{ "ipv4Rules": [ { "iface": "ccmni1", "prefix": "100.64.0.0", "prefixLen": 10 } ] }"#,
        )
        .is_err(),
    );
    // prefixLen out of range.
    assert!(
        parse_canonical(
            r#"{ "ipv4Rules": [ { "iface": "ccmni1", "prefix": "100.64.0.0", "prefixLen": 33, "fake": "100.87.23.45" } ] }"#,
        )
        .is_err(),
    );
    // Not an IPv4 address.
    assert!(
        parse_canonical(
            r#"{ "ipv4Rules": [ { "iface": "ccmni1", "prefix": "100.64.0", "prefixLen": 10, "fake": "100.87.23.45" } ] }"#,
        )
        .is_err(),
    );
    // Fake outside the rule prefix (100.87.x is inside /10; 192.168.x is not).
    assert!(
        parse_canonical(
            r#"{ "ipv4Rules": [ { "iface": "ccmni1", "prefix": "100.64.0.0", "prefixLen": 10, "fake": "192.168.1.7" } ] }"#,
        )
        .is_err(),
    );
    // iface with a space.
    assert!(
        parse_canonical(
            r#"{ "ipv4Rules": [ { "iface": "ccmni 1", "prefix": "100.64.0.0", "prefixLen": 10, "fake": "100.87.23.45" } ] }"#,
        )
        .is_err(),
    );
}

#[test]
fn ipv4_projection_is_bounded_to_backend_capacity() {
    let rules = (0..6)
        .map(|i| {
            format!(
                "{{ \"iface\": \"if{i}\", \"prefix\": \"100.64.0.0\", \"prefixLen\": 10, \"fake\": \"100.87.23.45\" }}"
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let cfg = parse_canonical(&format!("{{ \"ipv4Rules\": [ {rules} ] }}")).unwrap();
    let wire = project_native_with_resolver(&cfg, &PackageUidMap::default());
    assert_eq!(
        wire.lines()
            .filter(|line| line.starts_with("prefix4 "))
            .count(),
        4
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
