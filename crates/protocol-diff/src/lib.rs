//! Test-only host bridge for differential C ↔ Rust protocol checks.
//!
//! Keeping this in its own workspace crate prevents the C oracle from being
//! linked into any Android runtime artifact.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use vpnhide_protocol::{Config, Prefix4Rule, PrefixRule, Target, parse_config};

    const C_TARGET_CAPACITY: usize = 128;
    const C_PREFIX_CAPACITY: usize = 32;
    const C_PREFIX4_CAPACITY: usize = 32;

    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct CTarget {
        uid: u32,
        hookmask: u32,
    }

    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct CPrefixRule {
        ifname: [u8; 16],
        addr: [u8; 16],
        prefix_len: u8,
        mode: u8,
        fake: [u8; 16],
    }

    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct CPrefix4Rule {
        ifname: [u8; 16],
        addr: [u8; 4],
        prefix_len: u8,
        fake: [u8; 4],
    }

    unsafe extern "C" {
        fn vpnhide_diff_parse_config_ex(
            input: *const u8,
            len: usize,
            targets: *mut CTarget,
            capacity: i32,
            debug: *mut i32,
            prefixes: *mut CPrefixRule,
            pcapacity: i32,
            pcount: *mut i32,
            prefixes4: *mut CPrefix4Rule,
            p4capacity: i32,
            p4count: *mut i32,
        ) -> i32;
    }

    fn parse_with_c(input: &[u8]) -> Option<Config> {
        let mut targets = [CTarget::default(); C_TARGET_CAPACITY];
        let mut prefixes = [CPrefixRule::default(); C_PREFIX_CAPACITY];
        let mut prefixes4 = [CPrefix4Rule::default(); C_PREFIX4_CAPACITY];
        let mut debug = -1;
        let mut pcount = 0;
        let mut p4count = 0;
        let count = unsafe {
            vpnhide_diff_parse_config_ex(
                input.as_ptr(),
                input.len(),
                targets.as_mut_ptr(),
                C_TARGET_CAPACITY as i32,
                &mut debug,
                prefixes.as_mut_ptr(),
                C_PREFIX_CAPACITY as i32,
                &mut pcount,
                prefixes4.as_mut_ptr(),
                C_PREFIX4_CAPACITY as i32,
                &mut p4count,
            )
        };
        if count < 0 {
            return None;
        }
        Some(Config {
            debug: match debug {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            },
            targets: targets[..count as usize]
                .iter()
                .map(|t| Target {
                    uid: t.uid,
                    hookmask: t.hookmask,
                })
                .collect(),
            prefixes: prefixes[..pcount as usize]
                .iter()
                .map(|p| {
                    let end = p.ifname.iter().position(|&b| b == 0).unwrap_or(16);
                    PrefixRule {
                        ifname: String::from_utf8_lossy(&p.ifname[..end]).into_owned(),
                        addr: p.addr,
                        prefix_len: p.prefix_len,
                        // C mode: 0 = hide, 1 = rewrite (VPNHIDE_RULE_*)
                        fake: if p.mode == 1 { Some(p.fake) } else { None },
                    }
                })
                .collect(),
            prefixes4: prefixes4[..p4count as usize]
                .iter()
                .map(|p| {
                    let end = p.ifname.iter().position(|&b| b == 0).unwrap_or(16);
                    Prefix4Rule {
                        ifname: String::from_utf8_lossy(&p.ifname[..end]).into_owned(),
                        addr: p.addr,
                        prefix_len: p.prefix_len,
                        fake: p.fake,
                    }
                })
                .collect(),
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_048))]

        #[test]
        fn c_and_rust_config_parsers_agree(input in prop::collection::vec(any::<u8>(), 0..1024)) {
            prop_assert_eq!(parse_with_c(&input), parse_config(&input));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Bias inputs toward well-formed prefix lines (with and without the
        /// rewrite token) so the oracle exercises the arm densely, not just via
        /// random bytes.
        #[test]
        fn c_and_rust_agree_on_prefix_lines(
            iface in "[a-z]{1,15}",
            addr in "[0-9a-fA-F]{32}",
            plen in 0u16..=140,
            fake in prop::option::of("[0-9a-fA-F]{32}"),
        ) {
            let fake_part = fake.map(|f| format!(" {f}")).unwrap_or_default();
            let payload =
                format!("vpnhide 1 config\nprefix {iface} {addr} 0x{plen:x}{fake_part}\n");
            prop_assert_eq!(
                parse_with_c(payload.as_bytes()),
                parse_config(payload.as_bytes())
            );
        }

        /// Same density for the new prefix4 arm (fake always required).
        #[test]
        fn c_and_rust_agree_on_prefix4_lines(
            iface in "[a-z]{1,15}",
            addr in "[0-9a-fA-F]{8}",
            plen in 0u16..=40,
            fake in "[0-9a-fA-F]{8}",
        ) {
            let payload =
                format!("vpnhide 1 config\nprefix4 {iface} {addr} 0x{plen:x} {fake}\n");
            prop_assert_eq!(
                parse_with_c(payload.as_bytes()),
                parse_config(payload.as_bytes())
            );
        }
    }
}
