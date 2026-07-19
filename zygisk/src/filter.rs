//! Pure logic: is a given interface name a VPN tunnel?
//!
//! Kept as a leaf module so it's easy to unit-test on the host. The
//! actual rules live in `data/interfaces.toml` and are rendered into
//! `generated::iface_lists::matches_vpn` by
//! `scripts/codegen-interfaces.py`; this file is just the public API
//! plus the NUL-trim that `ifr_name`-style buffers need.

use core::ffi::CStr;

use crate::generated::iface_lists::matches_vpn;

/// True if the bytes look like a VPN tunnel interface name.
///
/// Works on raw `&[u8]` so we can call it straight from a
/// `libc::ifreq.ifr_name` buffer (which is `[c_char; IFNAMSIZ]`) without
/// having to copy into a String.
pub fn is_vpn_iface_bytes(name: &[u8]) -> bool {
    // Trim at the first NUL — ifr_name is a fixed-size buffer with a NUL
    // terminator somewhere inside it.
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    matches_vpn(&name[..end])
}

/// Convenience wrapper: takes a `CStr` and dispatches to `is_vpn_iface_bytes`.
pub fn is_vpn_iface_cstr(name: &CStr) -> bool {
    is_vpn_iface_bytes(name.to_bytes())
}

// ============================================================================
//  Global IPv6 prefix rules (wire `prefix` record, protocol §4.3)
// ============================================================================

use vpnhide_protocol::PrefixRule;

/// Backend cap, re-exported so the hook layer sizes its per-call resolve
/// array without importing the protocol crate separately.
pub const MAX_PREFIX_RULES: usize = vpnhide_protocol::MAX_PREFIX_RULES;

/// Bit-exact parity with C `vpnhide_prefix_match`
/// (kmod/shared/vpnhide_logic.h): compare the full bytes, then the top `rem`
/// bits of the boundary byte. `prefix_len` 0 matches every address; > 128
/// never matches (defensive — the wire parser already caps at 128, like the
/// C).
pub fn prefix_match(addr: &[u8; 16], rule_addr: &[u8; 16], prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    let full = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    if addr[..full] != rule_addr[..full] {
        return false;
    }
    if rem != 0 {
        let mask = 0xffu8 << (8 - rem);
        if (addr[full] ^ rule_addr[full]) & mask != 0 {
            return false;
        }
    }
    true
}

/// True when a rule names `ifname` (byte-exact; the caller has already
/// NUL-trimmed) AND its prefix covers `addr`.
pub fn prefix_rule_hit(rules: &[PrefixRule], ifname: &[u8], addr: &[u8; 16]) -> bool {
    rules
        .iter()
        .any(|r| r.ifname.as_bytes() == ifname && prefix_match(addr, &r.addr, r.prefix_len))
}

/// Parse exactly 32 hex chars (any case) into 16 network-order bytes — the
/// address-token shape in `/proc/net/if_inet6` and `/proc/net/ipv6_route`
/// (the same 32-hex form as the wire `prefix` record).
fn parse_addr32_hex(tok: &[u8]) -> Option<[u8; 16]> {
    if tok.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        // parse_hex_u32 on a 1-char slice yields that nibble (0 shl 4 | digit).
        let hi = parse_hex_u32(&tok[2 * i..2 * i + 1])?;
        let lo = parse_hex_u32(&tok[2 * i + 1..2 * i + 2])?;
        *byte = ((hi as u8) << 4) | lo as u8;
    }
    Some(out)
}

/// Walk `data` line by line, keeping every line for which `hide(line)` is
/// false and compacting the kept lines toward the front in place. Returns the
/// new valid length.
///
/// Each `line` passed to `hide` spans from the start of the line through and
/// including its terminating `'\n'` (or to end-of-buffer for an unterminated
/// final line) — the same span that gets copied down, so a predicate can look
/// at the whole record. Empty input yields 0 (the loop never runs). This is
/// the shared skeleton behind every `/proc/net/*` line filter below.
fn compact_lines(data: &mut [u8], mut hide: impl FnMut(&[u8]) -> bool) -> usize {
    let len = data.len();
    let mut read_pos = 0usize;
    let mut write_pos = 0usize;

    while read_pos < len {
        // Find end of current line (including the '\n').
        let line_end = data[read_pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| read_pos + p + 1)
            .unwrap_or(len);

        if !hide(&data[read_pos..line_end]) {
            let line_len = line_end - read_pos;
            if write_pos != read_pos {
                data.copy_within(read_pos..line_end, write_pos);
            }
            write_pos += line_len;
        }

        read_pos = line_end;
    }

    write_pos
}

/// Filter `/proc/net/route` content in-place, removing lines whose
/// first tab-separated field is a VPN interface name.
/// Returns the new length of the valid data in `data`.
///
/// Format:
/// ```text
/// Iface   Destination Gateway     Flags RefCnt Use Metric Mask     MTU Window IRTT
/// wlan0   00000000    0101A8C0    0003  0      0   0      00000000 0   0      0
/// tun0    00000000    010010AC    0003  0      0   0      00000000 0   0      0
/// ```
/// The header line (starting with "Iface") is always kept.
pub fn filter_route_buf(data: &mut [u8]) -> usize {
    compact_lines(data, |line| {
        // Extract first field (up to '\t').
        let field_len = line
            .iter()
            .position(|&b| b == b'\t' || b == b'\n')
            .unwrap_or(line.len());
        let ifname = &line[..field_len];
        !ifname.is_empty() && is_vpn_iface_bytes(ifname)
    })
}

/// Filter `/proc/net/ipv6_route` in-place. Interface name is the LAST
/// whitespace-delimited field on each line; the route DESTINATION is the
/// FIRST. Kept wrapper for the no-rules shape.
pub fn filter_ipv6_route_buf(data: &mut [u8]) -> usize {
    filter_ipv6_route_buf_ex(data, &[])
}

/// `ipv6_route` with global prefix rules (kernel `ipv6_route_seq_show`
/// parity): a line also drops when its DESTINATION (first field — the
/// route's own plen is never consulted) falls inside a rule prefix on the
/// egress iface (last field).
pub fn filter_ipv6_route_buf_ex(data: &mut [u8], rules: &[PrefixRule]) -> usize {
    filter_by_last_field_ex(data, rules)
}

/// Filter `/proc/net/dev` in-place. Each data line is `  <iface>: <stats>`;
/// drop lines whose interface name (trimmed, before the first ':') is a VPN
/// interface. The two header lines have no `name:` token and are kept.
pub fn filter_dev_buf(data: &mut [u8]) -> usize {
    compact_lines(data, |line| match line.iter().position(|&b| b == b':') {
        Some(colon) => {
            let name = trim_ascii_ws(&line[..colon]);
            !name.is_empty() && is_vpn_iface_bytes(name)
        }
        None => false,
    })
}

/// Trim leading and trailing ASCII whitespace from a byte slice.
fn trim_ascii_ws(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if matches!(first, b' ' | b'\t' | b'\n' | b'\r') {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if matches!(last, b' ' | b'\t' | b'\n' | b'\r') {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Filter `/proc/net/if_inet6` in-place. Interface name is the LAST
/// whitespace-delimited field on each line. Kept wrapper for the no-rules
/// shape.
pub fn filter_if_inet6_buf(data: &mut [u8]) -> usize {
    filter_if_inet6_buf_ex(data, &[])
}

/// `if_inet6` with global prefix rules (kernel `if6_seq_show` parity): a
/// line also drops when its address (first field, 32 hex) falls inside a
/// rule prefix on the iface (last field).
pub fn filter_if_inet6_buf_ex(data: &mut [u8], rules: &[PrefixRule]) -> usize {
    filter_by_last_field_ex(data, rules)
}

/// Shared logic: last-field VPN-name filtering plus the global prefix-rule
/// path (first-field address hit on a rule-named iface).
fn filter_by_last_field_ex(data: &mut [u8], rules: &[PrefixRule]) -> usize {
    compact_lines(data, |line| {
        let ifname = extract_last_field(line);
        if !ifname.is_empty() && is_vpn_iface_bytes(ifname) {
            return true;
        }
        first_field_addr_hit(line, ifname, rules)
    })
}

/// Prefix-rule check for the if_inet6/ipv6_route line shapes: parse the
/// FIRST whitespace-delimited field as a 32-hex v6 address and test it
/// against the rules naming `ifname`. Empty rules / empty ifname / a
/// non-32-hex first field are all a cheap miss.
fn first_field_addr_hit(line: &[u8], ifname: &[u8], rules: &[PrefixRule]) -> bool {
    if rules.is_empty() || ifname.is_empty() {
        return false;
    }
    let field_len = line
        .iter()
        .position(|&b| b == b' ' || b == b'\t' || b == b'\n')
        .unwrap_or(line.len());
    let Some(addr) = parse_addr32_hex(&line[..field_len]) else {
        return false;
    };
    prefix_rule_hit(rules, ifname, &addr)
}

/// Extract the last whitespace-delimited field from a line (trimming
/// trailing newline/spaces).
fn extract_last_field(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\n' | b' ' | b'\t') {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && !matches!(line[start - 1], b' ' | b'\t') {
        start -= 1;
    }
    &line[start..end]
}

/// Maximum number of VPN addresses to track for tcp/tcp6 filtering.
pub const MAX_VPN_ADDRS: usize = 16;

/// Filter `/proc/net/tcp` in-place. Removes lines whose local address
/// (8-char hex after ": ") matches any of the given VPN IPv4 addresses.
///
/// `vpn_addrs` contains raw `sin_addr.s_addr` values (__be32) which
/// match the hex format in /proc/net/tcp directly.
pub fn filter_tcp4_buf(data: &mut [u8], vpn_addrs: &[u32], n_addrs: usize) -> usize {
    if data.is_empty() || n_addrs == 0 {
        return data.len();
    }
    filter_tcp_addr(data, &vpn_addrs[..n_addrs], 8, parse_hex_u32)
}

/// Filter `/proc/net/tcp6` in-place. Removes lines whose local address
/// (32-char hex after ": ") matches any of the given VPN IPv6 addresses.
///
/// `vpn_addrs` contains raw `s6_addr32` as 4×u32 in native byte order.
pub fn filter_tcp6_buf(data: &mut [u8], vpn_addrs: &[[u32; 4]], n_addrs: usize) -> usize {
    if data.is_empty() || n_addrs == 0 {
        return data.len();
    }
    filter_tcp_addr(data, &vpn_addrs[..n_addrs], 32, parse_hex_addr6)
}

/// Generic TCP filter, shared by tcp4 (`Addr = u32`) and tcp6
/// (`Addr = [u32; 4]`): for each line find ": ", parse `hex_len` hex chars
/// into an `Addr`, and drop the line if it matches any of `vpn_addrs`.
fn filter_tcp_addr<Addr: PartialEq>(
    data: &mut [u8],
    vpn_addrs: &[Addr],
    hex_len: usize,
    parse: fn(&[u8]) -> Option<Addr>,
) -> usize {
    compact_lines(data, |line| {
        // Find ": " separator, then parse hex address after it.
        if let Some(colon_pos) = find_colon_space(line) {
            let addr_start = colon_pos + 2;
            if addr_start + hex_len <= line.len() {
                if let Some(addr) = parse(&line[addr_start..addr_start + hex_len]) {
                    return vpn_addrs.contains(&addr);
                }
            }
        }
        false
    })
}

fn find_colon_space(line: &[u8]) -> Option<usize> {
    line.windows(2).position(|w| w == b": ")
}

fn parse_hex_u32(hex: &[u8]) -> Option<u32> {
    let mut val = 0u32;
    for &b in hex {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'F' => b - b'A' + 10,
            b'a'..=b'f' => b - b'a' + 10,
            _ => return None,
        };
        val = val.checked_shl(4)? | digit as u32;
    }
    Some(val)
}

fn parse_hex_addr6(hex: &[u8]) -> Option<[u32; 4]> {
    if hex.len() != 32 {
        return None;
    }
    Some([
        parse_hex_u32(&hex[0..8])?,
        parse_hex_u32(&hex[8..16])?,
        parse_hex_u32(&hex[16..24])?,
        parse_hex_u32(&hex[24..32])?,
    ])
}

// ============================================================================
//  Netlink RTM_NEWADDR / RTM_NEWLINK / RTM_NEWROUTE filter
// ============================================================================

const NLMSG_ALIGNTO: usize = 4;
const NLMSG_HDRLEN: usize = 16; // sizeof(struct nlmsghdr), already aligned
pub(crate) const RTM_NEWLINK: u16 = 16;
pub(crate) const RTM_NEWADDR: u16 = 20;
pub(crate) const RTM_NEWROUTE: u16 = 24;

/// `sizeof(struct rtmsg)` — the fixed header that precedes the rtattr TLVs
/// in an `RTM_NEWROUTE` payload (family, dst_len, src_len, tos, table,
/// protocol, scope, type, then a `u32` rtm_flags = 8 + 4 bytes).
const RTMSG_HDRLEN: usize = 12;
const RTA_ALIGNTO: usize = 4;
/// `rtattr` type carrying the output interface index (`RTA_OIF`).
const RTA_OIF: u16 = 4;

/// `rtattr` type carrying the route destination (`RTA_DST`).
const RTA_DST: u16 = 1;
/// `rtattr` types carrying the interface address in `RTM_NEWADDR`. Kernel
/// parity: `IFA_LOCAL` is `ifa->addr`; `IFA_ADDRESS` is the peer (or the
/// same value when there is no peer) — match LOCAL first, ADDRESS as
/// fallback.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
/// `rtmsg.rtm_family` / `ifaddrmsg.ifa_family` value for IPv6. The prefix
/// paths gate on this — IPv4 is never filtered (hard constraint).
const AF_INET6: u8 = 10;

/// A prefix rule resolved to an interface index. Wire rules name ifaces;
/// netlink messages carry indices, so the hook layer resolves
/// `ifname → if_nametoindex` once per dump (never cached — bearers renumber
/// on every bring-up, and a stale index would filter the wrong iface).
#[derive(Clone, Copy, Debug)]
pub struct IndexedPrefixRule {
    pub index: u32,
    pub addr: [u8; 16],
    pub prefix_len: u8,
}

/// Prefix-rule check for one `RTM_NEWADDR` message (the whole message,
/// starting at the `nlmsghdr`). True when the message is AF_INET6, its
/// interface index is rule-matched, and its `IFA_LOCAL` (fallback
/// `IFA_ADDRESS`) falls inside that rule's prefix.
fn newaddr_prefix_hit(msg: &[u8], if_index: u32, prules: &[IndexedPrefixRule]) -> bool {
    // ifaddrmsg: family(1) plen(1) flags(1) scope(1) index(4) = 8 bytes.
    if prules.is_empty() || msg.len() < NLMSG_HDRLEN + 8 {
        return false;
    }
    let payload = &msg[NLMSG_HDRLEN..];
    if payload[0] != AF_INET6 {
        return false;
    }
    if !prules.iter().any(|r| r.index == if_index) {
        return false;
    }
    let mut local: Option<[u8; 16]> = None;
    let mut address: Option<[u8; 16]> = None;
    let mut pos = 8usize; // rtattrs follow the 8-byte ifaddrmsg
    while pos + 4 <= payload.len() {
        let Some(rta_len) = read_u16_ne(payload, pos) else {
            break;
        };
        let Some(rta_type) = read_u16_ne(payload, pos + 2) else {
            break;
        };
        let rta_len = rta_len as usize;
        if rta_len < 4 || pos + rta_len > payload.len() {
            break;
        }
        if rta_len >= 4 + 16
            && let Some(bytes) = payload
                .get(pos + 4..pos + 4 + 16)
                .and_then(|b| <&[u8; 16]>::try_from(b).ok())
        {
            if rta_type == IFA_LOCAL {
                local = Some(*bytes);
            } else if rta_type == IFA_ADDRESS {
                address = Some(*bytes);
            }
        }
        pos += rta_align(rta_len);
    }
    let Some(addr) = local.or(address) else {
        return false;
    };
    prules
        .iter()
        .any(|r| r.index == if_index && prefix_match(&addr, &r.addr, r.prefix_len))
}

/// Prefix-rule check for one `RTM_NEWROUTE` message. True when the message
/// is AF_INET6, its `RTA_OIF` is rule-matched, and its DESTINATION falls
/// inside that rule's prefix. A missing `RTA_DST` means `::/0` — all-zero
/// address, kernel `rt6key.addr` parity (so a plen-0 rule covers it; the
/// route's own `rtm_dst_len` is never consulted).
fn newroute_prefix_hit(msg: &[u8], oif: Option<u32>, prules: &[IndexedPrefixRule]) -> bool {
    if prules.is_empty() || msg.len() < NLMSG_HDRLEN + RTMSG_HDRLEN {
        return false;
    }
    let payload = &msg[NLMSG_HDRLEN..];
    if payload[0] != AF_INET6 {
        return false;
    }
    let Some(oif) = oif else {
        return false;
    };
    if !prules.iter().any(|r| r.index == oif) {
        return false;
    }
    let mut dst = [0u8; 16];
    let mut pos = RTMSG_HDRLEN;
    while pos + 4 <= payload.len() {
        let Some(rta_len) = read_u16_ne(payload, pos) else {
            break;
        };
        let Some(rta_type) = read_u16_ne(payload, pos + 2) else {
            break;
        };
        let rta_len = rta_len as usize;
        if rta_len < 4 || pos + rta_len > payload.len() {
            break;
        }
        if rta_type == RTA_DST {
            if rta_len >= 4 + 16
                && let Some(bytes) = payload.get(pos + 4..pos + 4 + 16)
            {
                dst.copy_from_slice(bytes);
            }
            break; // a malformed-short RTA_DST keeps dst = :: (no match below /0)
        }
        pos += rta_align(rta_len);
    }
    prules
        .iter()
        .any(|r| r.index == oif && prefix_match(&dst, &r.addr, r.prefix_len))
}

const fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

const fn rta_align(len: usize) -> usize {
    (len + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

/// Extract the `RTA_OIF` (output interface index) from a single
/// `RTM_NEWROUTE` message `msg` (the whole message, starting at the
/// `nlmsghdr`). Walks the rtattr TLVs that follow `struct rtmsg`.
///
/// Returns `None` if there is no `RTA_OIF` attribute — e.g. multipath
/// routes encode next-hops in `RTA_MULTIPATH` instead, which we don't
/// unpack here (option-1 scope: the leaking default route a detector
/// flags as `if<N>` always carries a single `RTA_OIF`).
fn route_oif(msg: &[u8]) -> Option<u32> {
    let mut pos = NLMSG_HDRLEN + RTMSG_HDRLEN;
    // Each rtattr: u16 rta_len (incl. 4-byte header) + u16 rta_type, then
    // payload padded to RTA_ALIGNTO.
    while pos + 4 <= msg.len() {
        let rta_len = read_u16_ne(msg, pos)? as usize;
        let rta_type = read_u16_ne(msg, pos + 2)?;
        if rta_len < 4 || pos + rta_len > msg.len() {
            break;
        }
        if rta_type == RTA_OIF && rta_len >= 8 {
            return read_u32_ne(msg, pos + 4);
        }
        pos += rta_align(rta_len);
    }
    None
}

fn read_u32_ne(data: &[u8], off: usize) -> Option<u32> {
    let bytes: &[u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(*bytes))
}

fn read_u16_ne(data: &[u8], off: usize) -> Option<u16> {
    let bytes: &[u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
    Some(u16::from_ne_bytes(*bytes))
}

/// Filter netlink dump responses in-place: remove `RTM_NEWLINK`,
/// `RTM_NEWADDR` and `RTM_NEWROUTE` messages tied to a VPN interface
/// index in `vpn_indices`.
///
/// Both `struct ifinfomsg` (RTM_NEWLINK) and `struct ifaddrmsg`
/// (RTM_NEWADDR) have the interface index as a `u32` at offset 4
/// within the payload, so the same extraction works for both.
///
/// `RTM_NEWROUTE` is different: the output interface lives in an
/// `RTA_OIF` rtattr after `struct rtmsg`, so we walk the TLVs (see
/// [`route_oif`]). This is what closes the `if<N>` route leak from
/// issue #86 — a detector dumping the route table via `RTM_GETROUTE`
/// sees the VPN's default route by oif index even when the interface
/// name itself is hidden, then renders it as the synthetic `if<index>`.
///
/// Kept wrapper: VPN-index filtering only (no prefix rules).
/// Returns the new valid length of the buffer.
pub fn filter_netlink_dump(data: &mut [u8], vpn_indices: &[u32]) -> usize {
    filter_netlink_dump_ex(data, vpn_indices, &[])
}

/// `filter_netlink_dump` with global prefix rules: additionally drops
/// AF_INET6 `RTM_NEWADDR` messages whose `IFA_LOCAL`/`IFA_ADDRESS` falls
/// inside a rule prefix on the message's interface, and AF_INET6
/// `RTM_NEWROUTE` messages whose destination falls inside a rule prefix on
/// the output interface (kernel `inet6_fill_ifaddr` / `rt6_fill_node`
/// parity). IPv4 messages are never prefix-filtered.
pub fn filter_netlink_dump_ex(
    data: &mut [u8],
    vpn_indices: &[u32],
    prules: &[IndexedPrefixRule],
) -> usize {
    if (vpn_indices.is_empty() && prules.is_empty()) || data.len() < NLMSG_HDRLEN {
        return data.len();
    }

    let len = data.len();
    let mut read_pos = 0usize;
    let mut write_pos = 0usize;

    while read_pos + NLMSG_HDRLEN <= len {
        let Some(nlmsg_len_raw) = read_u32_ne(data, read_pos) else {
            break;
        };
        let nlmsg_len = nlmsg_len_raw as usize;
        if nlmsg_len < NLMSG_HDRLEN || read_pos + nlmsg_len > len {
            break;
        }
        let aligned_len = nlmsg_align(nlmsg_len).min(len - read_pos);
        let Some(nlmsg_type) = read_u16_ne(data, read_pos + 4) else {
            break;
        };

        let hide = if (nlmsg_type == RTM_NEWLINK || nlmsg_type == RTM_NEWADDR)
            && nlmsg_len >= NLMSG_HDRLEN + 8
        {
            // Interface index is at payload offset 4 in both
            // ifinfomsg and ifaddrmsg.
            let if_index = read_u32_ne(data, read_pos + NLMSG_HDRLEN + 4).unwrap_or(0);
            vpn_indices.contains(&if_index)
                || (nlmsg_type == RTM_NEWADDR
                    && newaddr_prefix_hit(&data[read_pos..read_pos + nlmsg_len], if_index, prules))
        } else if nlmsg_type == RTM_NEWROUTE && nlmsg_len >= NLMSG_HDRLEN + RTMSG_HDRLEN {
            // Output interface is an RTA_OIF rtattr after struct rtmsg.
            let oif = route_oif(&data[read_pos..read_pos + nlmsg_len]);
            match oif {
                Some(o) if vpn_indices.contains(&o) => true,
                _ => newroute_prefix_hit(&data[read_pos..read_pos + nlmsg_len], oif, prules),
            }
        } else {
            false
        };

        if !hide {
            if write_pos != read_pos {
                data.copy_within(read_pos..read_pos + aligned_len, write_pos);
            }
            write_pos += aligned_len;
        }

        read_pos += aligned_len;
    }

    // Trailing bytes (shouldn't happen in well-formed netlink).
    if read_pos < len {
        let tail = len - read_pos;
        if write_pos != read_pos {
            data.copy_within(read_pos..len, write_pos);
        }
        write_pos += tail;
    }

    write_pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tun0() {
        assert!(is_vpn_iface_bytes(b"tun0"));
        assert!(is_vpn_iface_bytes(b"tun1"));
        assert!(is_vpn_iface_bytes(b"TUN0"));
    }

    #[test]
    fn filter_dev_removes_vpn_iface_keeps_headers() {
        let mut buf =
            b"Inter-|   Receive                                                |  Transmit\n \
face |bytes    packets errs drop\n    lo:  100    1    0    0\n  wlan0:  200    2    0    0\n  \
tun0:  300    3    0    0\n"
                .to_vec();
        let n = filter_dev_buf(&mut buf);
        let out = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(out.contains("Inter-|"), "header kept");
        assert!(out.contains("face |"), "second header kept");
        assert!(out.contains("lo:"), "lo kept");
        assert!(out.contains("wlan0:"), "wlan0 kept");
        assert!(!out.contains("tun0"), "tun0 removed");
    }

    #[test]
    fn filter_dev_empty() {
        let mut buf = Vec::new();
        assert_eq!(filter_dev_buf(&mut buf), 0);
    }

    #[test]
    fn detects_wireguard() {
        assert!(is_vpn_iface_bytes(b"wg0"));
        assert!(is_vpn_iface_bytes(b"wg-client"));
    }

    #[test]
    fn detects_ppp_and_l2tp() {
        assert!(is_vpn_iface_bytes(b"ppp0"));
        assert!(is_vpn_iface_bytes(b"l2tp0"));
    }

    #[test]
    fn detects_vpn_substring() {
        assert!(is_vpn_iface_bytes(b"my-vpn-iface"));
        assert!(is_vpn_iface_bytes(b"custom_VPN_42"));
    }

    #[test]
    fn rejects_real_interfaces() {
        assert!(!is_vpn_iface_bytes(b"lo"));
        assert!(!is_vpn_iface_bytes(b"wlan0"));
        assert!(!is_vpn_iface_bytes(b"rmnet16"));
        assert!(!is_vpn_iface_bytes(b"eth0"));
        assert!(!is_vpn_iface_bytes(b"dummy0"));
    }

    #[test]
    fn handles_embedded_nul_from_ifreq() {
        // IFNAMSIZ is 16 — simulate a kernel-filled ifr_name buffer
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(b"tun0");
        assert!(is_vpn_iface_bytes(&buf));

        buf.fill(0);
        buf[..5].copy_from_slice(b"wlan0");
        assert!(!is_vpn_iface_bytes(&buf));
    }

    #[test]
    fn empty_name_is_not_vpn() {
        assert!(!is_vpn_iface_bytes(b""));
        assert!(!is_vpn_iface_bytes(&[0u8; 16]));
    }

    #[test]
    fn filter_route_removes_vpn_lines() {
        let input = b"Iface\tDestination\tGateway\n\
                       wlan0\t00000000\t0101A8C0\n\
                       tun0\t00000000\t010010AC\n\
                       rmnet0\tFEFFFFFF\t00000000\n";
        let mut buf = input.to_vec();
        let new_len = filter_route_buf(&mut buf);
        let result = core::str::from_utf8(&buf[..new_len]).unwrap();
        assert!(result.contains("Iface\t"));
        assert!(result.contains("wlan0\t"));
        assert!(result.contains("rmnet0\t"));
        assert!(!result.contains("tun0"));
    }

    #[test]
    fn filter_route_keeps_all_when_no_vpn() {
        let input = b"Iface\tDestination\n\
                       wlan0\t00000000\n\
                       rmnet0\tFEFFFFFF\n";
        let mut buf = input.to_vec();
        let new_len = filter_route_buf(&mut buf);
        assert_eq!(new_len, input.len());
    }

    #[test]
    fn filter_route_removes_wg_lines() {
        let input = b"Iface\tDest\nwg0\t00000000\nwlan0\t00000000\n";
        let mut buf = input.to_vec();
        let new_len = filter_route_buf(&mut buf);
        let result = core::str::from_utf8(&buf[..new_len]).unwrap();
        assert!(!result.contains("wg0"));
        assert!(result.contains("wlan0"));
    }

    #[test]
    fn filter_route_empty_input() {
        let mut buf = [];
        assert_eq!(filter_route_buf(&mut buf), 0);
    }

    // ---- Netlink filter tests ----

    /// Build a minimal nlmsghdr + ifaddrmsg/ifinfomsg for testing.
    /// `msg_type` is RTM_NEWADDR (20) or RTM_NEWLINK (16).
    /// `if_index` is the interface index placed at payload offset 4.
    fn make_nlmsg(msg_type: u16, if_index: u32) -> Vec<u8> {
        // nlmsghdr (16 bytes) + 8 bytes payload (family/pad/type + index)
        let total_len: u32 = 24;
        let mut msg = Vec::new();
        msg.extend_from_slice(&total_len.to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        msg.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        // payload: 4 bytes (family etc) + 4 bytes (if_index)
        msg.extend_from_slice(&[0u8; 4]);
        msg.extend_from_slice(&if_index.to_ne_bytes());
        msg
    }

    #[test]
    fn netlink_filter_removes_vpn_newaddr() {
        let vpn_idx: u32 = 7; // tun0
        let wlan_idx: u32 = 2;

        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWADDR, wlan_idx));
        buf.extend(make_nlmsg(RTM_NEWADDR, vpn_idx));
        buf.extend(make_nlmsg(RTM_NEWADDR, wlan_idx));

        let orig_msgs = 3;
        let new_len = filter_netlink_dump(&mut buf, &[vpn_idx]);

        // Should have removed exactly the vpn_idx message (24 bytes).
        assert_eq!(new_len, 24 * (orig_msgs - 1));
        // First remaining msg should be wlan_idx.
        assert_eq!(read_u32_ne(&buf, NLMSG_HDRLEN + 4), Some(wlan_idx));
        // Second remaining msg should also be wlan_idx.
        assert_eq!(read_u32_ne(&buf, 24 + NLMSG_HDRLEN + 4), Some(wlan_idx));
    }

    #[test]
    fn netlink_filter_removes_vpn_newlink() {
        let vpn_idx: u32 = 5;
        let lo_idx: u32 = 1;

        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWLINK, vpn_idx));
        buf.extend(make_nlmsg(RTM_NEWLINK, lo_idx));

        let new_len = filter_netlink_dump(&mut buf, &[vpn_idx]);
        assert_eq!(new_len, 24); // only lo remains
        assert_eq!(read_u16_ne(&buf, 4), Some(RTM_NEWLINK));
        assert_eq!(read_u32_ne(&buf, NLMSG_HDRLEN + 4), Some(lo_idx));
    }

    #[test]
    fn netlink_filter_keeps_all_no_match() {
        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWADDR, 1));
        buf.extend(make_nlmsg(RTM_NEWADDR, 2));
        let orig_len = buf.len();

        let new_len = filter_netlink_dump(&mut buf, &[99]);
        assert_eq!(new_len, orig_len);
    }

    #[test]
    fn netlink_filter_removes_all() {
        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWADDR, 7));
        buf.extend(make_nlmsg(RTM_NEWADDR, 7));

        let new_len = filter_netlink_dump(&mut buf, &[7]);
        assert_eq!(new_len, 0);
    }

    #[test]
    fn netlink_filter_preserves_non_newaddr_msgs() {
        let nlmsg_done_type: u16 = 3; // NLMSG_DONE
        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWADDR, 7)); // VPN — remove
        buf.extend(make_nlmsg(nlmsg_done_type, 0)); // DONE — keep
        buf.extend(make_nlmsg(RTM_NEWADDR, 2)); // wlan — keep

        let new_len = filter_netlink_dump(&mut buf, &[7]);
        // Should keep DONE + wlan = 48 bytes
        assert_eq!(new_len, 48);
        assert_eq!(read_u16_ne(&buf, 4), Some(nlmsg_done_type));
        assert_eq!(read_u16_ne(&buf, 24 + 4), Some(RTM_NEWADDR));
        assert_eq!(read_u32_ne(&buf, 24 + NLMSG_HDRLEN + 4), Some(2));
    }

    #[test]
    fn netlink_filter_empty_indices() {
        let mut buf = make_nlmsg(RTM_NEWADDR, 7);
        let orig_len = buf.len();
        let new_len = filter_netlink_dump(&mut buf, &[]);
        assert_eq!(new_len, orig_len);
    }

    // ---- RTM_NEWROUTE (issue #86 `if<N>` leak) tests ----

    /// Build an RTM_NEWROUTE message: nlmsghdr + struct rtmsg + a single
    /// RTA_OIF rtattr carrying `oif`. Total = 16 + 12 + 8 = 36 bytes.
    fn make_route_nlmsg(oif: u32) -> Vec<u8> {
        make_route_nlmsg_inner(Some(oif))
    }

    fn make_route_nlmsg_inner(oif: Option<u32>) -> Vec<u8> {
        let body_len = if oif.is_some() {
            NLMSG_HDRLEN + RTMSG_HDRLEN + 8
        } else {
            NLMSG_HDRLEN + RTMSG_HDRLEN
        };
        let mut msg = Vec::new();
        msg.extend_from_slice(&(body_len as u32).to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&RTM_NEWROUTE.to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        msg.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        // struct rtmsg: family, dst_len, src_len, tos, table, protocol,
        // scope, type (8 bytes) + rtm_flags (u32).
        msg.extend_from_slice(&[2u8, 0, 0, 0, 254, 3, 0, 1]);
        msg.extend_from_slice(&0u32.to_ne_bytes());
        if let Some(oif) = oif {
            // RTA_OIF rtattr: rta_len (incl. 4-byte header) = 8, type, u32.
            msg.extend_from_slice(&8u16.to_ne_bytes());
            msg.extend_from_slice(&RTA_OIF.to_ne_bytes());
            msg.extend_from_slice(&oif.to_ne_bytes());
        }
        msg
    }

    /// Offset of the RTA_OIF value within a make_route_nlmsg() message.
    const ROUTE_OIF_OFF: usize = NLMSG_HDRLEN + RTMSG_HDRLEN + 4;

    #[test]
    fn route_oif_extracts_index() {
        let msg = make_route_nlmsg(33);
        assert_eq!(route_oif(&msg), Some(33));
        let no_oif = make_route_nlmsg_inner(None);
        assert_eq!(route_oif(&no_oif), None);
    }

    #[test]
    fn netlink_filter_removes_vpn_newroute() {
        let vpn_idx: u32 = 33; // tun0 — the `if33` case
        let route_len = make_route_nlmsg(0).len();

        let mut buf = Vec::new();
        buf.extend(make_route_nlmsg(2)); // wlan0 — keep
        buf.extend(make_route_nlmsg(vpn_idx)); // tun0 — remove
        buf.extend(make_route_nlmsg(4)); // rmnet — keep

        let new_len = filter_netlink_dump(&mut buf, &[vpn_idx]);
        assert_eq!(new_len, route_len * 2);
        // Remaining messages are wlan0 then rmnet, VPN route gone.
        assert_eq!(read_u32_ne(&buf, ROUTE_OIF_OFF), Some(2));
        assert_eq!(read_u32_ne(&buf, route_len + ROUTE_OIF_OFF), Some(4));
    }

    #[test]
    fn netlink_filter_keeps_route_without_oif() {
        // Multipath / oif-less routes must pass through untouched.
        let mut buf = make_route_nlmsg_inner(None);
        let orig_len = buf.len();
        let new_len = filter_netlink_dump(&mut buf, &[33]);
        assert_eq!(new_len, orig_len);
    }

    #[test]
    fn netlink_filter_mixed_link_and_route() {
        // A dump can interleave message types; only VPN-indexed ones drop.
        let vpn_idx: u32 = 33;
        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWLINK, vpn_idx)); // remove
        buf.extend(make_route_nlmsg(2)); // keep (wlan0)
        buf.extend(make_route_nlmsg(vpn_idx)); // remove (tun0)

        let new_len = filter_netlink_dump(&mut buf, &[vpn_idx]);
        assert_eq!(new_len, make_route_nlmsg(0).len());
        assert_eq!(read_u16_ne(&buf, 4), Some(RTM_NEWROUTE));
        assert_eq!(read_u32_ne(&buf, ROUTE_OIF_OFF), Some(2));
    }

    fn rule(ifname: &str, addr: [u8; 16], plen: u8) -> PrefixRule {
        PrefixRule {
            ifname: ifname.to_string(),
            addr,
            prefix_len: plen,
        }
    }

    #[test]
    fn prefix_match_plen_zero_matches_everything() {
        let any = [0xabu8; 16];
        assert!(prefix_match(&any, &[0u8; 16], 0));
        assert!(prefix_match(&[0u8; 16], &[0xffu8; 16], 0));
    }

    #[test]
    fn prefix_match_boundary_byte_and_off_by_one() {
        // 2409:40e3::/32 — the carrier blanket shape used on-device.
        let rule_addr: [u8; 16] = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut inside = rule_addr;
        inside[4] = 0xab; // first byte AFTER the /32 — must not matter
        inside[15] = 0xff;
        assert!(prefix_match(&inside, &rule_addr, 32));
        let mut outside = rule_addr;
        outside[3] ^= 0x01; // last bit of the boundary byte
        assert!(!prefix_match(&outside, &rule_addr, 32));
        outside = rule_addr;
        outside[2] ^= 0x80; // first bit of byte 2 (inside the /32)
        assert!(!prefix_match(&outside, &rule_addr, 32));
    }

    #[test]
    fn prefix_match_non_byte_aligned_and_edges() {
        let a: [u8; 16] = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // /31: top 7 bits of byte 3 must match (0xe2 vs 0xe3 differ only in bit 0).
        let mut b = a;
        b[3] = 0xe2; // 0b1110_0010 — same top 7 bits as 0xe3
        assert!(prefix_match(&b, &a, 31));
        b[3] = 0xe1; // differs in bit 1 (inside the /31)
        assert!(!prefix_match(&b, &a, 31));
        // /128 exact, /127 last bit ignored.
        assert!(prefix_match(&a, &a, 128));
        let mut c = a;
        c[15] = 1;
        assert!(!prefix_match(&c, &a, 128));
        assert!(prefix_match(&c, &a, 127));
        // Defensive: > 128 never matches.
        assert!(!prefix_match(&a, &a, 129));
    }

    #[test]
    fn prefix_rule_hit_scopes_by_ifname() {
        let rules = [rule(
            "rmnet_data1",
            [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        )];
        let addr = [
            0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        assert!(prefix_rule_hit(&rules, b"rmnet_data1", &addr));
        assert!(!prefix_rule_hit(&rules, b"rmnet_data3", &addr)); // same addr, other iface
        assert!(!prefix_rule_hit(&rules, b"rmnet_data1", &[0x26u8; 16])); // not covered
        assert!(!prefix_rule_hit(&[], b"rmnet_data1", &addr)); // empty rules
    }

    #[test]
    fn parse_addr32_hex_shape() {
        assert_eq!(
            parse_addr32_hex(b"240940e3000000000000000000000000"),
            Some([0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            parse_addr32_hex(b"240940E3000000000000000000000000"), // case-liberal
            Some([0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(parse_addr32_hex(b"2409"), None); // short
        assert_eq!(parse_addr32_hex(b"zz0940e3000000000000000000000000"), None);
    }

    #[test]
    fn max_prefix_rules_matches_wire_cap() {
        // Wire/parser cap is 8 everywhere (protocol crate, native parsers).
        assert_eq!(MAX_PREFIX_RULES, 8);
    }

    #[test]
    fn prefix_rules_fail_closed_empty_before_on_load() {
        // No on_load in host tests → the OnceLock is unset → fail-closed
        // empty rules (no prefix filtering).
        assert!(crate::prefix_rules().is_empty());
    }

    const PFX_RMNET1: [u8; 16] = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn if_inet6_ex_drops_covered_addr_on_rule_iface() {
        let rules = [rule("rmnet_data1", PFX_RMNET1, 32)];
        let input = b"240940e3000000000000000000000001 00000005 40 00 00 rmnet_data1\n\
                      24094123000000000000000000000001 00000007 40 00 00 rmnet_data3\n\
                      fe800000000000000000000000000001 00000005 40 00 00 rmnet_data1\n";
        let mut buf = input.to_vec();
        let n = filter_if_inet6_buf_ex(&mut buf, &rules);
        let out = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            !out.contains("240940e3"),
            "covered addr on rule iface dropped"
        );
        assert!(
            out.contains("24094123"),
            "other iface kept (rules scope by name)"
        );
        assert!(
            out.contains("fe800000"),
            "link-local kept (not covered by /32)"
        );
    }

    #[test]
    fn if_inet6_no_rules_is_byte_identical() {
        let input = b"240940e3000000000000000000000001 00000005 40 00 00 rmnet_data1\n";
        let mut buf = input.to_vec();
        let n = filter_if_inet6_buf_ex(&mut buf, &[]);
        assert_eq!(&buf[..n], input);
    }

    #[test]
    fn ipv6_route_ex_drops_covered_destination_keeps_defaults() {
        let rules = [rule("rmnet_data1", PFX_RMNET1, 32)];
        let input = b"240940e3000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 rmnet_data1\n\
                      00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000001 rmnet_data1\n\
                      fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 rmnet_data1\n";
        let mut buf = input.to_vec();
        let n = filter_ipv6_route_buf_ex(&mut buf, &rules);
        let out = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(!out.contains("240940e3"), "covered destination dropped");
        assert!(
            out.contains("00000000000000000000000000000000 00"),
            "default ::/0 kept — not inside a /32"
        );
        assert!(out.contains("fe800000"), "fe80 kept");
    }

    #[test]
    fn ipv6_route_ex_plen_zero_rule_covers_default() {
        // C parity: plen 0 matches every destination on the rule iface,
        // including ::/0. The route line's own plen field is never consulted.
        let rules = [rule("rmnet_data1", [0u8; 16], 0)];
        let input = b"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000001 rmnet_data1\n\
                      00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000001 rmnet_data3\n";
        let mut buf = input.to_vec();
        let n = filter_ipv6_route_buf_ex(&mut buf, &rules);
        let out = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(out.contains("rmnet_data3"));
        assert!(!out.contains("rmnet_data1"));
    }

    #[test]
    fn no_rules_wrappers_match_ex() {
        // The kept no-rules wrappers are exactly the _ex filters with an
        // empty rule set (and this keeps them exercised: their only
        // non-test caller moved to the _ex variants).
        let inet6 = b"240940e3000000000000000000000001 00000005 40 00 00 rmnet_data1\n";
        let mut a = inet6.to_vec();
        let mut b = inet6.to_vec();
        let na = filter_if_inet6_buf(&mut a);
        let nb = filter_if_inet6_buf_ex(&mut b, &[]);
        assert_eq!(&a[..na], &b[..nb]);

        let route = b"240940e3000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 rmnet_data1\n";
        let mut c = route.to_vec();
        let mut d = route.to_vec();
        let nc = filter_ipv6_route_buf(&mut c);
        let nd = filter_ipv6_route_buf_ex(&mut d, &[]);
        assert_eq!(&c[..nc], &d[..nd]);
    }

    fn make_newaddr6(
        if_index: u32,
        ifa_local: Option<[u8; 16]>,
        ifa_address: Option<[u8; 16]>,
    ) -> Vec<u8> {
        // nlmsghdr + ifaddrmsg(8) + rtattrs (16-byte payloads each).
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&[10u8, 64, 0, 0]); // family=AF_INET6, plen, flags, scope
        body.extend_from_slice(&if_index.to_ne_bytes());
        for (ty, val) in [(2u16, ifa_local), (1u16, ifa_address)] {
            if let Some(a) = val {
                body.extend_from_slice(&(4u16 + 16).to_ne_bytes()); // rta_len
                body.extend_from_slice(&ty.to_ne_bytes());
                body.extend_from_slice(&a);
            }
        }
        let total = (NLMSG_HDRLEN + body.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&total.to_ne_bytes());
        msg.extend_from_slice(&RTM_NEWADDR.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    fn make_newroute6(oif: u32, dst: Option<[u8; 16]>) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&[10u8, 0, 0, 0, 254, 3, 0, 1]); // rtmsg, family AF_INET6
        body.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        body.extend_from_slice(&8u16.to_ne_bytes()); // RTA_OIF rta_len
        body.extend_from_slice(&RTA_OIF.to_ne_bytes());
        body.extend_from_slice(&oif.to_ne_bytes());
        if let Some(d) = dst {
            body.extend_from_slice(&(4u16 + 16).to_ne_bytes());
            body.extend_from_slice(&RTA_DST.to_ne_bytes());
            body.extend_from_slice(&d);
        }
        let total = (NLMSG_HDRLEN + body.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&total.to_ne_bytes());
        msg.extend_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    fn prule(index: u32, addr: [u8; 16], plen: u8) -> IndexedPrefixRule {
        IndexedPrefixRule {
            index,
            addr,
            prefix_len: plen,
        }
    }

    #[test]
    fn newaddr6_dropped_by_local_prefix() {
        let inside = [
            0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let mut buf = Vec::new();
        buf.extend(make_newaddr6(5, Some(inside), None)); // covered — drop
        buf.extend(make_newaddr6(6, Some(inside), None)); // same addr, other index — keep
        let half = buf.len() / 2;
        let prules = [prule(5, PFX_RMNET1, 32)];
        let n = filter_netlink_dump_ex(&mut buf, &[], &prules);
        assert_eq!(n, half);
        assert_eq!(read_u32_ne(&buf, NLMSG_HDRLEN + 4), Some(6));
    }

    #[test]
    fn newaddr6_falls_back_to_ifa_address() {
        let inside = [
            0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let mut buf = make_newaddr6(5, None, Some(inside));
        let prules = [prule(5, PFX_RMNET1, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut buf, &[], &prules), 0);
    }

    #[test]
    fn newaddr6_ipv4_never_filtered() {
        // Same bytes but family = AF_INET (2): the hard-constraint gate.
        let mut msg = make_newaddr6(
            5,
            Some([
                0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ]),
            None,
        );
        msg[NLMSG_HDRLEN] = 2; // ifa_family = AF_INET
        let len = msg.len();
        let prules = [prule(5, PFX_RMNET1, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut msg, &[], &prules), len);
    }

    #[test]
    fn newroute6_dropped_by_dst_prefix() {
        let covered = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = Vec::new();
        buf.extend(make_newroute6(5, Some(covered))); // covered — drop
        buf.extend(make_newroute6(
            5,
            Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        )); // fe80 — keep
        let half = buf.len() / 2;
        let prules = [prule(5, PFX_RMNET1, 32)];
        let n = filter_netlink_dump_ex(&mut buf, &[], &prules);
        assert_eq!(n, half);
    }

    #[test]
    fn newroute6_missing_dst_means_default() {
        // No RTA_DST = ::/0 (all-zero). A plen-0 rule covers it; a /32 doesn't.
        let mut buf = make_newroute6(5, None);
        let plen0 = [prule(5, [0u8; 16], 0)];
        assert_eq!(filter_netlink_dump_ex(&mut buf, &[], &plen0), 0);
        let mut buf2 = make_newroute6(5, None);
        let len2 = buf2.len();
        let plen32 = [prule(5, PFX_RMNET1, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut buf2, &[], &plen32), len2);
    }

    #[test]
    fn newroute6_short_dst_rta_is_safe_miss() {
        // rta_len < 20 for RTA_DST: treated as absent (:: — no /32 match).
        let mut msg = make_newroute6(
            5,
            Some([0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        // Patch the RTA_DST rta_len down to 12 (4 header + 8 payload < 16-byte addr).
        let rta_dst_len_off = NLMSG_HDRLEN + RTMSG_HDRLEN + 8;
        msg[rta_dst_len_off..rta_dst_len_off + 2].copy_from_slice(&(12u16).to_ne_bytes());
        let len = msg.len();
        let prules = [prule(5, PFX_RMNET1, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut msg, &[], &prules), len);
    }

    #[test]
    fn newroute6_ipv4_never_filtered() {
        // Same bytes but rtm_family = AF_INET (2): the hard-constraint gate.
        let covered = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut msg = make_newroute6(5, Some(covered));
        msg[NLMSG_HDRLEN] = 2; // rtm_family = AF_INET
        let len = msg.len();
        let prules = [prule(5, PFX_RMNET1, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut msg, &[], &prules), len);
    }

    #[test]
    fn netlink_wrapper_unchanged_without_rules() {
        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWADDR, 7));
        buf.extend(make_nlmsg(RTM_NEWADDR, 2));
        let n = filter_netlink_dump(&mut buf, &[7]);
        assert_eq!(n, 24);
    }
}
