// AUTO-GENERATED from data/hooks.toml — do not edit by hand. Regenerate with: uv run scripts/codegen-hooks.py

#![allow(dead_code)]

/// Global hook id space (data/hooks.toml). bit N == hook id N.
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Hook {
    /// /proc/net/route — IPv4 route lines
    FibRouteSeqShow = 0,
    /// /proc/net/ipv6_route — IPv6 route lines
    Ipv6RouteSeqShow = 1,
    /// RTM_NEWLINK — getifaddrs() link enumeration
    RtnlFillIfinfo = 2,
    /// RTM_GETADDR — IPv4 address dump
    InetFillIfaddr = 3,
    /// RTM_GETADDR — IPv6 address dump
    Inet6FillIfaddr = 4,
    /// SIOCGIF* by name (per-interface ioctls)
    DevIoctl = 5,
    /// SIOCGIFCONF — interface list ioctl
    SockIoctl = 6,
    /// RTM_GETROUTE — IPv4 route dump (issue #86)
    FibDumpInfo = 7,
    /// RTM_GETROUTE — IPv6 route dump
    Rt6FillNode = 8,
    /// RTM_GETRULE — policy routing rules
    FibNlFillRule = 9,
    /// LinkProperties parcel/result sanitization
    LsposedLinkProperties = 10,
    /// NetworkCapabilities parcel/result sanitization
    LsposedNetworkCapabilities = 11,
    /// NetworkInfo parcel/result sanitization
    LsposedNetworkInfo = 12,
    /// Network handle replacement/filtering
    LsposedNetwork = 13,
    /// ConnectivityService synchronous result filtering
    LsposedConnectivityResult = 14,
    /// ConnectivityService callback filtering
    LsposedConnectivityCallback = 15,
    /// ConnectivityService Network handle APIs
    LsposedConnectivityNetwork = 16,
    /// PackageManager app-hiding filters
    LsposedPackageVisibility = 17,
    /// libc ioctl() SIOCGIF* interface probes
    ZygiskIoctl = 18,
    /// libc getifaddrs() interface enumeration
    ZygiskGetifaddrs = 19,
    /// openat() filtering for /proc/net routes and sockets
    ZygiskOpenat = 20,
    /// recvmsg() netlink dump filtering
    ZygiskRecvmsg = 21,
    /// recv() netlink dump filtering
    ZygiskRecv = 22,
    /// recvfrom() netlink dump filtering
    ZygiskRecvfrom = 23,
    /// __recvfrom_chk() fortified netlink dump filtering
    ZygiskRecvfromChk = 24,
    /// SO_BINDTODEVICE / SO_BINDTOIFINDEX pre-mutation denial
    SocketBindInterface = 25,
    /// libc setsockopt() best-effort socket-interface bind denial
    ZygiskSetsockopt = 26,
}

pub const HOOK_COUNT: u32 = 27;

/// Hooks owned by each backend: apply `mask & own`.
pub const KERNEL_HOOK_MASK: u32 = 0x20003ff;
pub const ZYGISK_HOOK_MASK: u32 = 0x5fc0000;
pub const LSPOSED_HOOK_MASK: u32 = 0x3fc00;

/// status error codes (protocol §5.1).
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum StatusError {
    /// healthy; every requested, owned hook installed
    Ok = 0,
    /// no offset table for the running kernel — refused, no hooks
    UnsupportedKver = 1,
    /// the other kernel backend (.ko<->KPM) is loaded — refused (protocol §1.2)
    ConflictingBackend = 2,
    /// a required kallsyms symbol was missing — refused
    SymbolResolutionFailed = 3,
    /// installed, but some owned hooks did not resolve (see the hooks mask)
    PartialHooks = 4,
}

/// backend ids (protocol §4.3 `status backend <id>`).
#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Backend {
    /// .ko kretprobe backend
    Kmod = 0,
    /// KernelPatch Module backend
    Kpm = 1,
    /// Zygisk libc-hook backend
    Zygisk = 2,
    /// LSPosed Java-hook backend (system_server)
    Lsposed = 3,
}

pub const HOOK_NAMES: [&str; 27] = [
    "fib_route_seq_show",
    "ipv6_route_seq_show",
    "rtnl_fill_ifinfo",
    "inet_fill_ifaddr",
    "inet6_fill_ifaddr",
    "dev_ioctl",
    "sock_ioctl",
    "fib_dump_info",
    "rt6_fill_node",
    "fib_nl_fill_rule",
    "lsposed_link_properties",
    "lsposed_network_capabilities",
    "lsposed_network_info",
    "lsposed_network",
    "lsposed_connectivity_result",
    "lsposed_connectivity_callback",
    "lsposed_connectivity_network",
    "lsposed_package_visibility",
    "zygisk_ioctl",
    "zygisk_getifaddrs",
    "zygisk_openat",
    "zygisk_recvmsg",
    "zygisk_recv",
    "zygisk_recvfrom",
    "zygisk_recvfrom_chk",
    "socket_bind_interface",
    "zygisk_setsockopt",
];
