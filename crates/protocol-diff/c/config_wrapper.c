#include "shared/vpnhide_logic.h"

/* Stable external symbol for the otherwise static-inline freestanding parser. */
int vpnhide_diff_parse_config(const unsigned char *input, unsigned long len,
                              struct vpnhide_target *targets, int capacity,
                              int *debug)
{
    return vpnhide_parse_config((const char *)input, len, targets, capacity,
                                debug);
}

/* Extended wrapper: also surfaces parsed prefix + prefix4 rules for the diff
 * oracle. */
int vpnhide_diff_parse_config_ex(const unsigned char *input, unsigned long len,
                                 struct vpnhide_target *targets, int capacity,
                                 int *debug,
                                 struct vpnhide_prefix_rule *prefixes,
                                 int pcapacity, int *pcount,
                                 struct vpnhide_prefix4_rule *prefixes4,
                                 int p4capacity, int *p4count)
{
    return vpnhide_parse_config_ex((const char *)input, len, targets, capacity,
                                   debug, prefixes, pcapacity, pcount,
                                   prefixes4, p4capacity, p4count);
}
