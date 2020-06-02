//
// Created by thomas on 2/06/20.
//

#include "../../public_bpf.h"
#include "../../prefix.h"
#include "ubpf_api.h"

#define AS_PATH_ATTR_CODE 2

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define numcmp(a, b)                                                           \
    ({                                                                     \
        typeof(a) _cmp_a = (a);                                        \
        typeof(b) _cmp_b = (b);                                        \
        (_cmp_a < _cmp_b) ? -1 : ((_cmp_a > _cmp_b) ? 1 : 0);          \
    })

int __always_inline prefixes_same(union prefix *pfx1, union prefix *pfx2) {

    if (pfx1->family != pfx2->family) return 0;

    if (pfx1->family == AF_INET) {
        if (pfx1->ip4_pfx.prefix_len != pfx2->ip4_pfx.prefix_len) return 0;
        return pfx1->ip4_pfx.p.s_addr == pfx2->ip4_pfx.p.s_addr;

    } else if (pfx1->family == AF_INET6) {
        if (pfx1->ip6_pfx.prefix_len != pfx2->ip6_pfx.prefix_len) return 0;
        return ebpf_memcmp(&pfx1->ip6_pfx.p, &pfx2->ip6_pfx.p, 16) == 0;
    }

    return 0;
}

/*
 * returns  1 if pfx1 is more specific than pfx2
 *          0 pfx1 is the same as pfx2
 *         -1 pfx1 is more general than pfx2
 *         -2 unable to determine (family mismatch or longest common bits are lower than MIN(pfx1.len, pfx2.len))
 */
int __always_inline cmp_prefix(union prefix *pfx1, union prefix *pfx2) {

    int pos, bit;
    int length;
    uint8_t xor;
    int longest_match;
    uint8_t *p1, *p2;
    int min_len, pfx1_len;

    if (pfx1->family != pfx2->family) return -2;

    if (pfx1->family == AF_INET) {
        length = 4;
        p1 = (uint8_t *) &pfx1->ip4_pfx.p.s_addr;
        p2 = (uint8_t *) &pfx2->ip4_pfx.p.s_addr;

        min_len = MIN(pfx1->ip4_pfx.prefix_len, pfx2->ip4_pfx.prefix_len);
        pfx1_len = pfx1->ip4_pfx.prefix_len;

    } else if (pfx1->family == AF_INET6) {
        length = 16;
        p1 = pfx1->ip6_pfx.p.s6_addr;
        p2 = pfx2->ip6_pfx.p.s6_addr;

        min_len = MIN(pfx1->ip6_pfx.prefix_len, pfx2->ip6_pfx.prefix_len);
        pfx1_len = pfx1->ip6_pfx.prefix_len;
    } else {
        return -2;
    }

    for (pos = 0; pos < length; pos++)
        if (p1[pos] != p2[pos])
            break;
    if (pos == length)
        return pos * 8;

    xor = p1[pos] ^ p2[pos];
    for (bit = 0; bit < 8; bit++)
        if (xor & (1u << (7u - bit)))
            break;

    longest_match = pos * 8 + bit;

    if (longest_match < min_len) return -2; // unk ?

    return numcmp(pfx1_len, longest_match);
}

uint32_t __always_inline rightmost_asn(struct path_attribute *attr) {

    uint32_t asn;

    if (attr->code != AS_PATH_ATTR_CODE) return 0;

    asn = *((uint32_t *) (&attr->data[(attr->len / 4) - 1]));

    return asn;
}

uint64_t prefix_validator(bpf_full_args_t *args) {
    int i;
    struct global_info info;
    struct global_info current_roa, current_asn, current_prefix;
    int cmp_info;
    uint64_t current_as_number;
    union prefix ipfx;
    union prefix *pfx_to_validate;
    struct path_attribute *as_path;

    as_path = get_attr_from_code(AS_PATH_ATTR_CODE);
    pfx_to_validate = get_prefix();
    if (!as_path) return FAIL;

    if (get_extra_info("allowed_prefixes", &info) != 0) next();

    for (i = 0;; i++) {
        if (get_extra_info_lst_idx(&info, i, &current_roa) != 0) break;

        if (get_extra_info_lst_idx(&current_roa, 0, &current_asn) != 0) {
            return FAIL;
        } if (get_extra_info_lst_idx(&current_roa, 1, &current_prefix) != 0) {
            return FAIL;
        } if (get_extra_info_value(&current_asn, &current_as_number, sizeof(current_as_number)) != 0) {
            return FAIL;
        } if (get_extra_info_value(&current_prefix, &ipfx, sizeof(ipfx)) != 0) {
            return FAIL;
        }
        cmp_info = cmp_prefix(pfx_to_validate, &ipfx);

        if (cmp_info == -2) continue;
        else if (cmp_info > 0) return PLUGIN_FILTER_REJECT; // more specific than ROA

        if (rightmost_asn(as_path) == current_as_number) {
            if (cmp_info == 0) next();
        } else if (cmp_info == 0) return PLUGIN_FILTER_REJECT;
    }

    // no ROA associated to this prefix --> unknown, move to next filter
    next();
    // shouldn't be reached
    return PLUGIN_FILTER_REJECT;
}