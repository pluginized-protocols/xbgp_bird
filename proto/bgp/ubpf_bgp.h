//
// Created by twirtgen on 10/02/20.
//

#ifndef PLUGINIZED_BIRD_UBPF_BGP_H
#define PLUGINIZED_BIRD_UBPF_BGP_H

#include <stdint.h>
#include <stdlib.h>
#include <xbgp_compliant_api/xbgp_defs.h>

enum type {
    TYPE_NULL = ARG_MAX_OPAQUE,
    BGP_ROUTE,
    UNSIGNED_INT,
    BYTE_ARRAY,
    PARSE_STATE,
    WRITE_STATE,
    BUFFER_ARRAY,
    BGP_SRC_INFO,
    BGP_TO_INFO,
    HOST_LINPOOL,
    LOC_RIB_TABLE,
    RIB_IN_TABLE,
    RIB_OUT_TABLE,
};

static inline int ret_val_filter(uint64_t a) {
    switch (a) {
        case PLUGIN_FILTER_REJECT:
        case PLUGIN_FILTER_ACCEPT:
            return 1;
        case PLUGIN_FILTER_UNKNOWN:
        default:
            return 0;
    }
}

static inline int ret_val_check_decode(uint64_t a) {
    return a == EXIT_FAILURE ? 0 : 1;
}

static inline int ret_val_check_encode_attr(uint64_t val) {
    if (val > 4096) return 0; // RFC 4271 says 4KB max TODO CHECK
    if (val == 0) return 1;

    return 1;
}

static int UNUSED ret_val_decision_process(uint64_t val) {
    switch (val) {
        case BGP_ROUTE_TYPE_NEW:
        case BGP_ROUTE_TYPE_OLD:
            return 1;
        case BGP_ROUTE_TYPE_UNKNOWN:
        default:
            return 0;
    }
}

#endif //PLUGINIZED_BIRD_UBPF_BGP_H
