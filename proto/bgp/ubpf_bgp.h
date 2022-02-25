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

struct pending_msgs {
    node n;
    int type;
    size_t buf_len;
    u8 buf[0];
};

extern inline int ret_val_filter(uint64_t a);

extern int ret_val_check_decode(uint64_t a);

extern int ret_val_check_encode_attr(uint64_t val);

extern int ret_val_decision_process(uint64_t val);

extern int ret_val_decode_bgp_message(uint64_t val);

#endif //PLUGINIZED_BIRD_UBPF_BGP_H
