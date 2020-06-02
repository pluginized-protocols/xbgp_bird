//
// Created by twirtgen on 10/02/20.
//

#ifndef PLUGINIZED_BIRD_UBPF_BGP_H
#define PLUGINIZED_BIRD_UBPF_BGP_H

#include <stdint.h>
#include <stdlib.h>

#include "ubpf_api_common.h"

enum ubpf_plugins {
    BGP_MED_DECISION = 1, // decision process MED insertion point
    BGP_DECODE_ATTR,
    BGP_ENCODE_ATTR,
    BGP_PRE_INBOUND_FILTER,
    BGP_PRE_OUTBOUND_FILTER,
};

enum type {
    TYPE_NULL = 0,
    BGP_ROUTE,
    UNSIGNED_INT,
    BYTE_ARRAY,
    ATTRIBUTE_LIST,
    ATTRIBUTE,
    PARSE_STATE,
    WRITE_STATE,
    BUFFER_ARRAY,
    BGP_SRC_INFO,
    BGP_TO_INFO,
    HOST_LINPOOL,
    PREFIX,
};

static inline int ret_val_filter(uint64_t a) {
    switch (a) {
        case PLUGIN_FILTER_REJECT:
        case PLUGIN_FILTER_ACCEPT:
            return 1;
        case PLUGIN_FILTER_UNK:
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

static int UNUSED ret_val_med_decision(uint64_t val) {
    switch (val) {
        case RTE_NEW:
        case RTE_OLD:
            return 1;
        case RTE_UNK:
        default:
            return 0;
    }
}

int add_attr(context_t *ctx, uint code, uint flags, uint16_t length, uint8_t *decoded_attr);

struct path_attribute *get_attr(context_t *ctx);

int set_attr(context_t *ctx, struct path_attribute *attr);

int write_to_buffer(context_t *ctx, uint8_t *buf, size_t len);

struct path_attribute *get_attr_by_code_from_rte(context_t *ctx, uint8_t code, int args_rte);

struct ubpf_peer_info *get_peer_info(context_t *ctx);

struct ubpf_peer_info *get_src_peer_info(context_t *ctx);

void *get_peer_info_src_extra(context_t *ctx, int key);

void *get_peer_info_extra(context_t *ctx, int key);

int set_peer_info(context_t *ctx, int key, void *value, int len);

int set_peer_info_src(context_t *ctx, int key, void *value, int len);

struct path_attribute *get_attr_from_code(context_t *ctx, uint8_t code);

union prefix *get_prefix(context_t *ctx);

#endif //PLUGINIZED_BIRD_UBPF_BGP_H
