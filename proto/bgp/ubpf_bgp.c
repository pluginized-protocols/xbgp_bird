//
// Created by thomas on 19/02/20.
//

#include <tools_ubpf_api.h>
#include <nest/route.h>
#include "public.h"
#include "ubpf_bgp.h"
#include "nest/attrs.h"
#include "lib/timer.h"
#include "nest/protocol.h"
#include "bgp.h"

static inline int is_u32_attr(word id) {

    switch (id) {
        case BA_ORIGIN:
        case BA_MULTI_EXIT_DISC:
        case BA_LOCAL_PREF:
        case BA_ORIGINATOR_ID:
            return 1;
        case BA_AS4_PATH:
        case BA_EXT_COMMUNITY:
        case BA_MP_UNREACH_NLRI:
        case BA_CLUSTER_LIST:
        case BA_MP_REACH_NLRI:
        case BA_AS4_AGGREGATOR:
        case BA_AIGP:
        case BA_LARGE_COMMUNITY:
        case BA_MPLS_LABEL_STACK:
        case BA_AS_PATH:
        case BA_NEXT_HOP:
        case BA_ATOMIC_AGGR:
        case BA_AGGREGATOR:
        case BA_COMMUNITY:
        default:
            return 0;
    }

}

static inline struct path_attribute *bird_to_vm_attr(context_t *ctx, eattr *oiseau) {

    struct path_attribute *attr_path;
    int is_u32 = 0;
    size_t attr_len;

    if (!oiseau) return NULL;

    attr_path = ctx_malloc(ctx, sizeof(struct path_attribute));
    if (!attr_path) return NULL;

    attr_path->code = EA_ID(oiseau->id);
    attr_path->flags = oiseau->flags;

    attr_len = (is_u32 = is_u32_attr(attr_path->code)) ? sizeof(uint32_t) :
               oiseau->u.ptr->length;

    attr_path->data = ctx_malloc(ctx, attr_len);
    if (!attr_path->data) return NULL;

    if (!is_u32) {
        memcpy(attr_path->data, oiseau->u.ptr, attr_len);
    } else {
        *attr_path->data = oiseau->u.data;
    }
    return attr_path;

}

int add_attr(context_t *ctx, uint code, uint flags, uint8_t *decoded_attr) {

    bpf_full_args_t *args = ctx->args;

    if (!safe_args(args, 4, ATTRIBUTE_LIST)) return -1;
    if (!safe_args(args, 5, PARSE_STATE)) return -1;

    ea_list **to = get_arg(args, 4, ea_list **);
    struct bgp_parse_state *s = get_arg(args, 5, struct bgp_parse_state *);

    // this function copy the memory pointed by
    // decoded_attr to the protocol memory
    bgp_set_attr_data(to, s->pool, code, flags, decoded_attr, 8);
    return 0;
}

struct path_attribute *get_attr(context_t *ctx) {

    int i;
    bpf_full_args_t *fargs;
    eattr *bird_attr;

    if (!ctx) return NULL; // Should normally not happen. If it does, the virtual machine is broken

    fargs = ctx->args;
    for (i = 0; i < fargs->nargs; i++) {
        if (fargs[i].args->type == ATTRIBUTE) {
            bird_attr = fargs[i].args->arg;
            return bird_to_vm_attr(ctx, bird_attr);
        }
    }
    return NULL;
}

int write_to_buffer(context_t *ctx, uint8_t *ptr, size_t len) {

    byte *buf;
    bpf_full_args_t *fargs;
    size_t remaining_len = 0;

    if (!ctx || !ptr || len == 0) return -1;

    fargs = ctx->args;
    if (fargs->nargs < 4) return -1;

    if (fargs[0].args->type == BUFFER_ARRAY) {
        buf = fargs[0].args->arg;
    } else {
        return -1;
    }

    if (fargs[1].args->type == UNSIGNED_INT) {
        remaining_len = *(uint *)fargs[0].args->arg;
    } else {
        return -1;
    }

    if (len > remaining_len) return -1;
    memcpy(buf, ptr, len);
    return 0;
}

struct path_attribute *get_attr_by_code_from_rte(context_t *ctx, uint8_t code, int args_rte) {

    eattr *attr;
    rte *route;
    bpf_full_args_t *args = ctx->args;

    if (!safe_args(args, args_rte, BGP_ROUTE)) return NULL;
    route = get_arg(args, args_rte, rte *);

    if (!(attr = bgp_find_attr(route->attrs->eattrs, code))) return NULL;

    return bird_to_vm_attr(ctx, attr);
}


