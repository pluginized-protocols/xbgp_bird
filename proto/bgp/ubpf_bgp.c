//
// Created by thomas on 19/02/20.
//

#include <tools_ubpf_api.h>
#include <nest/route.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "ubpf_public.h"
#include "ubpf_bgp.h"
#include "nest/attrs.h"
#include "lib/timer.h"
#include "nest/protocol.h"
#include "bgp.h"
#include "ubpf_prefix.h"

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

static eattr *eattr_append(struct linpool *pool, ea_list *e, int id UNUSED) {

    while (e->next != NULL) {
        e = e->next;
    }

    ea_list *new = lp_alloc(pool, sizeof(ea_list) + sizeof(eattr));

    if (!new) {
        fprintf(stderr, "Unable to allocate new attribute\n");
        return NULL;
    }

    eattr *e_new = &new->attrs[0];

    new->flags = EALF_SORTED;
    new->count = 1;
    new->next = NULL;
    e->next = new;

    new->next = NULL;

    return e_new;
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

    attr_len = (is_u32 = (oiseau->type & EAF_EMBEDDED)) ? sizeof(uint32_t) :
               oiseau->u.ptr->length;

    attr_path->data = ctx_malloc(ctx, attr_len);
    if (!attr_path->data) return NULL;
    attr_path->len = attr_len;

    if (!is_u32) {
        memcpy(attr_path->data, oiseau->u.ptr->data, attr_len);
    } else {
        *attr_path->data = oiseau->u.data;
    }
    return attr_path;

}

int add_attr(context_t *ctx, uint code, uint flags, uint16_t length, uint8_t *decoded_attr) {

    ea_list *to = get_arg_from_type(ctx, ATTRIBUTE_LIST);
    struct bgp_parse_state *s = get_arg_from_type(ctx, PARSE_STATE);

    // this function copy the memory pointed by
    // decoded_attr to the protocol memory

    flags |= 1u; // distinguish pluginized attribute from unknown one
    // flags will be reinitialized when exporting, see attr.c:bgp_export_attr

    ea_set_attr_data(&to, s->pool, EA_CODE(PROTOCOL_BGP, code), flags, EAF_TYPE_OPAQUE, decoded_attr, length);
    return 0;
}

int set_attr(context_t *ctx, struct path_attribute *attr) {
    struct linpool *pool;
    struct adata *a;

    ea_list *attr_list = NULL;
    eattr *attr_stored;

    if (!attr) return -1;
    if (!attr->data) return -1;

    attr_list = get_arg_from_type(ctx, ATTRIBUTE_LIST);
    if (!attr_list) return -1;

    attr_stored = ea_find(attr_list, EA_CODE(PROTOCOL_BGP, attr->code));
    if (!attr_stored) { // add new attr
        pool = get_arg_from_type(ctx, HOST_LINPOOL);
        if (!pool) return -1;

        attr_stored = eattr_append(pool, attr_list, attr->code);
        if (!attr_stored) return -1;

        attr_stored->id = EA_CODE(PROTOCOL_BGP, attr->code);
        attr_stored->flags = attr->flags;
        attr_stored->flags |= 1u; // pluginized attribute.
        attr_stored->type = EAF_TYPE_OPAQUE;

        a = lp_alloc_adata(pool, attr->len);

        if (!a) return -1;

        memcpy(a->data, attr->data, attr->len);
        attr_stored->u.ptr = a;
    } else { // replace existing one
        attr_stored->flags = attr->flags;
        if (attr_stored->type & EAF_EMBEDDED) {
            attr_stored->u.data = *((uint32_t *) attr->data);
        } else {
            if (attr_stored->u.ptr->length < attr->len) {
                return -1;
            }
            memcpy(attr_stored->u.ptr->data, attr->data, attr->len);
        }

        attr_stored->type |= EAF_FRESH;
    }
    return 0;
}

struct path_attribute *get_attr(context_t *ctx) {

    int i;
    args_t *fargs;
    eattr *bird_attr;

    if (!ctx) return NULL; // Should normally not happen. If it does, the virtual machine is broken

    fargs = ctx->args;
    for (i = 0; i < fargs->nargs; i++) {
        if (fargs->args[i].type == ATTRIBUTE) {
            bird_attr = fargs->args[i].arg;
            return bird_to_vm_attr(ctx, bird_attr);
        }
    }
    return NULL;
}

int write_to_buffer(context_t *ctx, uint8_t *ptr, size_t len) {

    byte *buf;
    args_t *fargs;
    size_t remaining_len = 0;

    if (!ctx || !ptr || len == 0) return -1;

    fargs = ctx->args;
    if (fargs->nargs < 4) return -1;

    if (fargs->args[0].type == BUFFER_ARRAY) {
        buf = fargs->args[0].arg;
    } else {
        return -1;
    }

    if (fargs->args[1].type == UNSIGNED_INT) {
        remaining_len = *(uint *) fargs->args[1].arg;
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

    route = get_arg_from_type(ctx, BGP_ROUTE);

    if (!(attr = bgp_find_attr(route->attrs->eattrs, code))) return NULL;

    return bird_to_vm_attr(ctx, attr);
}


static void fill_bgp_info(struct ubpf_peer_info *peer_info, struct bgp_proto *peer_proto, int local) {

    uint32_t h_ipv4;
    ip6_addr ip6;
    char addr_str[48];

    peer_info->as = local ? peer_proto->public_as : peer_proto->remote_as;
    peer_info->router_id = local ? peer_proto->local_id : peer_proto->remote_id;
    peer_info->capability = 0; // TODO HERE ?
    peer_info->peer_type =
            peer_proto->is_internal ? IBGP_SESSION : EBGP_SESSION;

    if(ipa_is_ip4(peer_proto->local_ip)) {
        peer_info->addr.af = AF_INET;
        h_ipv4 = ipa_to_u32(local ? peer_proto->local_ip : peer_proto->remote_ip);
        peer_info->addr.addr.in.s_addr = htonl(h_ipv4);
    } else {
        peer_info->addr.af = AF_INET6;
        memset(addr_str, 0, sizeof(char) * 48);
        ip6 = ip6_hton(local ? peer_proto->local_ip : peer_proto->remote_ip);
        ip6_ntop(ip6, addr_str);
        inet_pton(AF_INET6, addr_str, &peer_info->addr.addr.in6);
    }
    peer_info->local_bgp_session = NULL;
}


static struct ubpf_peer_info *get_peer_info_(context_t *ctx, int which_peer) {
    struct bgp_proto *bgp_info = NULL;
    struct bgp_proto *local_bgp = NULL;
    struct ubpf_peer_info *peer_info;
    struct ubpf_peer_info *local_info;

    bgp_info = get_arg_from_type(ctx, which_peer);
    if (!bgp_info) {
        fprintf(stderr, "NO BGP_INFO\n");
        return NULL;
    }

    peer_info = ctx_malloc(ctx, sizeof(*peer_info));
    local_info = ctx_malloc(ctx, sizeof(*local_bgp));
    if (!peer_info || !local_info) {
        return NULL;
    }

    fill_bgp_info(peer_info, bgp_info, 0);
    fill_bgp_info(local_info, bgp_info, 1);

    peer_info->local_bgp_session = local_info;

    return peer_info;
}

struct ubpf_peer_info *get_src_peer_info(context_t *ctx) {
    return get_peer_info_(ctx, BGP_SRC_INFO);
}

struct ubpf_peer_info *get_peer_info(context_t *ctx, int *nb_peers){

    if (!nb_peers) return NULL;
    *nb_peers = 1;

    return get_peer_info_(ctx, BGP_TO_INFO);
}

static int set_peer_info_(context_t *ctx, int key, void *value, int len, int type) {

    struct bgp_proto *bgp_info = NULL;
    mem_pool *mp;

    bgp_info = get_arg_from_type(ctx, type);
    if (!bgp_info) {
        fprintf(stderr, "NO BGP_INFO\n");
        return -1;
    }

    mp = bgp_info->mempool;
    if (!mp){
        fprintf(stderr, "Error, mempool not init");
        return -1;
    }

    if (add_mempool(mp, key, NULL, len, value,0) != 0) return -1;

    return 0;
}

int set_peer_info_src(context_t *ctx, int key, void *value, int len) {
    return set_peer_info_(ctx, key, value, len, BGP_SRC_INFO);
}

int set_peer_info(context_t *ctx, int key, void *value, int len) {
    return set_peer_info_(ctx, key, value, len, BGP_TO_INFO);
}

static void *get_peer_info_mp_(context_t *ctx, int key, int which_peer) {

    struct bgp_proto *bgp_info = NULL;
    struct mempool_data data;
    mem_pool *mp;
    void *plugin_data;

    bgp_info = get_arg_from_type(ctx, which_peer);
    if (!bgp_info) {
        fprintf(stderr, "NO BGP_INFO\n");
        return NULL;
    }

    mp = bgp_info->mempool;
    if (!mp){
        fprintf(stderr, "Error, mempool not init");
        return NULL;
    }

    if (get_mempool_data(mp, key, &data) != 0) return NULL;

    plugin_data = ctx_malloc(ctx, data.length);
    if (!plugin_data) return NULL;

    memcpy(plugin_data, data.data, data.length);
    return plugin_data;
}

void *get_peer_info_src_extra(context_t *ctx, int key) {
    return get_peer_info_mp_(ctx, key, BGP_SRC_INFO);
}

void *get_peer_info_extra(context_t *ctx, int key) {
    return get_peer_info_mp_(ctx, key, BGP_TO_INFO);
}

struct path_attribute *get_attr_from_code(context_t *ctx, uint8_t code) {
    ea_list *attr_list;
    eattr *attr;
    struct path_attribute *plugin_attr;
    uint8_t *data;

    attr_list = get_arg_from_type(ctx, ATTRIBUTE_LIST);
    if (!attr_list) return NULL;
    attr = ea_find(attr_list, EA_CODE(PROTOCOL_BGP, code));
    if (!attr) return NULL;

    plugin_attr = ctx_malloc(ctx, sizeof(*plugin_attr));
    if (!plugin_attr) return NULL;

    plugin_attr->code = code;
    plugin_attr->flags = attr->flags;
    if (attr->type & EAF_EMBEDDED) {
        data = ctx_malloc(ctx, sizeof(uint32_t));
        if (!data) return NULL;
        memcpy(data, &attr->u.data, 4);
        plugin_attr->len = 4;
    } else {
        data = ctx_malloc(ctx, attr->u.ptr->length);
        if (!data) return NULL;
        memcpy(data, attr->u.ptr->data, attr->u.ptr->length);
        plugin_attr->len = attr->u.ptr->length;
    }
    plugin_attr->data = data;
    return plugin_attr;
}


union ubpf_prefix *get_prefix(context_t *ctx) {

    net_addr *n = get_arg_from_type(ctx, PREFIX);
    net_addr_ip4 *nip4;
    net_addr_ip6 *nip6;

    union ubpf_prefix *prfx;
    struct in6_addr in6;

    if (!n) return NULL;

    prfx = ctx_malloc(ctx, sizeof(*prfx));
    if (!prfx) return NULL;

    if (n->type == NET_IP4) {
        nip4 = (net_addr_ip4 *) n;

        prfx->family = AF_INET;

        prfx->ip4_pfx.family = AF_INET;
        prfx->ip4_pfx.prefix_len = n->pxlen;
        prfx->ip4_pfx.p.s_addr = htonl(ip4_to_u32(nip4->prefix));

    } else if (n->type == NET_IP6) {

        prfx->family = AF_INET6;

        nip6 = (net_addr_ip6 *) n;
        memset(&in6, 0, sizeof(in6));

        in6.s6_addr32[0] = htonl(nip6->prefix.addr[0]);
        in6.s6_addr32[1] = htonl(nip6->prefix.addr[1]);
        in6.s6_addr32[2] = htonl(nip6->prefix.addr[2]);
        in6.s6_addr32[3] = htonl(nip6->prefix.addr[3]);


        prfx->ip6_pfx.family = AF_INET6;
        prfx->ip6_pfx.prefix_len = n->pxlen;
        prfx->ip6_pfx.p = in6;

    } else {
        return NULL;
    }

    return prfx;
}

struct ubpf_nexthop *get_nexthop(context_t *ctx, union ubpf_prefix *fx) {

    struct ubpf_nexthop *nexthop_info;

    rte *rib_route = get_arg_from_type(ctx, RIB_ROUTE);
    if (!rib_route) return NULL;

    nexthop_info = ctx_malloc(ctx, sizeof (*nexthop_info));
    if (!nexthop_info) return NULL;

    nexthop_info->igp_metric = rib_route->attrs->igp_metric;
    nexthop_info->route_type = rib_route->attrs->source;

    return nexthop_info;
}

struct ubpf_rib_entry *get_rib_in_entry(context_t *ctx, uint8_t af_family, union ubpf_prefix *pfx) {

    net_addr conv_pfx;
    rtable *table_in = get_arg_from_type(ctx, RIB_IN_TABLE);

    switch(pfx->family) {
        case AF_INET:
            net_fill_ip4(&conv_pfx, ip4_from_u32(ntohl(pfx->ip4_pfx.p.s_addr)), pfx->ip4_pfx.prefix_len);
            break;
        case AF_INET6:
            //net_fill_ip6(&conv_pfx, ip)
            break;
        default:
            return NULL;
    }

    fprintf(stderr, "No implemented yet %s\n", __func__ );
    abort();
    return NULL;

    //net_route(table_in, )

}


struct bgp_route *get_bgp_route(enum BGP_ROUTE_TYPE type) {

    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();

    /*switch (type) {
        case BGP_ROUTE_TYPE_NEW:
            break;
        case BGP_ROUTE_TYPE_OLD:
            break;
        default:
            break;
    }*/

}