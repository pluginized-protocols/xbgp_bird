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
//#include "utlist.h"
//#include "uthash.h"
//#include <string.h>
//#include "sysdep/unix/krt.h"

#include <xbgp_compliant_api/xbgp_plugin_host_api.h>
#include <xbgp_compliant_api/xbgp_defs.h>


//struct iterator_node {
//    struct iterator_node *prev, *next; /* for free list */
//    UT_hash_handle hh; /* for alloc iterators */
//
//    int idx;
//    size_t len_data;
//    uint8_t data[0];
//};

/*
static inline int it_node_cmp(struct iterator_node *it1, struct iterator_node *it2) {
    return it1->idx - it2->idx;
}

static inline struct iterator_node *new_iterator_node(int idx, int len_data) {
    struct iterator_node *node;
    node = calloc(1, sizeof(*node) + len_data);
    if (!node) return NULL;

    node->idx = idx;
    node->len_data = len_data;
    return node;
}

static inline struct iterator_node *realloc_iterator_node_data(struct iterator_node *node, size_t len_data) {
    if (node->len_data == len_data) return node;
    return realloc(node, sizeof(*node) + len_data);
}

static inline void free_iterator_node(struct iterator_node *node) {
    free(node);
}

struct rib_iterators_mgr {
    struct iterator_node *alloc_it;
    struct iterator_node *free_list;

    int max_alloc_idx;

};

int init_rib_iterators(struct rib_iterators_mgr *rit) {
    struct iterator_node *free_node;

    rit->alloc_it = NULL;
    rit->free_list = NULL;
    rit->max_alloc_idx = -1;

    free_node = new_iterator_node(0, 0);
    if (!free_node) return -1;

    DL_APPEND(rit->free_list, free_node);
    return 0;
}

int alloc_iterator(struct rib_iterators_mgr *rit, void *data, size_t data_len) {
    struct iterator_node *free_node;
    struct iterator_node *new_free_node;

    /* take the first item of free list */
  /*  free_node = rit->free_list;
    assert(free_node != NULL);
    DL_DELETE(rit->free_list, free_node);

    if (data_len != free_node->len_data) {
        free_node = realloc_iterator_node_data(free_node, data_len);
        if (!free_node) return -1;
        free_node->len_data = data_len;
    }

    memcpy(free_node->data, data, data_len);
    HASH_ADD_INT(rit->alloc_it, idx, free_node);

    rit->max_alloc_idx = MAX(free_node->idx, rit->max_alloc_idx);
    if (free_node->idx == rit->max_alloc_idx) {
        /* we need to add a new free node*/
      /*  assert(rit->free_list == NULL);

        new_free_node = new_iterator_node(rit->max_alloc_idx + 1, 0);
        if (!new_free_node) return -1;
        DL_APPEND(rit->free_list, new_free_node);
    }

    return free_node->idx;
}

int del_iterator(struct rib_iterators_mgr *rit, int idx) {
    struct iterator_node *curr = NULL;

    HASH_FIND_INT(rit->alloc_it, &idx, curr);
    if (!curr) return 0;

    /* delete and replace it in the free list */
    /*HASH_DEL(rit->alloc_it, curr);
    DL_INSERT_INORDER(rit->free_list, curr, it_node_cmp);
    return 0;
}

void *get_iterator(struct rib_iterators_mgr *rit, int idx) {
    struct iterator_node *curr = NULL;

    HASH_FIND_INT(rit->alloc_it, &idx, curr);
    if (!curr) return NULL;

    return curr->data;
}

void destroy_iterators_mgr(struct rib_iterators_mgr *rit) {
    struct iterator_node *curr, *tmp;
    HASH_ITER(hh, rit->alloc_it, curr, tmp) {
        HASH_DEL(rit->alloc_it, curr);
        free_iterator_node(curr);
    }

    curr = tmp = NULL;
    DL_FOREACH_SAFE(rit->free_list, curr, tmp) {
        DL_DELETE(rit->free_list, curr);
        free_iterator_node(curr);
    }
}*/

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

    attr_len = (is_u32 = (oiseau->type & EAF_EMBEDDED)) ? sizeof(uint32_t) :
               oiseau->u.ptr->length;

    attr_path = __ctx_malloc(ctx, sizeof(struct path_attribute) + attr_len);
    if (!attr_path) return NULL;

    attr_path->code = EA_ID(oiseau->id);
    attr_path->flags = oiseau->flags;
    attr_path->length = attr_len;

    if (!is_u32) {
        memcpy(attr_path->data, oiseau->u.ptr->data, attr_len);
    } else {
        *(uint32_t *)attr_path->data = oiseau->u.data;
    }
    return attr_path;

}

int add_attr(context_t *ctx, uint8_t code, uint8_t flags, uint16_t length, uint8_t *decoded_attr) {

    ea_list *to = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE_LIST);
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

    attr_list = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE_LIST);
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

        a = lp_alloc_adata(pool, attr->length);

        if (!a) return -1;

        memcpy(a->data, attr->data, attr->length);
        attr_stored->u.ptr = a;
    } else { // replace existing one
        attr_stored->flags = attr->flags;
        if (attr_stored->type & EAF_EMBEDDED) {
            attr_stored->u.data = *((uint32_t *) attr->data);
        } else {
            if (attr_stored->u.ptr->length < attr->length) {
                return -1;
            }
            memcpy(attr_stored->u.ptr->data, attr->data, attr->length);
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
        if (fargs->args[i].type == ARG_BGP_ATTRIBUTE) {
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

struct path_attribute *get_attr_from_code_by_route(context_t *ctx, uint8_t code, int arg_rte) {
    eattr *attr;
    rte *route;

    // TODO
    route = get_arg_from_type(ctx, arg_rte);

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

    peer_info = __ctx_malloc(ctx, sizeof(*peer_info));
    local_info = __ctx_malloc(ctx, sizeof(*local_bgp));
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

int set_peer_info(context_t *ctx, uint32_t router_id, int key, void *value, int len) {
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

    plugin_data = __ctx_malloc(ctx, data.length);
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
    size_t attr_len;
    ea_list *attr_list;
    eattr *attr;
    struct path_attribute *plugin_attr = NULL;
    uint8_t *data;

    attr_list = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE_LIST);
    if (!attr_list) return NULL;
    attr = ea_find(attr_list, EA_CODE(PROTOCOL_BGP, code));
    if (!attr) return NULL;

    if (attr->type & EAF_EMBEDDED) {;
        data = (uint8_t *) &attr->u.data;
        attr_len = 4;
    } else {
        data = (uint8_t *) attr->u.ptr->data;
        attr_len = attr->u.ptr->length;
    }

    plugin_attr = __ctx_malloc(ctx, sizeof(*plugin_attr) + attr_len);
    if (!plugin_attr) return NULL;

    plugin_attr->code = code;
    plugin_attr->flags = attr->flags;
    plugin_attr->length = attr_len;
    memcpy(plugin_attr->data, data, attr_len);
    return plugin_attr;
}


struct ubpf_prefix *get_prefix(context_t *ctx) {

net_addr *n = get_arg_from_type(ctx, ARG_BGP_PREFIX);
    net_addr_ip4 *nip4;
    net_addr_ip6 *nip6;

    struct ubpf_prefix *prfx;
    struct in6_addr in6;

    if (!n) return NULL;

    prfx = __ctx_malloc(ctx, sizeof(*prfx));
    if (!prfx) return NULL;

    if (n->type == NET_IP4) {
        nip4 = (net_addr_ip4 *) n;
        prfx->afi = XBGP_AFI_IPV4;
        prfx->prefixlen = n->pxlen;
        *(uint32_t *)prfx->u =  htonl(ip4_to_u32(nip4->prefix));
    } else if (n->type == NET_IP6) {

        prfx->afi = XBGP_AFI_IPV6;

        nip6 = (net_addr_ip6 *) n;
        memset(&in6, 0, sizeof(in6));

        in6.s6_addr32[0] = htonl(nip6->prefix.addr[0]);
        in6.s6_addr32[1] = htonl(nip6->prefix.addr[1]);
        in6.s6_addr32[2] = htonl(nip6->prefix.addr[2]);
        in6.s6_addr32[3] = htonl(nip6->prefix.addr[3]);

        prfx->prefixlen = n->pxlen;
        *(struct in6_addr *)prfx->u = in6;

    } else {
        return NULL;
    }

    return prfx;
}

struct ubpf_nexthop *get_nexthop(context_t *ctx, struct ubpf_prefix *fx) {

    struct ubpf_nexthop *nexthop_info;

    rte *rib_route = get_arg_from_type(ctx, ARG_BGP_ROUTE_RIB);
    if (!rib_route) return NULL;

    nexthop_info = __ctx_malloc(ctx, sizeof (*nexthop_info));
    if (!nexthop_info) return NULL;

    nexthop_info->igp_metric = rib_route->attrs->igp_metric;
    nexthop_info->route_type = rib_route->attrs->source;

    return nexthop_info;
}

struct ubpf_rib_entry *get_rib_in_entry(context_t *ctx, uint8_t af_family, struct ubpf_prefix *pfx) {

    net_addr conv_pfx;
    rtable *table_in = get_arg_from_type(ctx, RIB_IN_TABLE);

    switch(pfx->afi) {
        case XBGP_AFI_IPV4:
            net_fill_ip4(&conv_pfx, ip4_from_u32(ntohl(*(uint32_t *)pfx->u)), pfx->prefixlen);
            break;
        case XBGP_AFI_IPV6:
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


struct bgp_route *get_bgp_route(context_t *ctx UNUSED, enum BGP_ROUTE_TYPE type UNUSED) {

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

/* get the best bgp route exported to the kernel */
/* impossible to quickly find the best route by looking at the BGP RIB  */
/*
#define afi2af(afi) ({\
  int __af__ = -1;           \
  switch(afi) {          \
      case AFI_IPV4:     \
          __af__ = AF_INET;  \
          break;         \
      case AFI_IPV6:     \
          __af__ = AF_INET6; \
          break;         \
      default:       \
          break;         \
  }                      \
  __af__;                      \
})

static struct rtable *get_bgp_get_fib_afi(u32 afi) {
    node *n;
    struct krt_proto *p;
    struct channel *c;


    WALK_LIST(n, proto_list) {
        p = (struct krt_proto *) n;
        if (p->p.proto->class == PROTOCOL_KERNEL) {
            if (p->p.vrf == NULL) {
                WALK_LIST(c, p->p.channels) {
                    if (p->af == afi2af(afi)) {
                        return c->table;
                    }
                }
            }
        }
    }
    return NULL;
}

static struct bgp_proto *get_peer(char *ip) {
    
}
*/

int new_rib_iterator(context_t *ctx, int afi, int safi) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
    /*struct fib_iterator *fit;
    struct rtable *table;
    struct rib_iterators_mgr **rit;
    struct rib_iterators_mgr *nrit;

    static const char *fib_iterator = "fib_iterator";

    table = get_bgp_get_fib_afi(afi);
    if (!table) return -1;

    rit = get_runtime_data(ctx->p, fib_iterator);
    if (!rit) {
        nrit = malloc(sizeof(*nrit));
        if (!nrit) return -1;
        init_rib_iterators(nrit);

        if (new_runtime_data(ctx->p, fib_iterator,
                             sizeof(fib_iterator) - 1,
                             &nrit, sizeof(&nrit)) != 0) {
            return -1;
        }
    } else {
        nrit = *rit;
    }

    fit = malloc(sizeof(*fit));
    if (!fit) return -1;

    FIB_ITERATE_INIT(fit, &table->fib);

    FIB_ITERATE_START(&table->fib, fit, net, n) {

        n->routes->attrs->src->proto->proto->class == PROTOCOL_BGP;

    } FIB_ITERATE_END;*/

}

struct bgp_route *next_rib_route(context_t *ctx, unsigned int iterator_id) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

int rib_has_route(context_t *ctx, unsigned int iterator_id) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

void rib_iterator_clean(context_t *ctx, unsigned int iterator_id) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

int remove_route_from_rib(context_t *ctx, struct ubpf_prefix *pfx, struct ubpf_peer_info *peer_info) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

int get_vrf(context_t *ctx, struct vrf_info *vrf_info) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

int schedule_bgp_message(context_t *ctx, int type, struct bgp_message *message, const char *peer_ip) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}


int peer_session_reset(context_t *ctx, const char *peer_ip) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}