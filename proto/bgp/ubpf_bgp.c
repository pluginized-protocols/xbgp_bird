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

#include "nest/iface.h"


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




static eattr *eattr_prepend(struct linpool *pool, ea_list **e, int id UNUSED) {

    ea_list *new = lp_alloc(pool, sizeof(ea_list) + sizeof(eattr));

    if (!new) {
        fprintf(stderr, "Unable to allocate new attribute\n");
        return NULL;
    }

    eattr *e_new = &new->attrs[0];

    new->flags = EALF_SORTED;
    new->count = 1;
    new->next = *e;
    *e = new;

    return e_new;
}


static inline struct path_attribute *bird_to_vm_attr(context_t *ctx, eattr *oiseau) {

    struct path_attribute *attr_path;
    int is_u32 = 0;
    size_t attr_len;

    if (!oiseau) return NULL;

    attr_len = (is_u32 = (oiseau->type & EAF_EMBEDDED)) ? sizeof(uint32_t) :
               oiseau->u.ptr->length;

    attr_path = ctx_malloc(ctx, sizeof(struct path_attribute) + attr_len);
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

    ea_list **to = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE_LIST);
    struct bgp_parse_state *s = get_arg_from_type(ctx, PARSE_STATE);

    // this function copy the memory pointed by
    // decoded_attr to the protocol memory

    flags |= 1u; // distinguish pluginized attribute from unknown one
    // flags will be reinitialized when exporting, see attr.c:bgp_export_attr

    ea_set_attr_data(to, s->pool, EA_CODE(PROTOCOL_BGP, code), flags, EAF_TYPE_OPAQUE, decoded_attr, length);
    return 0;
}

int set_attr(context_t *ctx, struct path_attribute *attr) {
    struct linpool *pool;
    struct adata *a;

    ea_list **attr_list = NULL;
    eattr *attr_stored;

    if (!attr) return -1;

    attr_list = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE_LIST);
    if (!attr_list) return -1;

    attr_stored = ea_find(*attr_list, EA_CODE(PROTOCOL_BGP, attr->code));
    if (!attr_stored) { // add new attr
        pool = get_arg_from_type(ctx, HOST_LINPOOL);
        if (!pool) return -1;

        attr_stored = eattr_prepend(pool, attr_list, attr->code);
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
    size_t attr_len;
    ea_list **attr_list;
    eattr *attr;
    struct path_attribute *plugin_attr = NULL;
    uint8_t *data;

    attr_list = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE_LIST);
    if (!attr_list) return NULL;
    attr = ea_find(*attr_list, EA_CODE(PROTOCOL_BGP, code));
    if (!attr) return NULL;

    if (attr->type & EAF_EMBEDDED) {;
        data = (uint8_t *) &attr->u.data;
        attr_len = 4;
    } else {
        data = (uint8_t *) attr->u.ptr->data;
        attr_len = attr->u.ptr->length;
    }

    plugin_attr = ctx_malloc(ctx, sizeof(*plugin_attr) + attr_len);
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

    prfx = ctx_malloc(ctx, sizeof(*prfx));
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

    nexthop_info = ctx_malloc(ctx, sizeof (*nexthop_info));
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

static struct bgp_proto *get_bgp_inst_by_peer(struct ubpf_peer_info *pinfo) {
    node *n;
    struct bgp_proto *p;

    WALK_LIST(n, proto_list) {
        p = (struct bgp_proto *) n;
        if (p->p.proto->class == PROTOCOL_BGP) {
            if (p->remote_id == pinfo->router_id) {
                return p;
            }
        }
    }
    return NULL;
}

static struct rtable *get_bgp_table(struct bgp_proto *p, u32 afi) {
    struct bgp_channel *c;

    WALK_LIST(c, p->p.channels) {
        if (BGP_AFI(c->afi) == afi) {
            return c->c.table;
        }
    }
    return NULL;
}


#define afi2net(afi) ({     \
    int ret = -1;           \
    switch(afi) {           \
        case XBGP_AFI_IPV4: \
            ret = NET_IP4;  \
            break;          \
        case XBGP_AFI_IPV6: \
            ret = NET_IP6;  \
            break;          \
        default:            \
            ret = -1;       \
            break;          \
    }                       \
    ret;                    \
})

#define net2afi(net) ({          \
    int ret = -1;                \
    switch(net) {                \
        case NET_IP4:            \
            ret = XBGP_AFI_IPV4; \
            break;               \
        case NET_IP6:            \
            ret = XBGP_AFI_IPV6; \
            break;               \
        default:                 \
            ret = -1;            \
            break;               \
    }                            \
    ret;                         \
})

#define pfx2netlen(pfx) ({\
    int ret = -1;           \
    switch ((pfx)->afi) { \
        case XBGP_AFI_IPV4: \
            ret = sizeof(net_addr_ip4); \
            break;        \
        case XBGP_AFI_IPV6: \
            ret = sizeof(net_addr_ip6); \
            break;        \
        default:          \
            ret = -1;     \
            break;        \
    }                     \
    ret;                          \
})

int ubpf_pfx_to_net(struct ubpf_prefix *pfx, net_addr *addr) {
    *addr = (net_addr) {
            .type = afi2net(pfx->afi),
            .pxlen = pfx->prefixlen,
            .length = pfx2netlen(pfx),
    };

    switch (pfx->afi) {
        case XBGP_AFI_IPV4:
            ((net_addr_ip4*) &addr)->prefix = ntohl(*(uint32_t *)pfx->u);
            break;
        case XBGP_AFI_IPV6: {
            struct ip6_addr ip6;
            memcpy(&ip6, pfx->u, sizeof(struct ip6_addr));
            ((net_addr_ip6 *) &addr)->prefix = ip6_ntoh(ip6);
            break;
        }
        default:
            return -1;
            break;
    }
    return 0;
}

int net_to_ubpf_pfx(struct ubpf_prefix *pfx, net_addr *net) {

    pfx->afi = net2afi(net->type);
    pfx->prefixlen = net->pxlen;
    pfx->safi = XBGP_SAFI_UNICAST; // by default we only handle UNICAST routes

    switch (net->type) {
        case NET_IP4: {
            struct in_addr af4_addr;
            ip4_addr ip4 =  ip4_hton(((net_addr_ip4 *) net)->prefix);
            memcpy(&af4_addr.s_addr, &ip4, sizeof(ip4_addr));
            break;
        }
        case NET_IP6: {
            struct in6_addr af6_addr;
            ip6_addr ip6 = ip6_hton(((net_addr_ip6 *) net)->prefix);
            memcpy(&af6_addr, &ip6, sizeof(ip6_addr));
            break;
        }
        default:
            return -1;
    }
    return 0;
}

static struct bgp_proto *get_peer(ip_addr *ip) {
    node *n;
    struct bgp_proto *proto;

    WALK_LIST(n, proto_list) {
        proto = (struct bgp_proto *) n;
        if (proto->p.proto->class == PROTOCOL_BGP) {
            if (ipa_equal(*ip, proto->remote_ip)) {
                return proto;
            }
        }
    }
    return NULL;
}

int fill_peer_info(struct ubpf_peer_info *pinfo, rta *rta) {
    struct bgp_proto *proto;

    proto = get_peer(&rta->from);
    if (proto) {
        /* the route is originated from BGP */
        pinfo->router_id = proto->remote_id;
        pinfo->as = proto->remote_as;
        pinfo->peer_type = proto->is_interior ? IBGP_SESSION : EBGP_SESSION;
    }

    /* fill remote IP addr */
    if (ipa_is_ip4(rta->from)) {
        ip4_addr ip4;
        ip4 = ipa_to_ip4(rta->from);

        pinfo->addr.af = AF_INET;
        pinfo->addr.addr.in.s_addr = ip4_hton(ip4);

    } else {
        ip6_addr ip6, ip6_n;
        ip6 = ipa_to_ip6(rta->from);
        ip6_n = ip6_hton(ip6);

        pinfo->addr.af = AF_INET6;
        memcpy(&pinfo->addr.addr.in6, &ip6_n, sizeof(pinfo->addr.addr.in6));
    }

    pinfo->local_bgp_session = NULL;

    return 0;
}

struct bgp_route *bird_rte_to_ubpf_route(context_t *ctx, rte *rte) {
    struct bgp_route *bgp_route;
    int i, nb_attr;
    ea_list *ea;
    eattr *e;
    uint code;
    struct path_attribute *p_attr;

    bgp_route = ctx_malloc(ctx, sizeof(*bgp_route));
    if (!bgp_route) return NULL;

    if (net_to_ubpf_pfx(&bgp_route->pfx, rte->net->n.addr) != 0) {
        return NULL;
    }

    bgp_route->type = rte->attrs->source; // todo change with xBGP compatible representation
    bgp_route->peer_info = ctx_malloc(ctx, sizeof(struct ubpf_peer_info));
    if (!bgp_route->peer_info){
        return NULL;
    }

    fill_peer_info(bgp_route->peer_info, rte->attrs);

    bgp_route->uptime = rte->lastmod; // clock is monotonic

    bgp_route->attr_nb = rte->attrs->eattrs->count;
    nb_attr = bgp_route->attr_nb;

    bgp_route->attr = ctx_malloc(ctx, sizeof(struct path_attribute *) * nb_attr);
    if (!bgp_route->attr) { return NULL; }

    for (i = 0; i < nb_attr; i++) {
        e = &rte->attrs->eattrs->attrs[i];

        if (EA_PROTO(e->id) == PROTOCOL_BGP) {
            code = EA_ID(e->id);

            p_attr = bird_to_vm_attr(ctx, e);
            if (!p_attr) {
                // un recognized ?
            } else {
                bgp_route->attr[0] = p_attr;
            }
        }
    }

    return bgp_route;
}


struct bgp_route *get_rib_out_entry(context_t *ctx, uint8_t af_family,
                                    struct ubpf_prefix *pfx, struct ubpf_peer_info *pinfo) {
    struct bgp_proto *p;
    struct rtable *routing_table;
    net_addr addr;
    net *net;
    rte *rte;

    p = get_bgp_inst_by_peer(pinfo);

    if (!p) { return NULL; }
    routing_table = get_bgp_table(p, af_family);
    if (!routing_table) { return NULL; }

    if (ubpf_pfx_to_net(pfx, &addr) != 0) return NULL;

    net = net_find(routing_table, &addr);
    if (!net) { return NULL; }

    /* the docs said the first route is the best one.
     * i.e. the route used to route packets */
    rte = net->routes;
    return bird_rte_to_ubpf_route(ctx, rte);
}

struct rtable *get_bgp_fib(int afi, int safi) {
    node *n;
    struct bgp_proto *bgp_proto;
    int i;

    int bird_af = BGP_AF(afi, safi);

    /* Warning:
     * This gets the first AFI/SAFI compatible table.
     * The fetched table may not be
     * sync with the kernel FIB.
     */
    WALK_LIST(n, proto_list) {
        bgp_proto = (struct bgp_proto *) n;
        if (bgp_proto->p.proto->class == PROTOCOL_BGP) {
            /* find table by afi */
            for (i = 0; i < bgp_proto->channel_count; i++) {
                if (bgp_proto->afi_map[i] == bird_af) {
                    return bgp_proto->channel_map[i]->c.table;
                }
            }
        }
    }
    return NULL;
}

struct bird_iterator {
    struct fib_iterator fit;
    net *next;
    struct rtable *rtable;
};

int new_rib_iterator(context_t *ctx, int afi, int safi) {
    static unsigned int uid = 0;

    struct bird_iterator *biter;
    struct bird_iterator biter_;
    struct rtable *table;

     unsigned int key = ++uid;

    table = get_bgp_fib(afi, safi);
    if (!table) return -1;

    biter = get_runtime_data_int_key(ctx->p, key);
    if (!biter) {
        biter = &biter_;
        memset(biter, 0, sizeof(*biter));

        FIB_ITERATE_INIT(&biter->fit, &table->fib);
        biter->rtable = table;
        biter->next = NULL;

        if ((biter = new_runtime_data_int_key(ctx->p, key,
                             biter, sizeof(*biter))) == NULL) {
            return -1;
        }
    } else {
        return -1;
    }

    /* loop once to get the next route to retrieve */
    FIB_ITERATE_START(&biter->rtable->fib, &biter->fit, net, n) {
        biter->next = n;
        FIB_ITERATE_PUT(&biter->fit);
        break;
    } FIB_ITERATE_END;


    return key;
}

struct bgp_route *next_rib_route(context_t *ctx, unsigned int iterator_id) {
    struct bird_iterator *biter;
    biter = get_runtime_data_int_key(ctx->p, iterator_id);
    if (!biter) return NULL;
    struct rte *rte;
    struct bgp_route *bgp_route;

    if (!biter->next) return NULL;

    rte = biter->next->routes;
    bgp_route = bird_rte_to_ubpf_route(ctx, rte);

    biter->next = NULL; /* reset biter->next if the loop is not taken */
    FIB_ITERATE_START(&biter->rtable->fib, &biter->fit, net, n) {
        biter->next = n;
        FIB_ITERATE_PUT(&biter->fit);
        break;
    } FIB_ITERATE_END;

    return bgp_route;
}

int rib_has_route(context_t *ctx, unsigned int iterator_id) {
    struct bird_iterator *biter;
    biter = get_runtime_data_int_key(ctx->p, iterator_id);
    if (!biter) return -1;

    return biter->next != NULL ? 0 : -1;
}

void rib_iterator_clean(context_t *ctx, unsigned int iterator_id) {
    struct bird_iterator *biter;
    biter = get_runtime_data_int_key(ctx->p, iterator_id);
    if (!biter) return;

    FIB_ITERATE_UNLINK(&biter->fit, &biter->rtable->fib);
    del_runtime_data_int_key(ctx->p, iterator_id);
}

int remove_route_from_rib(context_t *ctx, struct ubpf_prefix *pfx, struct ubpf_peer_info *peer_info) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

int get_vrf(context_t *ctx, struct vrf_info *vrf_info) {
    int vrf_len;
    struct iface *iface;
    iface = get_arg_from_type(ctx, ARG_BGP_VRF);

    if(!iface) return -1;

    vrf_len = strnlen(iface->name, 16);

    if (vrf_info->str_len < vrf_len) {
        return -1;
    }
    strncpy(iface->name, vrf_info->name, vrf_len);

    //iface->name;

    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

int schedule_bgp_message(context_t *ctx, int type, struct bgp_message *message, const char *peer_ip) {
    ip4_addr ip4;
    ip6_addr ip6;
    ip_addr ip;
    node *n;
    struct bgp_proto *bgp_proto;
    struct bgp_proto *found;
    struct pending_msgs *msg;

    if (ip4_pton(peer_ip, &ip4) == 1) {
        ip = ipa_from_ip4(ip4);
    } else if (ip6_pton(peer_ip, &ip6) == 1) {
        ip = ipa_from_ip6(ip6);
    } else {
        return -1;
    }

    found = NULL;
    WALK_LIST(n, proto_list) {
        bgp_proto = (struct bgp_proto *) n;
        if (bgp_proto->p.proto->class == PROTOCOL_BGP) {
            if (ipa_equal(ip, bgp_proto->remote_ip)) {
                found = bgp_proto;
                break;
            }
        }
    }
    if (!found) { return -1; }

    msg = malloc(sizeof(*msg) + message->buf_len);
    if (!msg) return -1;
    memset(msg, 0, sizeof (*msg));

    add_tail(&found->xbgp_pending_msgs, &msg->n);

    msg->buf_len = message->buf_len;
    msg->type = message->type;
    memcpy(msg->buf, message->buf, message->buf_len);

    bgp_schedule_packet(found->conn, NULL, PKT_CUSTOM_XBGP);
    return 0;
}


int peer_session_reset(context_t *ctx, const char *peer_ip) {
    fprintf(stderr, "Not implemented yet %s\n", __func__ );
    abort();
}

/* check return value functions */

inline int ret_val_filter(uint64_t a) {
    switch (a) {
        case PLUGIN_FILTER_REJECT:
        case PLUGIN_FILTER_ACCEPT:
            return 1;
        case PLUGIN_FILTER_UNKNOWN:
        default:
            return 0;
    }
}

inline int ret_val_check_decode(uint64_t a) {
    return a == EXIT_FAILURE ? 0 : 1;
}

inline int ret_val_check_encode_attr(uint64_t val) {
    if (val > 4096) return 0; // RFC 4271 says 4KB max TODO CHECK
    if (val == 0) return 1;

    return 1;
}

int UNUSED ret_val_decision_process(uint64_t val) {
    switch (val) {
        case BGP_ROUTE_TYPE_NEW:
        case BGP_ROUTE_TYPE_OLD:
            return 1;
        case BGP_ROUTE_TYPE_UNKNOWN:
        default:
            return 0;
    }
}

int ret_val_decode_bgp_message(uint64_t val) {
    return val == EXIT_SUCCESS ? 1 : 0;
}