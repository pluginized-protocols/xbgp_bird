//
// Created by thomas on 19/05/20.
//

#include "../../public_bpf.h"
#include "ubpf_api.h"
#include "common_rr.h"

uint64_t export_route_rr(bpf_full_args_t *args UNUSED) {

    int i;
    uint32_t *cluster_array;
    uint32_t *cluster_data;

    struct path_attribute *originator;
    struct path_attribute *cluster_list;

    struct ubpf_peer_info *pinfo = get_peer_info();
    struct ubpf_peer_info *src_info = get_src_peer_info();

    if (!pinfo || !src_info) {
        ebpf_print("Unable to get peer info\n");
        next();
    }

    if (pinfo->peer_type == EBGP_SESSION) {
        // eBGP -> nothing to do
        next();
    }

    if (pinfo->router_id == src_info->router_id) {
        // don't send back to the sender
        return PLUGIN_FILTER_REJECT;
    }

    originator = get_attr_from_code(ORIGINATOR_ID);
    cluster_list = get_attr_from_code(CLUSTER_LIST);

    if (!originator) {
        // must set the ORIGINATOR ID
        originator = ctx_malloc(sizeof(struct path_attribute));
        if (!originator) {
            // fail !!!
            return FAIL;
        }
        originator->code = ORIGINATOR_ID;
        originator->flags = 0xc0;
        originator->len = 4;
        originator->data = (uint8_t *) &pinfo->local_bgp_session->router_id;

    }

    if (!cluster_list) {

        cluster_list = ctx_malloc(sizeof(struct path_attribute));
        if (!cluster_list) return FAIL;

        cluster_list->code = CLUSTER_LIST;
        cluster_list->flags = 0xc0;
        cluster_list->len = 0;
        cluster_list->data = NULL; // len and data will be set afterwards
    }

    if (cluster_list->data) {
        /* append our router_id if it is not contained inside */
        cluster_array = (uint32_t *) cluster_list->data;
        for(i = 0; i < cluster_list->len / 4; i++) {
            if(cluster_array[i] == pinfo->router_id) {
                return PLUGIN_FILTER_REJECT;
            }
        }
    }

    /* check according to client-non client sessions */
    if (!is_rr_client(src_info->router_id)) {
        /* route coming from a non client, send to clients only */
        if (!is_rr_client(pinfo->router_id)){
            /* the neighbor is not rr client, don't send the route*/
            return PLUGIN_FILTER_REJECT;
        }
    }

    /* must append here */
    cluster_data = ctx_malloc(cluster_list->len + 4);
    if (!cluster_data) return FAIL;

    cluster_data[0] = pinfo->local_bgp_session->router_id;


    if (cluster_list->len != 0) {
        ebpf_memcpy(&cluster_data[1], cluster_list->data, cluster_list->len);
    }
    cluster_list->len += 4;
    cluster_list->data = (uint8_t *) cluster_data;

    set_attr(originator);
    set_attr(cluster_list);
    next();
    return PLUGIN_FILTER_ACCEPT;
}
