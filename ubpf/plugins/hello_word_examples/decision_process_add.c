#include "ubpf_api.h"
#include "bytecode_public.h"

#define get_community_from_array(arr, len, attr_id) ({ \
 int i__;                                              \
 struct path_attribute *attr = NULL;                   \
 for (i__ = 0; i__ < (len); i__++) {                   \
     if ((arr)[i__].code == (attr_id)) {               \
         attr = &((arr)[i__]);                         \
         break;                                        \
     }                                                 \
 }                                                     \
 attr;                                                 \
})

#define check_community(arr, len, community) ({              \
  int i__;                                                   \
  uint16_t val_ret__ = 0;                                    \
  uint32_t commu__;                                          \
  uint32_t *arru32 = (uint32_t *) (arr);                     \
  for (i__ = 0; i__ < (len); i__++) {                        \
      commu__ = ebpf_ntohl(arru32[i__]);                     \
      if ((commu__ >> 16u) == (community)) {                 \
          val_ret__ = commu__ & (0x0000FFFFU);               \
          break;                                             \
      }                                                      \
  }                                                          \
  val_ret__;                                                 \
})

uint64_t new_bgp_decision_process(args_t *args UNUSED) {
    struct bgp_route *rte_new;
    struct bgp_route *rte_old;

    struct path_attribute *new_attr;
    struct path_attribute *old_attr;

    uint32_t old_community;
    uint32_t new_community;

    /* retrieve routes from the BGP implementation */
    rte_new = get_bgp_route(BGP_ROUTE_TYPE_NEW);
    rte_old = get_bgp_route(BGP_ROUTE_TYPE_OLD);

    if (!rte_new || !rte_old) {
        return EXIT_FAILURE;
    }

    // get the community attribute
    new_attr = get_community_from_array(rte_new->attr, rte_new->attr_nb, COMMUNITY_ATTR_ID);
    old_attr = get_community_from_array(rte_old->attr, rte_old->attr_nb, COMMUNITY_ATTR_ID);

    if (!new_attr || !old_attr) {
        return EXIT_FAILURE;
    }

    // get the community value
    new_community = check_community(new_attr->data, new_attr->len, 125);
    old_community = check_community(old_attr->data, old_attr->len, 125);

    // actual decision
    if (new_community > old_community) return RTE_NEW;
    if (new_community < old_community) return RTE_OLD;

    return RTE_UNK;
}