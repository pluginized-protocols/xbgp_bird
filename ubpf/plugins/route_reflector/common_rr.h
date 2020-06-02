//
// Created by thomas on 19/05/20.
//

#ifndef PLUGINIZED_BIRD_COMMON_RR_H
#define PLUGINIZED_BIRD_COMMON_RR_H

#define ORIGINATOR_ID 9
#define CLUSTER_LIST 10

enum {
    KEY_RR_CLIENT = 1,
};

static __always_inline int is_rr_client(uint32_t router_id) {
    uint32_t rr_client[] = {
            3232249859, 2829596676
    };

    unsigned int i;
    for (i = 0; i < sizeof(rr_client) / sizeof(rr_client[0]); i++) {
        if (router_id == rr_client[i]) return 1;
    }
    return 0;
}

#endif //PLUGINIZED_BIRD_COMMON_RR_H
