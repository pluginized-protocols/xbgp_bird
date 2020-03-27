//
// Created by thomas on 20/02/20.
//

#ifndef PLUGINIZED_BIRD_UBPF_API_H
#define PLUGINIZED_BIRD_UBPF_API_H

#include "ubpf_api_common.h"

int add_attr(uint code, uint flags, uint16_t length, uint8_t *decoded_attr);

struct path_attribute *get_attr();

int write_to_buffer(uint8_t *ptr, size_t len);

struct path_attribute *get_attr_by_code_from_rte(uint8_t code, int args_rte);

#endif //PLUGINIZED_BIRD_UBPF_API_H
