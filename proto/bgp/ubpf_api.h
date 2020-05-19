//
// Created by thomas on 20/02/20.
//

#ifndef PLUGINIZED_BIRD_UBPF_API_H
#define PLUGINIZED_BIRD_UBPF_API_H

#include "ubpf_api_common.h"

/**
 * Add a new attribute to the route processed by the current plugin
 */
int add_attr(uint code, uint flags, uint16_t length, uint8_t *decoded_attr);

/**
 * Adds or modifies an attribute of the current route
 * @param attr
 * @return
 */
int set_attr(struct path_attribute *attr);

/**
 * Get the current attribute to be processed (if the plugin receives a single
 * attribute as argument)
 */
struct path_attribute *get_attr();

/**
 * Write the content of a buffer pointer by ptr to the protocol buffer
 * Usually used when the plugin wants to encode a BGP message to be sent
 * through the network. The buffer has to be encoded in network byte order
 */
int write_to_buffer(uint8_t *ptr, size_t len);

/**
 * Get the route attribute from its code if the plugin receives multiple routes
 * (Decision process for example)
 */
struct path_attribute *get_attr_by_code_from_rte(uint8_t code, int args_rte);

/**
 * Get the current peer router id (if the plugin is related to a specific peer)
 */
uint32_t get_peer_router_id();

/**
 * Get the attribute from its code (among a sequence of multiple attributes)
 */
struct path_attribute *get_attr_from_code(uint8_t code);

/**
 * Announce to the peer implementation that a prefix has been parsed.
 * This function could only be used when a BGP UPDATE is decoded.
 * @param pfx the prefix to announce to the host BGP implementation
 * @return 1 if the host has correctly received the prefix
 *         0 otherwise. The prefix has not been taken into account
 */
int announce_nrli(struct ubpf_prefix *pfx);

#endif //PLUGINIZED_BIRD_UBPF_API_H
