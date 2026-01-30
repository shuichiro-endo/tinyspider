/*
 * Title:  route.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef ROUTE_H_
#define ROUTE_H_

#include "stdfunc.h"
#include "spiderip.h"
#include "thread.h"
#include "message.h"
#include "rbtree.h"
#include "pipe.h"

#define DELETE_ROUTE_TIME       60

#pragma pack(push, 1)
typedef struct route_data
{
    char mode;  // auto:a self:s
    uint8_t metric;
    uint32_t pipe_id;
    byte alive; // dead:0 alive:1
    struct timeval time;
} route_data;
#pragma pack(pop)

typedef struct avlt_node_route
{
    char *ip;
    struct route_data *data;
    struct avlt_node_route *left;
    struct avlt_node_route *right;
    int height;
} avlt_node_route;

static struct avlt_node_route *create_avlt_node_route(const char *ip_address, struct route_data *data);
static int get_height_avlt_node_route(struct avlt_node_route *node);
static int get_balance_avlt_node_route(struct avlt_node_route *node);
static struct avlt_node_route *left_rotate_avlt_node_route(struct avlt_node_route *x);
static struct avlt_node_route *right_rotate_avlt_node_route(struct avlt_node_route *y);
static struct avlt_node_route *insert_avlt_node_route(struct avlt_node_route *node, const char *ip_address, struct route_data *data);
static struct avlt_node_route *search_avlt_node_route(struct avlt_node_route *root, const char *ip_address);
static struct avlt_node_route *delete_avlt_node_route(struct avlt_node_route *root, const char *ip_address);
static void register_dead_route_2(struct avlt_node_route *root, uint32_t pipe_id);
static void inorder_avlt_node_route(struct avlt_node_route *root);
static void free_avlt_node_route(struct avlt_node_route *root);
static void free_avlt_tree_node_route(struct avlt_node_route *root);

void insert_route(struct avlt_node_route **node, const char *ip_address, struct route_data *data);
struct avlt_node_route *search_route(struct avlt_node_route *root, const char *ip_address);
void delete_route(struct avlt_node_route **root, const char *ip_address);
void register_dead_route(struct avlt_node_route *root, uint32_t pipe_id);
void free_routing_table(struct avlt_node_route *root);

int init_routing_table();
void print_routing_table();

static void send_routing_table_inorder_avlt_node_route(struct avlt_node_route *root, char *buffer, int *buffer_length, int buffer_size);
void send_routing_table();

int update_route(char *ip_address, struct route_data *r_data_new);
void update_routing_table(struct function_args *args);

static void delete_routing_table_inorder_avlt_node_route(struct avlt_node_route *root, char *ip_address);
void delete_routing_table(struct function_args *args);

#endif /* ROUTE_H_ */

