/*
 * Title:  rbtree.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef RBTREE_H_
#define RBTREE_H_

#include "stdfunc.h"
#include "pipe.h"
#include "client.h"
#include "server.h"

typedef enum { RED, BLACK } rbt_node_color;

typedef struct rbt_node_spider
{
    uint32_t id;
    void *data;
    rbt_node_color color;
    struct rbt_node_spider *parent;
    struct rbt_node_spider *left;
    struct rbt_node_spider *right;
} rbt_node_spider;

typedef struct rbt_spider
{
    struct rbt_node_spider *root;
    struct rbt_node_spider *nil;
} rbt_spider;

static void init_rbt_spider(struct rbt_spider **tree);
static void left_rotate_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *x);
static void right_rotate_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *y);
static void insert_fixup_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *node);
static void insert_rbt_node_spider(struct rbt_spider *tree, uint32_t id, void *data);
static void transplant_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *u, struct rbt_node_spider *v);
static void delete_fixup_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *x);
static void delete_rbt_node_spider(struct rbt_spider *tree, uint32_t id);
static rbt_node_spider *search_rbt_node_spider(struct rbt_spider *tree, uint32_t id);
static void inorder_rbt_node_pipe(struct rbt_node_spider *node, struct rbt_node_spider *nil);
static void inorder_rbt_node_client(struct rbt_node_spider *node, struct rbt_node_spider *nil);
static void inorder_rbt_node_server(struct rbt_node_spider *node, struct rbt_node_spider *nil);
static void inorder_tree_rbt_node_pipe(struct rbt_spider *tree);
static void inorder_tree_rbt_node_client(struct rbt_spider *tree);
static void inorder_tree_rbt_node_server(struct rbt_spider *tree);
static void free_rbt_node_spider(struct rbt_node_spider *node, struct rbt_node_spider *nil);

int init_tree_spider_node();
int insert_spider_node(struct rbt_spider *tree, HANDLE handle, uint32_t id, void *data);
struct rbt_node_spider *search_spider_node(struct rbt_spider *tree, HANDLE handle, uint32_t id);
void delete_spider_node(struct rbt_spider *tree, HANDLE handle, uint32_t id);

static void send_routing_table_inorder_rbt_node_pipe(struct rbt_node_spider *node, struct rbt_node_spider *nil, char *buffer, int32_t buffer_length);
void send_routing_table_inorder_tree_rbt_node_pipe(struct rbt_spider *tree, HANDLE handle, char *buffer, int32_t buffer_length);
void print_spider_node_pipe(struct rbt_spider *tree, HANDLE handle);

void print_spider_node_client(struct rbt_spider *tree, HANDLE handle);
void print_spider_node_server(struct rbt_spider *tree, HANDLE handle);
void free_rbt_tree_spider(struct rbt_spider *tree, HANDLE handle);

#endif /* RBTREE_H_ */

