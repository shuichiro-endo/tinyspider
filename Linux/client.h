/*
 * Title:  client.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef CLIENT_H_
#define CLIENT_H_

#include "stdfunc.h"
#include "socks5.h"
#include "xor.h"
#include "aes.h"
#include "queue.h"
#include "dns.h"
#include "thread.h"
#include "spiderip.h"
#include "rbtree.h"
#include "message.h"
#include "route.h"

typedef struct map_node_client_receive_message
{
    uint32_t message_id;
    struct spider_message *message;
    struct map_node_client_receive_message *next;
} map_node_client_receive_message;

typedef struct map_client_receive_message
{
    struct map_node_client_receive_message *head;
} map_client_receive_message;

typedef struct client_data
{
    int32_t client_sock;
    uint32_t connection_id;
    uint32_t client_id;
    uint32_t server_id;
    char client_type[INET6_ADDR_STRING_LENGTH + 1];
    char client_ip[INET6_ADDR_STRING_LENGTH + 1];
    char client_ip_scope_id[INET6_ADDR_STRING_LENGTH + 1];
    char client_listen_port[INET6_ADDR_STRING_LENGTH + 1];
    char client_port[INET6_ADDR_STRING_LENGTH + 1];
    char destination_spider_ip[INET6_ADDR_STRING_LENGTH + 1];
    char target_ip[INET6_ADDR_STRING_LENGTH + 1];
    char target_port[INET6_ADDR_STRING_LENGTH + 1];
    int32_t tv_sec;
    int32_t tv_usec;
    int32_t forwarder_tv_sec;
    int32_t forwarder_tv_usec;
    int encryption_flag;    // no:0 xor:1 aes:2
    uint32_t recv_message_id;
    uint32_t next_recv_message_id;
    uint32_t send_message_id;
    struct queue *socks5_message_queue;
    struct map_client_receive_message *m_client_receive_message;
    struct semaphore sem_m_client_receive_message;
} client_data;

typedef struct insert_map_node_client_receive_message_thread_function_args
{
    struct client_data *client;
    uint32_t message_id;
    struct spider_message *message;
} insert_map_node_client_receive_message_thread_function_args;

typedef struct push_message_queue_function_args_client
{
    struct client_data *client;
    struct spider_message *message;
} push_message_queue_function_args_client;

void create_map_client_receive_message(struct map_client_receive_message **map, struct semaphore *sem);
void insert_map_node_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem, uint32_t message_id, struct spider_message *message);
struct map_node_client_receive_message *search_map_node_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem, uint32_t message_id);
void delete_map_node_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem, uint32_t message_id);
void free_map_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem);

void insert_map_node_client_receive_message_thread(struct stack_head *stack);

void push_socks5_message_client(struct stack_head *stack);
struct spider_message *pop_socks5_message_client_timeout(struct client_data *client, long tv_sec, long tv_usec);

int32_t recv_message_client(struct client_data *client, char *buffer, int32_t buffer_size, long tv_sec, long tv_usec, bool register_server_id_flag);
int32_t send_message_client(struct client_data *client, char *buffer, int32_t buffer_length, long tv_sec, long tv_usec);
int recv_receive_message_client(struct client_data *client, uint32_t message_id, long tv_sec, long tv_usec);
int send_receive_message_client(struct client_data *client, uint32_t message_id, uint8_t receive_flag, uint8_t receive_result, long tv_sec, long tv_usec);
void forwarder_recv_data_client(struct stack_head *stack);
void forwarder_send_data_client(struct stack_head *stack);
void forwarder_client(struct client_data * client);
void do_socks5_connection_client(struct client_data *client);
void client_worker(struct stack_head *stack_client_worker);
void listen_client(struct stack_head *stack);

#endif /* CLIENT_H_ */
