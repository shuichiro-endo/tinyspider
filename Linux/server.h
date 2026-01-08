/*
 * Title:  server.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef SERVER_H_
#define SERVER_H_

#define SOCKS5_AUTHENTICATION_METHOD 0x0; // 0x0:No Authentication Required  0x2:Username/Password Authentication
#define SOCKS5_USERNAME "socks5user"
#define SOCKS5_PASSWORD "supersecretpassword"

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

typedef struct map_node_server_receive_message
{
    uint32_t message_id;
    struct spider_message *message;
    struct map_node_server_receive_message *next;
} map_node_server_receive_message;

typedef struct map_server_receive_message
{
    struct map_node_server_receive_message *head;
} map_server_receive_message;

typedef struct server_data
{
    int32_t server_sock;
    uint32_t connection_id;
    uint32_t client_id;
    uint32_t server_id;
    char server_ip[INET6_ADDR_STRING_LENGTH + 1];
    char server_ip_scope_id[INET6_ADDR_STRING_LENGTH + 1];
    char server_port[INET6_ADDR_STRING_LENGTH + 1];
    char client_destination_ip[INET6_ADDR_STRING_LENGTH + 1];
    int32_t target_sock;
    char target_ip[INET6_ADDR_STRING_LENGTH + 1];
    char target_ip_scope_id[INET6_ADDR_STRING_LENGTH + 1];
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
    struct map_server_receive_message *m_server_receive_message;
    struct semaphore sem_m_server_receive_message;
} server_data;

typedef struct insert_map_node_server_receive_message_thread_function_args
{
    struct server_data *server;
    uint32_t message_id;
    struct spider_message *message;
} insert_map_node_server_receive_message_thread_function_args;

typedef struct push_message_queue_function_args_server
{
    struct server_data *server;
    struct spider_message *message;
} push_message_queue_function_args_server;

typedef struct server_worker_function_args
{
    struct server_data *server;
    struct spider_message *message;
} server_worker_function_args;

void create_map_server_receive_message(struct map_server_receive_message **map, struct semaphore *sem);
void insert_map_node_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem, uint32_t message_id, struct spider_message *message);
struct map_node_server_receive_message *search_map_node_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem, uint32_t message_id);
void delete_map_node_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem, uint32_t message_id);
void free_map_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem);

void insert_map_node_server_receive_message_thread(struct stack_head *stack);

void push_socks5_message_server(struct stack_head *stack);
struct spider_message *pop_socks5_message_server_timeout(struct server_data *server, long tv_sec, long tv_usec);



int32_t recv_message_server(struct server_data *server, char *buffer, int32_t buffer_size, long tv_sec, long tv_usec);
int32_t send_message_server(struct server_data *server, char *buffer, int32_t buffer_length, long tv_sec, long tv_usec);


int recv_receive_message_server(struct server_data *server, uint32_t message_id, long tv_sec, long tv_usec);
int send_receive_message_server(struct server_data *server, uint32_t message_id, uint8_t receive_flag, uint8_t receive_result, long tv_sec, long tv_usec);



void forwarder_recv_data_server(struct stack_head *stack);
void forwarder_send_data_server(struct stack_head *stack);
void forwarder_server(struct server_data *server);
int32_t send_socks_response_ipv4(struct server_data *server, char *buffer, int32_t buffer_size, char ver, char rep, char rsv, char atyp);
int32_t send_socks_response_ipv6(struct server_data *server, char *buffer, int32_t buffer_size, char ver, char rep, char rsv, char atyp);
void do_socks5_connection_server(struct server_data *server, struct spider_message *socks5_message);
void server_worker(struct stack_head *stack);

#endif /* SERVER_H_ */

