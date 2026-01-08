/*
 * Title:  pipe.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef PIPE_H_
#define PIPE_H_

#include "stdfunc.h"
#include "queue.h"
#include "message.h"
#include "dns.h"
#include "thread.h"
#include "spiderip.h"
#include "rbtree.h"
#include "route.h"

typedef struct pipe_data
{
    uint32_t pipe_id;
    int32_t pipe_sock;
    char pipe_mode[INET6_ADDR_STRING_LENGTH + 1];
    char pipe_ip[INET6_ADDR_STRING_LENGTH + 1];
    char pipe_ip_scope_id[INET6_ADDR_STRING_LENGTH + 1];
    char pipe_destination_ip[INET6_ADDR_STRING_LENGTH + 1];
    char pipe_destination_ip_scope_id[INET6_ADDR_STRING_LENGTH + 1];
    char pipe_destination_port[INET6_ADDR_STRING_LENGTH + 1];
    char pipe_listen_port[INET6_ADDR_STRING_LENGTH + 1];
    struct queue *routing_message_queue;
    struct queue *socks5_message_queue;
} pipe_data;

typedef struct push_message_queue_function_args_pipe
{
    struct pipe_data *pipe;
    struct spider_message *message;
} push_message_queue_function_args_pipe;

struct pipe_data *get_destination_pipe(const char *ip);

void push_routing_message_pipe(struct stack_head *stack);
void push_socks5_message_pipe(struct stack_head *stack);
struct spider_message *pop_routing_message_pipe_timeout(struct pipe_data *pipe, long tv_sec, long tv_usec);
struct spider_message *pop_socks5_message_pipe_timeout(struct pipe_data *pipe, long tv_sec, long tv_usec);

int recv_message(struct pipe_data *pipe);
int send_routing_message(struct pipe_data *pipe);
int send_socks5_message(struct pipe_data *pipe);
void pipe_recv_message(struct stack_head *stack);
void pipe_send_routing_message(struct stack_head *stack);
void pipe_send_socks5_message(struct stack_head *stack);
void pipe_worker(struct stack_head *stack_pipe_worker);

bool check_pipe(uint32_t pipe_id);
void connect_pipe(struct stack_head *stack);
void listen_pipe(struct stack_head *stack);

#endif /* PIPE_H_ */

