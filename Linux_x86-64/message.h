/*
 * Title:  message.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef MESSAGE_H_
#define MESSAGE_H_

#define NODE_BUFFER_SIZE 72000
#define SPIDER_MESSAGE_DATA_SIZE 65536
#define SPIDER_MESSAGE_DATA_MAX_SIZE 65552        // 65536 + 16 (AES padding)

#include "stdfunc.h"
#include "queue.h"
#include "thread.h"
#include "spiderip.h"
#include "rbtree.h"
#include "pipe.h"
#include "client.h"
#include "server.h"

#pragma pack(push, 1)
typedef struct spider_message_header
{
    char message_type;          // routing:r socks5:s
    uint8_t receive_flag;       // received:1
    uint8_t receive_result;     // ok:0  ng:1
    uint8_t encryption_flag;    // no:0 xor:1 aes:2
    char reserved1;
    char reserved2;
    char reserved3;
    char reserved4;
    uint32_t message_id;
    uint32_t connection_id;
    uint32_t client_id;
    uint32_t server_id;
    uint32_t pipe_id;
    char source_node_type;
    char reserved5;
    char source_ip[INET6_ADDR_STRING_LENGTH + 1];
    char reserved6;
    char destination_node_type;
    char reserved7;
    char destination_ip[INET6_ADDR_STRING_LENGTH + 1];
    char reserved8;
    int32_t tv_sec;
    int32_t tv_usec;
    int32_t forwarder_tv_sec;
    int32_t forwarder_tv_usec;
    int32_t data_size;
} spider_message_header;

typedef struct spider_message
{
    struct spider_message_header header;
    char data[SPIDER_MESSAGE_DATA_MAX_SIZE];
} spider_message;
#pragma pack(pop)

void push_routing_message(struct stack_head *stack);
void push_socks5_message(struct stack_head *stack);
struct spider_message *pop_routing_message();
struct spider_message *pop_socks5_message();

struct spider_message *transfer_socks5_message();
void message_worker(struct stack_head *stack);

#endif /* MESSAGE_H_ */

