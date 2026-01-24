/*
 * Title:  server.c
 * Author: Shuichiro Endo
 */

#include "server.h"

extern spider_ip *ip;
extern map_thread *m_thread;
extern int encryption_flag;
extern avlt_node_route *routing_table;
extern rbt_spider *tree_server;
extern semaphore sem_tree_server;
extern xor_key *x_key;
extern aes_key *a_key;

void create_map_server_receive_message(struct map_server_receive_message **map, struct semaphore *sem)
{
    semaphore_init(sem, 1);

    semaphore_wait(sem);

    *map = (struct map_server_receive_message *)calloc(1, sizeof(struct map_server_receive_message));
    (*map)->head = NULL;

    semaphore_post(sem);
}

void insert_map_node_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem, uint32_t message_id, struct spider_message *message)
{
    map_node_server_receive_message *node = NULL;

    semaphore_wait(sem);

    node = (struct map_node_server_receive_message *)calloc(1, sizeof(struct map_node_server_receive_message));
    node->message_id = message_id;
    node->message = message;
    node->next = map->head;
    map->head = node;

    semaphore_post(sem);
}

struct map_node_server_receive_message *search_map_node_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem, uint32_t message_id)
{
    struct map_node_server_receive_message *current = NULL;

    semaphore_wait(sem);

    current = map->head;

    while(current != NULL)
    {
        if(current->message_id == message_id)
        {
            semaphore_post(sem);

            return current;
        }
        current = current->next;
    }

    semaphore_post(sem);

    return NULL;
}

void delete_map_node_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem, uint32_t message_id)
{
    struct map_node_server_receive_message *current = NULL;
    struct map_node_server_receive_message *previous = NULL;

    semaphore_wait(sem);

    current = map->head;

    while(current != NULL && current->message_id != message_id)
    {
        previous = current;
        current = current->next;
    }

    if(previous == NULL)
    {
        map->head = current->next;
    }else
    {
        previous->next = current->next;
    }

    if(current->message != NULL)
    {
        free(current->message);
    }

    if(current != NULL)
    {
        free(current);
    }

    semaphore_post(sem);
}

void free_map_server_receive_message(struct map_server_receive_message *map, struct semaphore *sem)
{
    struct map_node_server_receive_message *current = NULL;
    struct map_node_server_receive_message *next = NULL;

    semaphore_wait(sem);

    current = map->head;

    while(current != NULL)
    {
        next = current->next;

        if(current->message != NULL)
        {
            free(current->message);
        }

        free(current);

        current = next;
    }

    free(map);

    semaphore_post(sem);
}

void insert_map_node_server_receive_message_thread(struct stack_head *stack)
{
    struct insert_map_node_server_receive_message_thread_function_args *args = stack->args;
    struct server_data *server = args->server;
    uint32_t message_id = args->message_id;
    struct spider_message *message = args->message;
    struct map_node_thread *thread = NULL;

    free(args);

    insert_map_node_server_receive_message(server->m_server_receive_message, &server->sem_m_server_receive_message, message_id, message);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] insert_map_node_server_receive_message_thread is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] insert_map_node_server_receive_message_thread cannot free stack\n");
#endif
    }

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

void push_socks5_message_server(struct stack_head *stack)
{
    struct push_message_queue_function_args_server *args = stack->args;
    struct server_data *server = args->server;
    struct spider_message *message = args->message;
    struct map_node_thread *thread = NULL;

    free(args);

    if(server->socks5_message_queue != NULL)
    {
        enqueue(server->socks5_message_queue, (void *)message);
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message_server socks5_message_queue is null\n");
#endif

        free(message);
    }

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_socks5_message_server is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message_server cannot free stack\n");
#endif
    }

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

struct spider_message *pop_socks5_message_server_timeout(struct server_data *server, long tv_sec, long tv_usec)
{
    struct timeval start;
    struct timeval end;
    long t = 0;
    struct spider_message *socks5_message = NULL;

    if(gettimeofday(&start, NULL) == -1)
    {
#ifdef _DEBUG
        printf("[-] pop_socks5_message_server_timeout gettimeofday error\n");
#endif
        return NULL;
    }

    do
    {
        if(gettimeofday(&end, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] pop_socks5_message_server_timeout gettimeofday error\n");
#endif
            return NULL;
        }

        t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
        if(t >= (tv_sec * 1000000 + tv_usec))
        {
#ifdef _DEBUG
            printf("[+] pop_socks5_message_server_timeout timeout\n");
#endif

            return NULL;
        }

        millisleep(100);
    }while(server->socks5_message_queue->count <= 0);

    socks5_message = (struct spider_message *)dequeue(server->socks5_message_queue);

    return socks5_message;
}

int32_t recv_message_server(struct server_data *server, char *buffer, int32_t buffer_size, long tv_sec, long tv_usec)
{
    int32_t ret = 0;
    int32_t rec = 0;
    struct spider_message *socks5_message = NULL;

    memset(buffer, 0, buffer_size);

    socks5_message = pop_socks5_message_server_timeout(server, tv_sec, tv_usec);
    if(socks5_message !=  NULL)
    {
        if(socks5_message->header.message_type == 's')     // socks5 message
        {
            rec = socks5_message->header.data_size;
            if(rec >= 0)
            {
                server->recv_message_id = socks5_message->header.message_id;

                memcpy(buffer, socks5_message->data, rec);

#ifdef _DEBUG
//                printf("[+] recv_message_server server_id: %u rec: %d\n", server->server_id, rec);
//                print_bytes(buffer, rec);
#endif

                if(server->encryption_flag == 1)    // xor
                {
                    ret = xor_decrypt(x_key, buffer, rec, buffer_size);
                    if(ret <= 0)
                    {
#ifdef _DEBUG
                        printf("[-] recv_message_server xor_decrypt error: %d\n", ret);
#endif

                        goto error;
                    }

                    rec = ret;
                }else if(server->encryption_flag == 2)  // aes
                {
                    ret = aes_decrypt(a_key, buffer, rec, buffer_size);
                    if(ret <= 0)
                    {
#ifdef _DEBUG
                        printf("[-] recv_message_client aes_decrypt error: %d\n", ret);
#endif

                        goto error;
                    }

                    rec = ret;
                }
            }else
            {
#ifdef _DEBUG
                printf("[-] recv_message_server recv error: %d\n", rec);
#endif

                goto error;
            }
        }else
        {
#ifdef _DEBUG
            printf("[-] recv_message_server unknown message type: %c\n", socks5_message->header.message_type);
#endif

            goto error;
        }
    }else
    {
#ifdef _DEBUG
        printf("[-] recv_message_server error\n");
#endif

        goto error;
    }

    if(socks5_message != NULL)
    {
        free(socks5_message);
    }

    return rec;

error:
    if(socks5_message != NULL)
    {
        free(socks5_message);
    }

    return -1;
}

int32_t send_message_server(struct server_data *server, char *buffer, int32_t buffer_length, long tv_sec, long tv_usec)
{
    int32_t ret = 0;
    int32_t sen = 0;
    struct spider_message *socks5_message = NULL;

    if(server->encryption_flag == 1)    // xor
    {
        ret = xor_encrypt(x_key,
                          buffer,
                          buffer_length,
                          SPIDER_MESSAGE_DATA_MAX_SIZE);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] send_message_server xor_encrypt error: %d\n", ret);
#endif

            return -1;
        }

        buffer_length = ret;
    }else if(server->encryption_flag == 2)  // aes
    {
        ret = aes_encrypt(a_key,
                          buffer,
                          buffer_length,
                          SPIDER_MESSAGE_DATA_MAX_SIZE);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] send_message_server aes_encrypt error: %d\n", ret);
#endif

            return -1;
        }

        buffer_length = ret;
    }

#ifdef _DEBUG
//    printf("[+] send_message_server server_id: %u buffer_length: %d\n", server->server_id, buffer_length);
//    print_bytes(buffer, buffer_length);
#endif

    socks5_message = (struct spider_message *)calloc(1, sizeof(struct spider_message));

    socks5_message->header.message_type = 's';
    socks5_message->header.message_id = htonl(server->send_message_id);
    socks5_message->header.connection_id = htonl(server->connection_id);
    socks5_message->header.client_id = htonl(server->client_id);
    socks5_message->header.server_id = htonl(server->server_id);
    socks5_message->header.pipe_id = htonl(0);
    socks5_message->header.source_node_type = 's';
    strcpy((char *)&socks5_message->header.source_ip, (char *)&server->server_ip);
    socks5_message->header.destination_node_type = 'c';
    strcpy((char *)&socks5_message->header.destination_ip, (char *)&server->client_destination_ip);
    socks5_message->header.tv_sec = htonl(server->tv_sec);
    socks5_message->header.tv_usec = htonl(server->tv_usec);
    socks5_message->header.forwarder_tv_sec = htonl(server->forwarder_tv_sec);
    socks5_message->header.forwarder_tv_usec = htonl(server->forwarder_tv_usec);
    socks5_message->header.data_size = htonl(buffer_length);
    memcpy((char *)&socks5_message->data, buffer, buffer_length);

    start_thread(m_thread, (void *)push_socks5_message, (void *)socks5_message);

    return buffer_length;
}

int recv_receive_message_server(struct server_data *server, uint32_t message_id, long tv_sec, long tv_usec)
{
    struct map_node_server_receive_message *node = NULL;
    struct spider_message *socks5_message = NULL;
    struct timeval start;
    struct timeval end;
    long t = 0;

    if(gettimeofday(&start, NULL) == -1)
    {
#ifdef _DEBUG
        printf("[-] recv_receive_message_server gettimeofday error\n");
#endif

        goto error;
    }

    while(1)
    {
        node = search_map_node_server_receive_message(server->m_server_receive_message, &server->sem_m_server_receive_message, message_id);
        if(node != NULL)
        {
            socks5_message = (struct spider_message *)node->message;
            if(socks5_message != NULL)
            {
                if(socks5_message->header.receive_flag == 1 && socks5_message->header.receive_result == 0)  // ok
                {
                    delete_map_node_server_receive_message(server->m_server_receive_message, &server->sem_m_server_receive_message, message_id);

                    goto exit_0;
                }else if(socks5_message->header.receive_flag == 1 && socks5_message->header.receive_result == 1)    // ng
                {
                    delete_map_node_server_receive_message(server->m_server_receive_message, &server->sem_m_server_receive_message, message_id);

                    goto exit_1;
                }else
                {
                    delete_map_node_server_receive_message(server->m_server_receive_message, &server->sem_m_server_receive_message, message_id);

                    goto error;
                }
            }else
            {
                delete_map_node_server_receive_message(server->m_server_receive_message, &server->sem_m_server_receive_message, message_id);

                goto error;
            }
        }else
        {
            if(gettimeofday(&end, NULL) == -1)
            {
#ifdef _DEBUG
                printf("[-] recv_receive_message_server gettimeofday error\n");
#endif

                goto error;
            }

            t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
            if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
                printf("[+] recv_receive_message_server recv_receive_message timeout\n");
#endif

                goto error;
            }

            millisleep(5);
        }
    }

exit_0:
    return 0;

exit_1:
    return 1;

error:
    return -1;
}

int send_receive_message_server(struct server_data *server, uint32_t message_id, uint8_t receive_flag, uint8_t receive_result, long tv_sec, long tv_usec)
{
    struct spider_message *socks5_message = (struct spider_message *)calloc(1, sizeof(struct spider_message));

    socks5_message->header.message_type = 's';
    socks5_message->header.receive_flag = receive_flag;;
    socks5_message->header.receive_result = receive_result;
    socks5_message->header.message_id = htonl(message_id);
    socks5_message->header.connection_id = htonl(server->connection_id);
    socks5_message->header.client_id = htonl(server->client_id);
    socks5_message->header.server_id = htonl(server->server_id);
    socks5_message->header.pipe_id = htonl(0);
    socks5_message->header.source_node_type = 's';
    strcpy((char *)&socks5_message->header.source_ip, (char *)&server->server_ip);
    socks5_message->header.destination_node_type = 'c';
    strcpy((char *)&socks5_message->header.destination_ip, (char *)&server->client_destination_ip);
    socks5_message->header.tv_sec = htonl(0);
    socks5_message->header.tv_usec = htonl(0);
    socks5_message->header.forwarder_tv_sec = htonl(0);
    socks5_message->header.forwarder_tv_usec = htonl(0);
    socks5_message->header.data_size = htonl(0);

    start_thread(m_thread, (void *)push_socks5_message, (void *)socks5_message);

    return 0;
}

void forwarder_recv_data_server(struct stack_head *stack)
{
    struct server_data *server = stack->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;
    int32_t rec = 0;
    int32_t sen = 0;
    int32_t len = 0;
    int32_t send_length = 0;
    struct fd_set writefds;
    int nfds = -1;
    struct timeval tv;
    char *buffer = (char *)calloc(NODE_BUFFER_SIZE, sizeof(char));

    server->recv_message_id = 0;

    while(1)
    {
        FD_ZERO(&writefds);
        FD_SET(server->target_sock, &writefds);
        nfds = server->target_sock + 1;
        tv.tv_sec = server->forwarder_tv_sec;
        tv.tv_usec = server->forwarder_tv_usec;

        ret = select(nfds, NULL, &writefds, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[+] forwarder_recv_data_server select timeout\n");
#endif

            break;
        }

        ret = FD_ISSET(server->target_sock, &writefds);
        if(ret > 0)
        {
#ifdef _DEBUG
            printf("[+] [client -> server] forwarder_recv_data_server recv_message\n");
#endif

            memset(buffer, 0, NODE_BUFFER_SIZE);

            rec = recv_message_server(server, buffer, NODE_BUFFER_SIZE, server->forwarder_tv_sec, server->forwarder_tv_usec);
            if(rec > 0)
            {
                if(server->recv_message_id == server->next_recv_message_id)
                {
#ifdef _DEBUG
                    printf("[+] [client <- server] forwarder_recv_data_server send_receive_message(%u) ok\n", server->recv_message_id);
#endif

                    ret = send_receive_message_server(server, server->recv_message_id, 1, 0, server->forwarder_tv_sec, server->forwarder_tv_usec);
                    if(ret < 0)
                    {
                        break;
                    }

                    len = rec;
                    send_length = 0;

#ifdef _DEBUG
                    printf("[+] [server -> target] forwarder_recv_data_server write(%u)\n", server->recv_message_id);
#endif

                    while(len > 0)
                    {
                        sen = write(server->target_sock, buffer + send_length, len);
                        if(sen <= 0)
                        {
                            if(sen == EINTR)
                            {
                                continue;
                            }else if(sen == EAGAIN)
                            {
                                millisleep(5);

                                continue;
                            }else
                            {
#ifdef _DEBUG
                                printf("[-] [server -> target] forwarder_recv_data_server write error: %d\n", sen);
#endif

                                break;
                            }
                        }

                        send_length += sen;
                        len -= sen;
                    }

                    server->next_recv_message_id++;
                }else
                {
#ifdef _DEBUG
                    printf("[+] [client <- server] forwarder_recv_data_server send_receive_message(%u) ng\n", server->recv_message_id);
#endif

                    ret = send_receive_message_server(server, server->recv_message_id, 1, 1, server->forwarder_tv_sec, server->forwarder_tv_usec);

                    break;
                }
            }else
            {
                break;
            }
        }
    }

    free(buffer);

    __asm__ __volatile__
    (
        "lock\n"
        "incl %0"
        : "=m"(stack->join_futex)
        : "m"(stack->join_futex)
        : "cc"
    );

    futex_wake(&stack->join_futex, 1);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] forwarder_recv_data_server is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] forwarder_recv_data_server cannot free stack\n");
#endif
    }

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

void forwarder_send_data_server(struct stack_head *stack)
{
    struct server_data *server = stack->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;
    int32_t rec = 0;
    int32_t sen = 0;
    struct fd_set readfds;
    int nfds = -1;
    struct timeval tv;
    char *buffer = (char *)calloc(NODE_BUFFER_SIZE, sizeof(char));

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(server->target_sock, &readfds);
        nfds = server->target_sock + 1;
        tv.tv_sec = server->forwarder_tv_sec;
        tv.tv_usec = server->forwarder_tv_usec;

        ret = select(nfds, &readfds, NULL, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[+] forwarder_send_data_server select timeout\n");
#endif

            break;
        }

        ret = FD_ISSET(server->target_sock, &readfds);
        if(ret > 0)
        {
#ifdef _DEBUG
            printf("[+] [server <- target] forwarder_send_data_server read\n");
#endif

            memset(buffer, 0, NODE_BUFFER_SIZE);

            rec = read(server->target_sock, buffer, SPIDER_MESSAGE_DATA_SIZE);
            if(rec <= 0)
            {
                if(rec == EINTR)
                {
                    continue;
                }else if(rec == EAGAIN)
                {
                    millisleep(5);

                    continue;
                }else
                {
#ifdef _DEBUG
                    printf("[-] forwarder_send_data_server read error: %d\n", rec);
#endif

                    break;
                }
            }else
            {
#ifdef _DEBUG
                printf("[+] [client <- server] forwarder_send_data_server send_message(%u)\n", server->send_message_id);
#endif

                sen = send_message_server(server, buffer, rec, server->forwarder_tv_sec,server->forwarder_tv_usec);
                if(sen <= 0)
                {
                    break;
                }

#ifdef _DEBUG
                printf("[+] [client -> server] forwarder_send_data_server recv_receive_message(%u)\n", server->send_message_id);
#endif

                ret = recv_receive_message_server(server, server->send_message_id, server->forwarder_tv_sec, server->forwarder_tv_usec);
                if(ret == 0)    //ok
                {
#ifdef _DEBUG
                    printf("[+] [client -> server] forwarder_send_data_server recv_receive_message(%u) ok\n", server->send_message_id);
#endif
                }else if(ret == 1)    // ng
                {
#ifdef _DEBUG
                    printf("[-] [client -> server] forwarder_send_data_server recv_receive_message(%u) ng\n", server->send_message_id);
#endif

                    break;
                }else
                {
                    break;
                }

                server->send_message_id++;
            }
        }
    }

    free(buffer);

    __asm__ __volatile__
    (
        "lock\n"
        "incl %0"
        : "=m"(stack->join_futex)
        : "m"(stack->join_futex)
        : "cc"
    );

    futex_wake(&stack->join_futex, 1);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] forwarder_send_data_server is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] forwarder_send_data_server cannot free stack\n");
#endif
    }

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

void forwarder_server(struct server_data *server)
{
    struct stack_head *stack_forwarder_recv_data_server = NULL;
    struct stack_head *stack_forwarder_send_data_server = NULL;

    stack_forwarder_recv_data_server = start_thread(m_thread, (void *)forwarder_recv_data_server, (void *)server);
    millisleep(100);

    stack_forwarder_send_data_server = start_thread(m_thread, (void *)forwarder_send_data_server, (void *)server);
    millisleep(100);

    futex_wait(&stack_forwarder_recv_data_server->join_futex, 0);
    futex_wait(&stack_forwarder_send_data_server->join_futex, 0);

    return;
}

int32_t send_socks_response_ipv4(struct server_data *server, char *buffer, int32_t buffer_size, char ver, char rep, char rsv, char atyp)
{
    int32_t sen = 0;

    memset(buffer, 0, buffer_size);

    struct socks_response_ipv4 *socks_response_ipv4 = (struct socks_response_ipv4 *)buffer;

    socks_response_ipv4->ver = ver;                 // protocol version
    socks_response_ipv4->rep = rep;                 // Connection refused
    socks_response_ipv4->rsv = rsv;                 // RESERVED
    socks_response_ipv4->atyp = atyp;               // IPv4
    memset(socks_response_ipv4->bnd_addr, 0, 4);    // BND.ADDR
    memset(socks_response_ipv4->bnd_port, 0, 2);    // BND.PORT

    server->send_message_id++;
    sen = send_message_server(server, buffer, sizeof(struct socks_response_ipv4), server->tv_sec, server->tv_usec);

    return sen;
}

int32_t send_socks_response_ipv6(struct server_data *server, char *buffer, int32_t buffer_size, char ver, char rep, char rsv, char atyp)
{
    int32_t sen = 0;

    memset(buffer, 0, buffer_size);

    struct socks_response_ipv6 *socks_response_ipv6 = (struct socks_response_ipv6 *)buffer;

    socks_response_ipv6->ver = ver;                 // protocol version
    socks_response_ipv6->rep = rep;                 // Connection refused
    socks_response_ipv6->rsv = rsv;                 // RESERVED
    socks_response_ipv6->atyp = atyp;               // IPv6
    memset(socks_response_ipv6->bnd_addr, 0, 16);   // BND.ADDR
    memset(socks_response_ipv6->bnd_port, 0, 2);    // BND.PORT

    server->send_message_id++;
    sen = send_message_server(server, buffer, sizeof(struct socks_response_ipv6), server->tv_sec, server->tv_usec);

    return sen;
}

void do_socks5_connection_server(struct server_data *server, struct spider_message *socks5_message)
{
    int32_t ret = 0;
    int i = 0;
    static char authentication_method = SOCKS5_AUTHENTICATION_METHOD;   // 0x0:No Authentication Required  0x2:Username/Password Authentication
    char username[256] = SOCKS5_USERNAME;
    char password[256] = SOCKS5_PASSWORD;
    int32_t rec = 0;
    int32_t sen = 0;
    char *buffer = (char *)calloc(NODE_BUFFER_SIZE, sizeof(char));

    unsigned char method;
    char ver;

    unsigned char ulen = 0;
    unsigned char plen = 0;
    char uname[256] = {0};
    char passwd[256] = {0};

    struct socks_request *socks_request = NULL;
    struct socks_request_ipv4 *socks_request_ipv4 = NULL;
    struct socks_request_domainname *socks_request_domainname = NULL;
    struct socks_request_ipv6 *socks_request_ipv6 = NULL;

    char atyp;
    char cmd;

    struct sockaddr_in target_addr;      // ipv4
    struct sockaddr_in6 target_addr6;    // ipv6
    int target_addr_length = 16;
    int target_addr6_length = sizeof(target_addr6);

    int family = 0;
    char domainname[256] = {0};
    unsigned short domainname_length = 0;

    int flags = 0;

    char *ipv6_link_local_prefix = "fe80:";

    memset(&target_addr, 0, sizeof(struct sockaddr_in));
    memset(&target_addr6, 0, sizeof(struct sockaddr_in6));

    server->recv_message_id = 0;
    server->next_recv_message_id = 0;
    server->send_message_id = generate_random_id();

    if(strstr((char *)&server->server_ip, ipv6_link_local_prefix) == (char *)&server->server_ip)
    {
        strcpy((char *)&server->server_ip_scope_id, ip->spider_ipv6_link_local_scope_id);
    }

    // socks SELECTION_REQUEST [client -> server]
#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_server recv selection request\n");
#endif

    rec = socks5_message->header.data_size;
    if(rec <= 0 || rec > NODE_BUFFER_SIZE)
    {
#ifdef _DEBUG
        printf("[-] [client -> server] do_socks5_connection_server recv selection request error\n");
#endif

        goto exit;
    }

    memcpy(buffer, (char *)&socks5_message->data, rec);
    server->recv_message_id = socks5_message->header.message_id;
    server->next_recv_message_id = server->recv_message_id + 1;

    free(socks5_message);

    if(server->encryption_flag == 1)    // xor
    {
        ret = xor_decrypt(x_key, buffer, rec, NODE_BUFFER_SIZE);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] [client -> server] do_socks5_connection_server selection request xor_decrypt error: %d\n", ret);
#endif
            goto exit;
        }

        rec = ret;
    }else if(server->encryption_flag == 2)  // aes
    {
        ret = aes_decrypt(a_key, buffer, rec, NODE_BUFFER_SIZE);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] [client -> server] do_socks5_connection_server selection request aes_decrypt error: %d\n", ret);
#endif

            goto exit;
        }

        rec = ret;
    }

#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_server recv selection request: %d bytes\n", rec);
#endif

    struct selection_request *selection_request = (struct selection_request *)buffer;
    method = 0xFF;
    for(i = 0; i < selection_request->nmethods; i++)
    {
        if(selection_request->methods[i] == authentication_method)  // NO AUTHENTICATION REQUIRED or USERNAME/PASSWORD
        {
#ifdef _DEBUG
            printf("[+] do_socks5_connection_server selection_request->methods[%d]: %02x\n", i, selection_request->methods[i]);
#endif

            method = selection_request->methods[i];

            break;
        }
    }

    if(method == 0xFF)
    {
#ifdef _DEBUG
        printf("[-] [client -> server] do_socks5_connection_server selection request method error\n");
#endif
    }

    ver = selection_request->ver;

    // socks SELECTION_RESPONSE [client <- server]
    memset(buffer, 0, NODE_BUFFER_SIZE);
    struct selection_response *selection_response = (struct selection_response *)buffer;
    selection_response->ver = 0x5;          // socks version 5
    selection_response->method = method;    // no authentication required or username/password

    if(ver != 0x5 || authentication_method != method)
    {
        selection_response->method = 0xFF;
    }

    server->send_message_id++;
    sen = send_message_server(server, buffer, sizeof(struct selection_response), server->tv_sec, server->tv_usec);

#ifdef _DEBUG
    printf("[+] [client <- server] do_socks5_connection_server send selection response: %d bytes\n", sen);
#endif

    if(authentication_method != method)
    {
#ifdef _DEBUG
        printf("[-] do_socks5_connection_server authentication method error: server: 0x%x client: 0x%x\n", authentication_method, method);
#endif

        goto exit;
    }

    // socks USERNAME_PASSWORD_AUTHENTICATION [client -> server]
    if(method == 0x2)
    {
        // socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST [client -> server]
#ifdef _DEBUG
        printf("[+] [client -> server] do_socks5_connection_server recv username password authentication request\n");
#endif

        rec = recv_message_server(server, buffer, NODE_BUFFER_SIZE, server->tv_sec, server->tv_usec);

        if(rec <= 0 || server->next_recv_message_id != server->recv_message_id)
        {
#ifdef _DEBUG
            printf("[-] [client -> server] do_socks5_connection_server recv username password authentication request error\n");
#endif

            goto exit;
        }

        server->next_recv_message_id++;

#ifdef _DEBUG
        printf("[+] [client -> server] do_socks5_connection_server receive username password authentication request: %d bytes\n", rec);
#endif

        struct username_password_authentication_request_tmp *username_password_authentication_request_tmp = (struct username_password_authentication_request_tmp *)buffer;

        ulen = username_password_authentication_request_tmp->ulen;
        memcpy(uname, &username_password_authentication_request_tmp->uname, ulen);
        memcpy(&plen, &username_password_authentication_request_tmp->uname + ulen, 1);
        memcpy(passwd, &username_password_authentication_request_tmp->uname + ulen + 1, plen);

#ifdef _DEBUG
        printf("[+] do_socks5_connection_server uname: %s, ulen: %d, passwd: %s, plen: %d\n", uname, ulen, passwd, plen);
#endif

        ver = username_password_authentication_request_tmp->ver;


        // socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE [client <- server]
        memset(buffer, 0, NODE_BUFFER_SIZE);
        struct username_password_authentication_response *username_password_authentication_response = (struct username_password_authentication_response *)buffer;
        username_password_authentication_response->ver = 0x1;

        if(ver == 0x1 && !strncmp(uname, username, sizeof(username)) && !strncmp(passwd, password, sizeof(password)))
        {
#ifdef _DEBUG
            printf("[+] do_socks5_connection_server succeed username password authentication\n");
#endif
            username_password_authentication_response->status = 0x0;

            server->send_message_id++;
            sen = send_message_server(server, buffer, sizeof(struct username_password_authentication_response), server->tv_sec, server->tv_usec);

#ifdef _DEBUG
            printf("[+] [client <- server] do_socks5_connection_server send username password authentication response: %d bytes\n", sen);
#endif
        }else
        {
#ifdef _DEBUG
            printf("[-] do_socks5_connection_server fail username password authentication\n");
#endif
            username_password_authentication_response->status = 0xFF;

            server->send_message_id++;
            sen = send_message_server(server, buffer, sizeof(struct username_password_authentication_response), server->tv_sec, server->tv_usec);

#ifdef _DEBUG
            printf("[+] [client <- server] do_socks5_connection_server send selection response: %d bytes\n", sen);
#endif

            goto exit;
        }
    }

    // socks SOCKS_REQUEST [client -> server]
#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_server recv socks request\n");
#endif

    memset(buffer, 0, NODE_BUFFER_SIZE);

    rec = recv_message_server(server, buffer, NODE_BUFFER_SIZE, server->tv_sec, server->tv_usec);
    if(rec <= 0 || server->next_recv_message_id != server->recv_message_id)
    {
#ifdef _DEBUG
        printf("[-] [client -> server] do_socks5_connection_server recv socks request error\n");
#endif

        goto exit;
    }

    server->next_recv_message_id++;

#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_server recv socks request: %d bytes\n", rec);
#endif

    socks_request = (struct socks_request *)buffer;

    atyp = socks_request->atyp;
    if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4)
    {
#ifdef _DEBUG
        printf("[-] do_socks5_connection_server socks request atyp(%d) error\n", atyp);
        printf("[-] not implemented\n");
#endif

        // socks SOCKS_RESPONSE send error [client <- server]
        sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x8, 0x0, 0x1);

        goto exit;
    }

    cmd = socks_request->cmd;
    if(cmd != 0x1)  // CONNECT (0x1)
    {
#ifdef _DEBUG
        printf("[-] do_socks5_connection_server socks request cmd(%d) error\n", cmd);
        printf("[-] not implemented\n");
#endif

        // socks SOCKS_RESPONSE send error [client <- server]
        if(atyp == 0x1 || atyp == 0x3)  // ipv4
        {
            sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x1);
        }else   // ipv6
        {
            sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x4);
        }

            goto exit;
    }

    if(socks_request->atyp == 0x1)  // ipv4
    {
        socks_request_ipv4 = (struct socks_request_ipv4 *)buffer;

        family = AF_INET;
        target_addr.sin_family = AF_INET;
        memcpy(&target_addr.sin_addr.s_addr, &socks_request_ipv4->dst_addr, 4);
        memcpy(&target_addr.sin_port, &socks_request_ipv4->dst_port, 2);
    }else if(socks_request->atyp == 0x3)    // domain name
    {
        socks_request_domainname = (struct socks_request_domainname*)buffer;
        domainname_length = socks_request_domainname->dst_addr_len;
        memcpy(&domainname, &socks_request_domainname->dst_addr, domainname_length);

#ifdef _DEBUG
        printf("[+] do_socks5_connection_server domainname: %s length: %d\n", domainname, domainname_length);
#endif

        if(strchr((char *)&server->server_ip, ':') == NULL)  // ipv4
        {
            family = AF_INET;
            target_addr.sin_family = AF_INET;
            memcpy(&target_addr.sin_port, &socks_request_domainname->dst_addr[domainname_length], 2);

            ret = get_host_by_name((char *)&domainname, TYPE_A, &target_addr, target_addr_length);
            if(ret < 0)
            {
#ifdef _DEBUG
                printf("[-] do_socks5_connection_server cannot resolv the domain name: %s\n", domainname);
#endif

                // socks SOCKS_RESPONSE send error [client <- server]
                sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x5, 0x0, 0x1);

                goto exit;
            }
        }else   // ipv6
        {
            family = AF_INET6;
            target_addr6.sin6_family = AF_INET6;
            memcpy(&target_addr6.sin6_port, &socks_request_domainname->dst_addr[domainname_length], 2);

            ret = get_host_by_name((char *)&domainname, TYPE_AAAA, &target_addr6, target_addr6_length);
            if(ret != 0)
            {
#ifdef _DEBUG
                printf("[-] do_socks5_connection_server cannot resolv the domain name: %s\n", domainname);
#endif

                // socks SOCKS_RESPONSE send error [client <- server]
                sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x5, 0x0, 0x4);

                goto exit;
            }

            if(strlen((char *)&server->server_ip_scope_id) > 0)
            {
                strcpy((char *)&server->target_ip_scope_id, (char *)&server->server_ip_scope_id);
                target_addr6.sin6_scope_id = atoi((char *)&server->target_ip_scope_id);
            }
        }
    }else if(socks_request->atyp == 0x4)    // IPv6
    {
        socks_request_ipv6 = (struct socks_request_ipv6*)buffer;

        family = AF_INET6;
        target_addr6.sin6_family = AF_INET6;
        memcpy(&target_addr6.sin6_addr, &socks_request_ipv6->dst_addr, 16);
        memcpy(&target_addr6.sin6_port, &socks_request_ipv6->dst_port, 2);

        if(strlen((char *)&server->server_ip_scope_id) > 0)
        {
            strcpy((char *)&server->target_ip_scope_id, (char *)&server->server_ip_scope_id);
            target_addr6.sin6_scope_id = atoi((char *)&server->target_ip_scope_id);
        }
    }else
    {
#ifdef _DEBUG
        printf("[-] not implemented\n");
#endif

        // socks SOCKS_RESPONSE send error [client <- server]
        sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x1, 0x0, 0x1);

        goto exit;
    }

    // socks SOCKS_RESPONSE [client <- server]
    if(atyp == 0x1) // ipv4
    {
        inet_ntop(AF_INET, &target_addr.sin_addr, (char *)&server->target_ip, INET6_ADDR_STRING_LENGTH + 1);
        sprintf((char *)&server->target_port, "%d", ntohs(target_addr.sin_port));

        if(cmd == 0x1)  // CONNECT
        {
#ifdef _DEBUG
            printf("[+] [server -> target] do_socks5_connection_server connecting ip: %s port: %s\n", server->target_ip, server->target_port);
#endif

#ifdef _DEBUG
            printf("[+] do_socks5_connection_server socks5 response cmd: CONNECT\n");
#endif

            server->target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

            flags = fcntl(server->target_sock, F_GETFL, 0);
            flags &= ~O_NONBLOCK;
            fcntl(server->target_sock, F_SETFL, flags);

            ret = connect(server->target_sock, (struct sockaddr *)&target_addr, target_addr_length);
            if(ret < 0)
            {
#ifdef _DEBUG
                printf("[-] [server <- target] do_socks5_connection_server cannot connect errno: %d\n", ret);
#endif

                sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x5, 0x0, 0x1);

#ifdef _DEBUG
                printf("[+] [client <- server] do_socks5_connection_server socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif

                close(server->target_sock);

                goto exit;
            }

#ifdef _DEBUG
            printf("[+] [server <- target] do_socks5_connection_server connected ip: %s port: %s\n", server->target_ip, server->target_port);
#endif

            sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x0, 0x0, 0x1);

#ifdef _DEBUG
            printf("[+] [client <- server] do_socks5_connection_server socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif

        }else if(cmd == 0x2)    // BIND
        {
#ifdef _DEBUG
            printf("[+] do_socks5_connection_server socks5 response cmd: BIND\n");
            printf("[-] not implemented\n");
#endif

            sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x1);

            goto exit;
        }else if(cmd == 0x3)    // UDP ASSOCIATE
        {
#ifdef _DEBUG
            printf("[+] do_socks5_connection_server socks5 response cmd: UDP ASSOCIATE\n");
            printf("[-] not implemented\n");
#endif

            sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x1);

            goto exit;
        }else
        {
#ifdef _DEBUG
            printf("[-] not implemented\n");
#endif

            sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x1, 0x0, 0x1);

            goto exit;
        }
    }else if(atyp == 0x3)   // domainname
    {
        if(family == AF_INET)   // IPv4
        {
            inet_ntop(AF_INET, &target_addr.sin_addr, (char *)&server->target_ip, INET6_ADDR_STRING_LENGTH + 1);
            sprintf((char *)&server->target_port, "%d", ntohs(target_addr.sin_port));

            if(cmd == 0x1)  // CONNECT
            {
#ifdef _DEBUG
                printf("[+] [server -> target] do_socks5_connection_server connecting ip: %s port: %s\n", server->target_ip, server->target_port);
#endif

#ifdef _DEBUG
                printf("[+] do_socks5_connection_server socks5 response cmd: CONNECT\n");
#endif
                server->target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

                flags = fcntl(server->target_sock, F_GETFL, 0);
                flags &= ~O_NONBLOCK;
                fcntl(server->target_sock, F_SETFL, flags);

                ret = connect(server->target_sock, (struct sockaddr *)&target_addr, target_addr_length);
                if(ret < 0)
                {
#ifdef _DEBUG
                    printf("[-] [server <- target] do_socks5_connection_server cannot connect errno: %d\n", ret);
#endif

                    sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x5, 0x0, 0x1);

#ifdef _DEBUG
                    printf("[+] [client <- server] do_socks5_connection_server socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif

                    close(server->target_sock);

                    goto exit;
                }
#ifdef _DEBUG
                printf("[+] [server <- target] do_socks5_connection_server connected ip: %s port: %s\n", server->target_ip, server->target_port);
#endif

                sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x0, 0x0, 0x1);

#ifdef _DEBUG
                printf("[+] [client <- server] do_socks5_connection_server socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif
            }else if(cmd == 0x2)    // BIND
            {
#ifdef _DEBUG
                printf("[+] do_socks5_connection_server socks5 response cmd: BIND\n");
                printf("[-] not implemented\n");
#endif

                sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x1);

                goto exit;
            }else if(cmd == 0x3)    // UDP ASSOCIATE
            {
#ifdef _DEBUG
                printf("[+] do_socks5_connection_server socks5 response cmd: UDP ASSOCIATE\n");
                printf("[-] not implemented\n");
#endif

                sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x1);

                goto exit;
            }else
            {
#ifdef _DEBUG
                printf("[-] not implemented\n");
#endif

                sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x1, 0x0, 0x1);

                goto exit;
            }
        }else if(family == AF_INET6)    // ipv6
        {
            inet_ntop(AF_INET6, &target_addr6.sin6_addr, (char *)&server->target_ip, INET6_ADDR_STRING_LENGTH + 1);
            sprintf((char *)&server->target_port, "%d", ntohs(target_addr6.sin6_port));

            if(cmd == 0x1)  // CONNECT
            {
#ifdef _DEBUG
                if(target_addr6.sin6_scope_id > 0)
                {
                    printf("[+] [server -> target] do_socks5_connection_server connecting ip: %s%%%s port: %s\n", server->target_ip, server->target_ip_scope_id, server->target_port);
                }else
                {
                    printf("[+] [server -> target] do_socks5_connection_server connecting ip: %s port: %s\n", server->target_ip, server->target_port);
                }
#endif

#ifdef _DEBUG
                printf("[+] do_socks5_connection_server socks5 response cmd: CONNECT\n");
#endif
                server->target_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

                flags = fcntl(server->target_sock, F_GETFL, 0);
                flags &= ~O_NONBLOCK;
                fcntl(server->target_sock, F_SETFL, flags);

                ret = connect(server->target_sock, (struct sockaddr *)&target_addr6, target_addr6_length);
                if(ret < 0)
                {
#ifdef _DEBUG
                    printf("[-] [server <- target] do_socks5_connection_server cannot connect errno: %d\n", ret);
#endif

                    sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x5, 0x0, 0x4);

#ifdef _DEBUG
                    printf("[+] [client <- server] do_socks5_connection_server socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif

                    close(server->target_sock);

                    goto exit;
                }

#ifdef _DEBUG
                if(target_addr6.sin6_scope_id > 0)
                {
                    printf("[+] [server -> target] do_socks5_connection_server connected ip: %s%%%s port: %s\n", server->target_ip, server->target_ip_scope_id, server->target_port);
                }else
                {
                    printf("[+] [server -> target] do_socks5_connection_server connected ip: %s port: %s\n", server->target_ip, server->target_port);
                }
#endif

                sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x0, 0x0, 0x4);

#ifdef _DEBUG
                printf("[+] [client <- server] do_socks5_connection_server socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif
            }else if(cmd == 0x2)    // BIND
            {
#ifdef _DEBUG
                printf("[+] do_socks5_connection_server socks5 response cmd: BIND\n");
                printf("[-] not implemented\n");
#endif

                sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x4);

                goto exit;
            }else if(cmd == 0x3)    // UDP ASSOCIATE
            {
#ifdef _DEBUG
                printf("[+] do_socks5_connection_server socks5 response cmd: UDP ASSOCIATE\n");
                printf("[-] not implemented\n");
#endif

                sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x4);

                goto exit;
            }else
            {
#ifdef _DEBUG
                printf("[-] not implemented\n");
#endif

                sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x1, 0x0, 0x4);

                goto exit;
            }
        }else
        {
#ifdef _DEBUG
            printf("[-] not implemented\n");
#endif

            sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x1, 0x0, 0x1);

            goto exit;
        }
    }else if(atyp == 0x4)   // IPv6
    {
        inet_ntop(AF_INET6, &target_addr6.sin6_addr, (char *)&server->target_ip, INET6_ADDR_STRING_LENGTH + 1);
        sprintf((char *)&server->target_port, "%d", ntohs(target_addr6.sin6_port));

        if(cmd == 0x1)  // CONNECT
        {
#ifdef _DEBUG
            if(target_addr6.sin6_scope_id > 0)
            {
                printf("[+] [server -> target] do_socks5_connection_server connecting ip: %s%%%s port: %s\n", server->target_ip, server->target_ip_scope_id, server->target_port);
            }else
            {
                printf("[+] [server -> target] do_socks5_connection_server connecting ip: %s port: %s\n", server->target_ip, server->target_port);
            }
#endif

#ifdef _DEBUG
            printf("[+] do_socks5_connection_server socks5 response cmd: CONNECT\n");
#endif
            server->target_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

            flags = fcntl(server->target_sock, F_GETFL, 0);
            flags &= ~O_NONBLOCK;
            fcntl(server->target_sock, F_SETFL, flags);

            ret = connect(server->target_sock, (struct sockaddr *)&target_addr6, target_addr6_length);
            if(ret < 0)
            {
#ifdef _DEBUG
                printf("[-] [server <- target] do_socks5_connection_server cannot connect errno: %d\n", ret);
#endif

                sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x5, 0x0, 0x4);

#ifdef _DEBUG
                printf("[+] [client <- server] socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif

                close(server->target_sock);

                goto exit;
            }

#ifdef _DEBUG
            if(target_addr6.sin6_scope_id > 0)
            {
                printf("[+] [server -> target] do_socks5_connection_server connected ip: %s%%%s port: %s\n", server->target_ip, server->target_ip_scope_id, server->target_port);
            }else
            {
                printf("[+] [server -> target] do_socks5_connection_server connected ip: %s port: %s\n", server->target_ip, server->target_port);
            }
#endif

            sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x0, 0x0, 0x4);

#ifdef _DEBUG
            printf("[+] [client <- server] do_socks5_connection_server socks request: %d bytes, socks response: %d bytes\n", rec, sen);
#endif
        }else if(cmd == 0x2)    // BIND
        {
#ifdef _DEBUG
            printf("[+] do_socks5_connection_server socks5 response cmd: BIND\n");
            printf("[-] not implemented\n");
#endif

            sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x4);

            goto exit;
        }else if(cmd == 0x3)    // UDP ASSOCIATE
        {
#ifdef _DEBUG
            printf("[+] do_socks5_connection_server socks5 response cmd: UDP ASSOCIATE\n");
            printf("[-] not implemented\n");
#endif

            sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x7, 0x0, 0x4);

            goto exit;
        }else{
#ifdef _DEBUG
            printf("[-] not implemented\n");
#endif

            sen = send_socks_response_ipv6(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x1, 0x0, 0x4);

            goto exit;
        }
    }else
    {
#ifdef _DEBUG
        printf("[-] not implemented\n");
#endif

        sen = send_socks_response_ipv4(server, buffer, NODE_BUFFER_SIZE, 0x5, 0x1, 0x0, 0x1);

        goto exit;
    }

    // forwarder [client <> client <> server <> target]
#ifdef _DEBUG
    printf("[+] [client <> client <> server <> target] do_socks5_connection_server forwarder_server\n");
#endif

    server->send_message_id++;
    forwarder_server(server);

#ifdef _DEBUG
    printf("[+] do_socks5_connection_server worker exit\n");
#endif

    close(server->target_sock);

exit:
    free(buffer);

    return;
}

void server_worker(struct stack_head *stack)
{
    struct server_worker_function_args *args = stack->args;
    struct server_data *server = args->server;
    struct spider_message *message = args->message;
    struct map_node_thread *thread = NULL;

    do_socks5_connection_server(server, message);

    free_map_server_receive_message(server->m_server_receive_message, &server->sem_m_server_receive_message);
    free_queue(server->socks5_message_queue);
    delete_spider_node(tree_server, &sem_tree_server, server->server_id);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] server_worker is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] server_worker cannot free stack\n");
#endif
    }

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

