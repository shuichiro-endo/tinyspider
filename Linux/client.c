/*
 * Title:  client.c
 * Author: Shuichiro Endo
 */

#include "client.h"

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
extern int encryption_flag;
extern struct avlt_node_route *routing_table;
extern struct rbt_spider *tree_client;
extern struct semaphore sem_tree_client;
extern struct xor_key *x_key;
extern struct aes_key *a_key;

void create_map_client_receive_message(struct map_client_receive_message **map, struct semaphore *sem)
{
    semaphore_init(sem, 1);

    semaphore_wait(sem);

    *map = (struct map_client_receive_message *)calloc(1, sizeof(struct map_client_receive_message));
    (*map)->head = NULL;

    semaphore_post(sem);
}

void insert_map_node_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem, uint32_t message_id, struct spider_message *message)
{
    struct map_node_client_receive_message *node = NULL;

    semaphore_wait(sem);

    node = (struct map_node_client_receive_message *)calloc(1, sizeof(struct map_node_client_receive_message));
    node->message_id = message_id;
    node->message = message;
    node->next = map->head;
    map->head = node;

    semaphore_post(sem);
}

struct map_node_client_receive_message *search_map_node_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem, uint32_t message_id)
{
    struct map_node_client_receive_message *current = NULL;

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

void delete_map_node_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem, uint32_t message_id)
{
    struct map_node_client_receive_message *current = NULL;
    struct map_node_client_receive_message *previous = NULL;

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

void free_map_client_receive_message(struct map_client_receive_message *map, struct semaphore *sem)
{
    struct map_node_client_receive_message *current = NULL;
    struct map_node_client_receive_message *next = NULL;

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

void insert_map_node_client_receive_message_thread(struct stack_head *stack)
{
    struct insert_map_node_client_receive_message_thread_function_args *args = stack->args;
    struct client_data *client = args->client;
    uint32_t message_id = args->message_id;
    struct spider_message *message = args->message;
    struct map_node_thread *thread = NULL;

    free(args);

    insert_map_node_client_receive_message(client->m_client_receive_message, &client->sem_m_client_receive_message, message_id, message);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] insert_map_node_client_receive_message_thread is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] insert_map_node_client_receive_message_thread cannot free stack\n");
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

void push_socks5_message_client(struct stack_head *stack)
{
    struct push_message_queue_function_args_client *args = stack->args;
    struct client_data *client = args->client;
    struct spider_message *message = args->message;
    struct map_node_thread *thread = NULL;

    free(args);

    if(client->socks5_message_queue != NULL)
    {
        enqueue(client->socks5_message_queue, (void *)message);
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message_client socks5_message_queue is null\n");
#endif

        free(message);
    }

    millisleep(100);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_socks5_message_client is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message_client cannot free stack\n");
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

struct spider_message *pop_socks5_message_client_timeout(struct client_data *client, long tv_sec, long tv_usec)
{
    struct timeval start;
    struct timeval end;
    long t = 0;
    struct spider_message *socks5_message = NULL;

    if(gettimeofday(&start, NULL) == -1)
    {
#ifdef _DEBUG
        printf("[-] pop_socks5_message_client_timeout gettimeofday error\n");
#endif
        return NULL;
    }

    do
    {
        if(gettimeofday(&end, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] pop_socks5_message_client_timeout gettimeofday error\n");
#endif
            return NULL;
        }

        t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
        if(t >= (tv_sec * 1000000 + tv_usec))
        {
#ifdef _DEBUG
            printf("[+] pop_socks5_message_client_timeout timeout\n");
#endif

            return NULL;
        }

        millisleep(100);
    }while(client->socks5_message_queue->count <= 0);

    socks5_message = (struct spider_message *)dequeue(client->socks5_message_queue);

    return socks5_message;
}

int32_t recv_message_client(struct client_data *client, char *buffer, int32_t buffer_size, long tv_sec, long tv_usec, bool register_server_id_flag)
{
    int32_t ret = 0;
    int32_t rec = 0;
    struct spider_message *socks5_message = NULL;

    memset(buffer, 0, buffer_size);

    socks5_message = pop_socks5_message_client_timeout(client, tv_sec, tv_usec);
    if(socks5_message !=  NULL)
    {
        if(socks5_message->header.message_type == 's')     // socks5 message
        {
            rec = socks5_message->header.data_size;
            if(rec >= 0)
            {
                if(register_server_id_flag)
                {
                    client->server_id = socks5_message->header.server_id;
                }

                client->recv_message_id = socks5_message->header.message_id;

                memcpy(buffer, socks5_message->data, rec);

#ifdef _DEBUG
//                printf("[+] recv_message_client client_id: %u rec: %d\n", client->client_id, rec);
//                print_bytes(buffer, rec);
#endif

                if(client->encryption_flag == 1)    // xor
                {
                    ret = xor_decrypt(x_key, buffer, rec, buffer_size);
                    if(ret <= 0)
                    {
#ifdef _DEBUG
                        printf("[-] recv_message_client xor_decrypt error: %d\n", ret);
#endif

                        goto error;
                    }

                    rec = ret;
                }else if(client->encryption_flag == 2)  // aes
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
                printf("[-] recv_message recv error: %d\n", rec);
#endif

                goto error;
            }
        }else
        {
#ifdef _DEBUG
            printf("[-] recv_message unknown message type: %c\n", socks5_message->header.message_type);
#endif

            goto error;
        }
    }else
    {
#ifdef _DEBUG
        printf("[-] recv_message error\n");
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

int32_t send_message_client(struct client_data *client, char *buffer, int32_t buffer_length, long tv_sec, long tv_usec)
{
    int32_t ret = 0;
    int32_t sen = 0;
    struct spider_message *socks5_message = NULL;

    if(client->encryption_flag == 1)    // xor
    {
        ret = xor_encrypt(x_key, buffer, buffer_length, SPIDER_MESSAGE_DATA_MAX_SIZE);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] send_message_client xor_encrypt error: %d\n", ret);
#endif

            return -1;
        }

        buffer_length = ret;
    }else if(client->encryption_flag == 2)  // aes
    {
        ret = aes_encrypt(a_key, buffer, buffer_length, SPIDER_MESSAGE_DATA_MAX_SIZE);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] send_message_client aes_encrypt error: %d\n", ret);
#endif

            return -1;
        }

        buffer_length = ret;
    }

#ifdef _DEBUG
//    printf("[+] send_message_client client_id: %u buffer_length: %d\n", client->client_id, buffer_length);
//    print_bytes(buffer, buffer_length);
#endif

    socks5_message = (struct spider_message *)calloc(1, sizeof(struct spider_message));

    socks5_message->header.message_type = 's';
    socks5_message->header.message_id = htonl(client->send_message_id);
    socks5_message->header.connection_id = htonl(client->connection_id);
    socks5_message->header.client_id = htonl(client->client_id);
    socks5_message->header.server_id = htonl(client->server_id);
    socks5_message->header.pipe_id = htonl(0);
    socks5_message->header.source_node_type = 'c';
    strcpy((char *)&socks5_message->header.source_ip, (char *)&client->client_ip);
    socks5_message->header.destination_node_type = 's';
    strcpy((char *)&socks5_message->header.destination_ip, (char *)&client->destination_spider_ip);
    socks5_message->header.tv_sec = htonl(client->tv_sec);
    socks5_message->header.tv_usec = htonl(client->tv_usec);
    socks5_message->header.forwarder_tv_sec = htonl(client->forwarder_tv_sec);
    socks5_message->header.forwarder_tv_usec = htonl(client->forwarder_tv_usec);
    socks5_message->header.data_size = htonl(buffer_length);
    memcpy((char *)&socks5_message->data, buffer, buffer_length);

    start_thread(m_thread, (void *)push_socks5_message, (void *)socks5_message);

    return buffer_length;
}

int recv_receive_message_client(struct client_data *client, uint32_t message_id, long tv_sec, long tv_usec)
{
    struct map_node_client_receive_message *node = NULL;
    struct spider_message *socks5_message = NULL;
    struct timeval start;
    struct timeval end;
    long t = 0;

    if(gettimeofday(&start, NULL) == -1)
    {
#ifdef _DEBUG
        printf("[-] recv_receive_message_client gettimeofday error\n");
#endif

        goto error;
    }

    while(1)
    {
        node = search_map_node_client_receive_message(client->m_client_receive_message, &client->sem_m_client_receive_message, message_id);
        if(node != NULL)
        {
            socks5_message = (struct spider_message *)node->message;
            if(socks5_message != NULL)
            {
                if(socks5_message->header.receive_flag == 1 && socks5_message->header.receive_result == 0)  // ok
                {
                    delete_map_node_client_receive_message(client->m_client_receive_message, &client->sem_m_client_receive_message, message_id);

                    goto exit_0;
                }else if(socks5_message->header.receive_flag == 1 && socks5_message->header.receive_result == 1)    // ng
                {
                    delete_map_node_client_receive_message(client->m_client_receive_message, &client->sem_m_client_receive_message, message_id);

                    goto exit_1;
                }else
                {
                    delete_map_node_client_receive_message(client->m_client_receive_message, &client->sem_m_client_receive_message, message_id);

                    goto error;
                }
            }else
            {
                delete_map_node_client_receive_message(client->m_client_receive_message, &client->sem_m_client_receive_message, message_id);

                goto error;
            }
        }else
        {
            if(gettimeofday(&end, NULL) == -1)
            {
#ifdef _DEBUG
                printf("[-] recv_receive_message_client gettimeofday error\n");
#endif

                goto error;
            }

            t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
            if(t >= (tv_sec * 1000000 + tv_usec))
            {
#ifdef _DEBUG
                printf("[+] recv_receive_message_client recv_receive_message timeout\n");
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

int send_receive_message_client(struct client_data *client, uint32_t message_id, uint8_t receive_flag, uint8_t receive_result, long tv_sec, long tv_usec)
{
    struct spider_message *socks5_message = (struct spider_message *)calloc(1, sizeof(struct spider_message));

    socks5_message->header.message_type = 's';
    socks5_message->header.receive_flag = receive_flag;;
    socks5_message->header.receive_result = receive_result;
    socks5_message->header.message_id = htonl(message_id);
    socks5_message->header.connection_id = htonl(client->connection_id);
    socks5_message->header.client_id = htonl(client->client_id);
    socks5_message->header.server_id = htonl(client->server_id);
    socks5_message->header.pipe_id = htonl(0);
    socks5_message->header.source_node_type = 'c';
    strcpy((char *)&socks5_message->header.source_ip, (char *)&client->client_ip);
    socks5_message->header.destination_node_type = 's';
    strcpy((char *)&socks5_message->header.destination_ip, (char *)&client->destination_spider_ip);
    socks5_message->header.tv_sec = htonl(0);
    socks5_message->header.tv_usec = htonl(0);
    socks5_message->header.forwarder_tv_sec = htonl(0);
    socks5_message->header.forwarder_tv_usec = htonl(0);
    socks5_message->header.data_size = htonl(0);

    start_thread(m_thread, (void *)push_socks5_message, (void *)socks5_message);

    return 0;
}

void forwarder_recv_data_client(struct stack_head *stack)
{
    client_data *client = stack->args;
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
        FD_SET(client->client_sock, &readfds);
        nfds = client->client_sock + 1;
        tv.tv_sec = client->forwarder_tv_sec;
        tv.tv_usec = client->forwarder_tv_usec;

        ret = select(nfds, &readfds, NULL, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[+] forwarder_recv_data_client select timeout\n");
#endif

            break;
        }

        ret = FD_ISSET(client->client_sock, &readfds);
        if(ret > 0)
        {
#ifdef _DEBUG
            printf("[+] [client -> client] forwarder_recv_data_client read\n");
#endif

            memset(buffer, 0, NODE_BUFFER_SIZE);

            rec = read(client->client_sock, buffer, SPIDER_MESSAGE_DATA_SIZE);
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
                    printf("[-] [client -> client] forwarder_recv_data_client read error: %d\n", rec);
#endif

                    break;
                }
            }else
            {
#ifdef _DEBUG
                printf("[+] [client -> server] forwarder_recv_data_client send_message(%u)\n", client->send_message_id);
#endif
                sen = send_message_client(client, buffer, rec, client->forwarder_tv_sec, client->forwarder_tv_usec);
                if(sen <= 0)
                {
                    break;
                }

#ifdef _DEBUG
                printf("[+] [client <- server] forwarder_recv_data_client recv_receive_message(%u)\n", client->send_message_id);
#endif
                ret = recv_receive_message_client(client, client->send_message_id, client->forwarder_tv_sec, client->forwarder_tv_usec);
                if(ret == 0)    // ok
                {
#ifdef _DEBUG
                    printf("[+] [client <- server] forwarder_recv_data_client recv_receive_message(%u) ok\n", client->send_message_id);
#endif
                }else if(ret == 1)    // ng
                {
#ifdef _DEBUG
                    printf("[-] [client <- server] forwarder_recv_data_client recv_receive_message(%u) ng\n", client->send_message_id);
#endif

                    break;
                }else
                {
                    break;
                }

                client->send_message_id++;
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
        printf("[+] forwarder_recv_data_client is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] forwarder_recv_data_client cannot free stack\n");
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

void forwarder_send_data_client(struct stack_head *stack)
{
    struct client_data *client = stack->args;
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
    client->recv_message_id = 0;

    while(1)
    {
        FD_ZERO(&writefds);
        FD_SET(client->client_sock, &writefds);
        nfds = client->client_sock + 1;
        tv.tv_sec = client->forwarder_tv_sec;
        tv.tv_usec = client->forwarder_tv_usec;

        ret = select(nfds, NULL, &writefds, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[+] forwarder_send_data_client select timeout\n");
#endif

            break;
        }

        ret = FD_ISSET(client->client_sock, &writefds);
        if(ret > 0)
        {
#ifdef _DEBUG
            printf("[+] [client <- server] forwarder_send_data_client recv_message\n");
#endif

            memset(buffer, 0, NODE_BUFFER_SIZE);

            rec = recv_message_client(client, buffer, NODE_BUFFER_SIZE, client->forwarder_tv_sec, client->forwarder_tv_usec, false);
            if(rec > 0)
            {
                if(client->recv_message_id == client->next_recv_message_id)
                {
#ifdef _DEBUG
                    printf("[+] [client -> server] forwarder_send_data_client send_receive_message(%u) ok\n", client->recv_message_id);
#endif

                    ret = send_receive_message_client(client, client->recv_message_id, 1, 0, client->forwarder_tv_sec, client->forwarder_tv_usec);
                    if(ret < 0)
                    {
                        break;
                    }

                    len = rec;
                    send_length = 0;

#ifdef _DEBUG
                    printf("[+] [client <- client] forwarder_send_data_client write(%u)\n", client->recv_message_id);
#endif

                    while(len > 0)
                    {
                        sen = write(client->client_sock, buffer + send_length, len);
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
                                printf("[-] [client <- client] forwarder_send_data_client write error: %d\n", sen);
#endif

                                break;
                            }
                        }

                        send_length += sen;
                        len -= sen;
                    }

                    client->next_recv_message_id++;
                }else
                {
#ifdef _DEBUG
                    printf("[-] [client -> server] forwarder_send_data_client send_receive_message(%u) ng\n", client->recv_message_id);
#endif

                    ret = send_receive_message_client(client, client->recv_message_id, 1, 1, client->forwarder_tv_sec, client->forwarder_tv_usec);

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
        printf("[+] forwarder_send_data_client is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] forwarder_send_data_client cannot free stack\n");
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

void forwarder_client(struct client_data * client)
{
    struct stack_head *stack_forwarder_recv_data_client = NULL;
    struct stack_head *stack_forwarder_send_data_client = NULL;

    stack_forwarder_recv_data_client = start_thread(m_thread, (void *)forwarder_recv_data_client, (void *)client);
    millisleep(100);

    stack_forwarder_send_data_client = start_thread(m_thread, (void *)forwarder_send_data_client, (void *)client);
    millisleep(100);

    futex_wait(&stack_forwarder_recv_data_client->join_futex, 0);
    futex_wait(&stack_forwarder_send_data_client->join_futex, 0);

    return;
}

void do_socks5_connection_client(struct client_data *client)
{
    int ret = 0;
    int32_t rec = 0;
    int32_t sen = 0;
    char *buffer = (char *)calloc(NODE_BUFFER_SIZE, sizeof(char));

    client->recv_message_id = 0;
    client->next_recv_message_id = 0;
    client->send_message_id = generate_random_id();

    // socks SELECTION_REQUEST [client -> client]
#ifdef _DEBUG
    printf("[+] [client -> client] do_socks5_connection_client recv selection request\n");
#endif

    rec = recv_data(client->client_sock, buffer, SPIDER_MESSAGE_DATA_SIZE, client->tv_sec, client->tv_usec);
    if(rec <= 0)
    {
#ifdef _DEBUG
        printf("[-] [client -> client] do_socks5_connection_client recv selection request error\n");
#endif

        goto exit;
    }

#ifdef _DEBUG
    printf("[+] [client -> client] do_socks5_connection_client recv selection request: %d bytes\n", rec);
#endif

    // socks SELECTION_REQUEST [client -> server]
#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_client send selection request\n");
#endif

    client->send_message_id++;
    sen = send_message_client(client, buffer, rec, client->tv_sec, client->tv_usec);

#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_client send selection request: %d bytes\n", sen);
#endif

    // socks SELECTION_RESPONSE [client <- server]
#ifdef _DEBUG
    printf("[+] [client <- server] do_socks5_connection_client recv selection response\n");
#endif

    rec = recv_message_client(client, buffer, NODE_BUFFER_SIZE, client->tv_sec, client->tv_usec, true);

    if(rec != sizeof(struct selection_response))
    {
#ifdef _DEBUG
        printf("[-] [client <- server] do_socks5_connection_client recv selection response error\n");
#endif

        goto exit;
    }

    client->next_recv_message_id = client->recv_message_id + 1;

#ifdef _DEBUG
    printf("[+] [client <- server] do_socks5_connection_client recv selection response: %d bytes\n", rec);
#endif

    // socks SELECTION_RESPONSE [client <- client]
#ifdef _DEBUG
    printf("[+] [client <- client] do_socks5_connection_client send selection response\n");
#endif
    sen = send_data(client->client_sock, buffer, rec, client->tv_sec, client->tv_usec);

#ifdef _DEBUG
    printf("[+] [client <- client] do_socks5_connection_client send selection response: %d bytes\n", sen);
#endif

    struct selection_response *selection_response = (struct selection_response *)buffer;
    if((unsigned char)selection_response->method == 0xFF)
    {
#ifdef _DEBUG
        printf("[-] [client <- client] do_socks5_connection_client socks5server authentication method error\n");
#endif
    }

    if(selection_response->method == 0x2)   // USERNAME_PASSWORD_AUTHENTICATION
    {
        // socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST client -> client
#ifdef _DEBUG
        printf("[+] [client -> client] do_socks5_connection_client recv username password authentication request\n");
#endif

        rec = recv_data(client->client_sock, buffer, SPIDER_MESSAGE_DATA_SIZE, client->tv_sec, client->tv_usec);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] [client -> client] do_socks5_connection_client recv username password authentication request error\n");
#endif

            goto exit;
        }

#ifdef _DEBUG
        printf("[+] [client -> client] do_socks5_connection_client recv username password authentication request: %d bytes\n", rec);
#endif

        // socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST [client -> server]
#ifdef _DEBUG
        printf("[+] [client -> server] do_socks5_connection_client send username password authentication request\n");
#endif

        client->send_message_id++;
        sen = send_message_client(client, buffer, rec, client->tv_sec, client->tv_usec);

#ifdef _DEBUG
        printf("[+] [client -> server] do_socks5_connection_client send username password authentication request: %d bytes\n", sen);
#endif

        // socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE [client <- server]
#ifdef _DEBUG
        printf("[+] [client <- server] do_socks5_connection_client recv username password authentication response\n");
#endif

        rec = recv_message_client(client, buffer, NODE_BUFFER_SIZE, client->tv_sec, client->tv_usec, false);

        if(rec <= 0 || client->next_recv_message_id != client->recv_message_id)
        {
#ifdef _DEBUG
            printf("[-] [client <- server] do_socks5_connection_client recv username password authentication response error\n");
#endif

            goto exit;
        }

        client->next_recv_message_id++;

#ifdef _DEBUG
        printf("[+] [client <- server] do_socks5_connection_client recv username password authentication response: %d bytes\n", rec);
#endif

        // socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE [client <- client]
#ifdef _DEBUG
        printf("[+] [client <- client] do_socks5_connection_client send username password authentication response\n");
#endif

        sen = send_data(client->client_sock, buffer, rec, client->tv_sec, client->tv_usec);

#ifdef _DEBUG
        printf("[+] [client <- client] do_socks5_connection_client send username password authentication response: %d bytes\n", sen);
#endif
    }


    // socks SOCKS_REQUEST [client -> client]
#ifdef _DEBUG
    printf("[+] [client -> client] do_socks5_connection_client recv socks request\n");
#endif
    rec = recv_data(client->client_sock, buffer, SPIDER_MESSAGE_DATA_SIZE, client->tv_sec,  client->tv_usec);
    if(rec <= 0)
    {
#ifdef _DEBUG
        printf("[-] [client -> client] do_socks5_connection_client recv socks request error\n");
#endif

        goto exit;
    }

#ifdef _DEBUG
    printf("[+] [client -> client] do_socks5_connection_client recv socks request: %d bytes\n", rec);
#endif


    // socks SOCKS_REQUEST [client -> server]
#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_client send socks request\n");
#endif

    client->send_message_id++;
    sen = send_message_client(client, buffer, rec, client->tv_sec, client->tv_usec);

#ifdef _DEBUG
    printf("[+] [client -> server] do_socks5_connection_client send socks request: %d bytes\n", sen);
#endif

    // socks SOCKS_RESPONSE [client <- server]
#ifdef _DEBUG
    printf("[+] [client <- server] do_socks5_connection_client recv socks response\n");
#endif

    rec = recv_message_client(client, buffer, NODE_BUFFER_SIZE, client->tv_sec, client->tv_usec, false);

    if(rec <= 0 || client->next_recv_message_id != client->recv_message_id)
    {
#ifdef _DEBUG
        printf("[-] [client <- server] do_socks5_connection_client recv socks response error\n");
#endif

        goto exit;
    }

    client->next_recv_message_id++;

#ifdef _DEBUG
    printf("[+] [client <- server] do_socks5_connection_client recv socks response: %d bytes\n", rec);
#endif

    // socks SOCKS_RESPONSE [client <- client]
#ifdef _DEBUG
    printf("[+] [client <- client] do_socks5_connection_client send socks response\n");
#endif

    sen = send_data(client->client_sock, buffer, rec, client->tv_sec, client->tv_usec);

#ifdef _DEBUG
    printf("[+] [client <- client] do_socks5_connection_client send socks response: %d bytes\n", sen);
#endif


    // forwarder [client <> client <> server <> target]
#ifdef _DEBUG
    printf("[+] [client <> client <> server <> target] do_socks5_connection_client forwarder_client\n");
#endif

    client->send_message_id++;
    forwarder_client(client);

#ifdef _DEBUG
    printf("[+] do_socks5_connection_client worker exit\n");
#endif

    close(client->client_sock);

exit:
    free(buffer);

    return;
}

void client_worker(struct stack_head *stack_client_worker)
{
    struct client_data *client = stack_client_worker->args;
    struct map_node_thread *thread_client_worker = NULL;

    do_socks5_connection_client(client);

    free_map_client_receive_message(client->m_client_receive_message, &client->sem_m_client_receive_message);
    free_queue(client->socks5_message_queue);
    delete_spider_node(tree_client, &sem_tree_client, client->client_id);

    thread_client_worker = search_map_node_thread(m_thread, stack_client_worker->thread_id);
    if(thread_client_worker != NULL)
    {
#ifdef _DEBUG
        printf("[+] client_worker is dead\n");
#endif

        thread_client_worker->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] client_worker cannot free stack\n");
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

void listen_client(struct stack_head *stack)
{
    struct client_data *client_listen = (struct client_data *)stack->args;
    struct map_node_thread *thread = NULL;

    int ret = 0;
    uint32_t connection_id = 0;
    uint32_t client_listen_id = 0;
    uint32_t client_id = 0;
    struct sockaddr_in client_listen_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_in6 client_listen_addr6;
    struct sockaddr_in6 client_addr6;
    uint16_t port_num = 0;
    uint32_t client_listen_sock = -1;
    uint32_t client_sock = -1;
    int reuse = 1;
    int flags = 0;
    int client_addr_length = 16;
    int client_addr6_length = sizeof(client_addr6);
    char *client_ip = NULL;
    char *client_ip_scope_id = NULL;
    char *client_port = NULL;

    memset((char *)&client_listen_addr, 0, sizeof(struct sockaddr_in));
    memset((char *)&client_addr, 0, sizeof(struct sockaddr_in));
    memset((char *)&client_listen_addr6, 0, sizeof(struct sockaddr_in6));
    memset((char *)&client_addr6, 0, sizeof(struct sockaddr_in6));

    if(strchr(client_listen->client_ip, ':') == NULL)   // ipv4
    {
        client_listen_addr.sin_family = AF_INET;

        ret = inet_pton(AF_INET, client_listen->client_ip, &client_listen_addr.sin_addr);
        if(ret == 0)
        {
            printf("[-] listen_client inet_pton error\n");

            free(client_listen);
            goto exit_0;
        }

        port_num = atoi(client_listen->client_listen_port);
        client_listen_addr.sin_port = htons(port_num);

        // socket
        client_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        reuse = 1;
        ret = setsockopt(client_listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

        // bind
        ret = bind(client_listen_sock, (sockaddr *)&client_listen_addr, client_addr_length);
        if(ret < 0)
        {
            printf("[-] listen_client bind error: %d\n", ret);

            free(client_listen);
            goto exit_0;
        }

        // listen
        listen(client_listen_sock, 5);

        printf("[+] listen_client listening ip: %s  port: %s\n", client_listen->client_ip, client_listen->client_listen_port);

        client_listen->client_sock = client_listen_sock;
        strcpy((char *)&client_listen->client_type, "socks5");

        connection_id = generate_random_id();
        client_listen->connection_id = connection_id;

        client_listen->server_id = 0;
        client_listen->encryption_flag = encryption_flag;
        client_listen->socks5_message_queue = NULL;

        do
        {
            client_listen_id = generate_random_id();
            client_listen->client_id = client_listen_id;
            ret = insert_spider_node(tree_client, &sem_tree_client, client_listen_id, client_listen);
        }while(ret != 0);

        while(1)
        {
            // accept
            client_sock = accept(client_listen_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_length);

            flags = fcntl(client_sock, F_GETFL, 0);
            flags &= ~O_NONBLOCK;
            fcntl(client_sock, F_SETFL, flags);

            client_data *client = (client_data *)calloc(1, sizeof(struct client_data));
            client_ip = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            client_port = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            if(client == NULL || client_ip == NULL || client_port == NULL)
            {
#ifdef _DEBUG
                printf("[-] listen_client calloc error\n");
#endif

                close(client_sock);
                continue;
            }

            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET6_ADDR_STRING_LENGTH + 1);
            sprintf(client_port, "%d", ntohs(client_addr.sin_port));

            client->client_sock = client_sock;
            client->connection_id = connection_id;
            client->client_id = 0;
            client->server_id = 0;
            strcpy(client->client_type, "socks5");
            strcpy(client->client_ip, client_ip);
            strcpy(client->client_port, client_port);
            strcpy(client->destination_spider_ip, client_listen->destination_spider_ip);
            client->tv_sec = client_listen->tv_sec;
            client->tv_usec = client_listen->tv_usec;
            client->forwarder_tv_sec = client_listen->forwarder_tv_sec;
            client->forwarder_tv_usec = client_listen->forwarder_tv_usec;
            client->encryption_flag = encryption_flag;
            client->socks5_message_queue = create_queue();
            create_map_client_receive_message(&client->m_client_receive_message, &client->sem_m_client_receive_message);

            free(client_ip);
            free(client_port);

            do
            {
                client_id = generate_random_id();
                client->client_id = client_id;
                ret = insert_spider_node(tree_client, &sem_tree_client, client_id, client);
            }while(ret != 0);

#ifdef _DEBUG
            printf("[+] listen_client connected ip: %s port: %s\n", client->client_ip, client->client_port);
#endif

            start_thread(m_thread, (void *)client_worker, (void *)client);
            millisleep(100);
        }
    }else   // ipv6
    {
        client_listen_addr6.sin6_family = AF_INET6;

        ret = inet_pton(AF_INET6, client_listen->client_ip, &client_listen_addr6.sin6_addr);
        if(ret == 0)
        {
            printf("[-] listen_client inet_pton error\n");

            free(client_listen);
            goto exit_0;
        }

        port_num = atoi(client_listen->client_listen_port);
        client_listen_addr6.sin6_port = htons(port_num);

        if(strlen(client_listen->client_ip_scope_id) > 0)
        {
            client_listen_addr6.sin6_scope_id = atoi(client_listen->client_ip_scope_id);
        }

        // socket
        client_listen_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        reuse = 1;
        ret = setsockopt(client_listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

        // bind
        ret = bind(client_listen_sock, (struct sockaddr *)&client_listen_addr6, sizeof(client_listen_addr6));
        if(ret == -1)
        {
            printf("[-] listen_client bind error: %d\n", ret);

            free(client_listen);
            goto exit_0;
        }

        // listen
        listen(client_listen_sock, 5);

        if(client_listen_addr6.sin6_scope_id > 0)
        {
            printf("[+] listen_client listening ip: %s%%%s port: %s\n", client_listen->client_ip, client_listen->client_ip_scope_id, client_listen->client_listen_port);
        }else
        {
            printf("[+] listen_client listening ip: %s port: %s\n", client_listen->client_ip, client_listen->client_listen_port);
        }

        client_listen->client_sock = client_listen_sock;
        strcpy((char *)&client_listen->client_type, "socks5");

        connection_id = generate_random_id();
        client_listen->connection_id = connection_id;

        client_listen->server_id = 0;
        client_listen->encryption_flag = encryption_flag;
        client_listen->socks5_message_queue = NULL;

        do
        {
            client_listen_id = generate_random_id();
            client_listen->client_id = client_listen_id;
            ret = insert_spider_node(tree_client, &sem_tree_client, client_listen_id, client_listen);
        }while(ret != 0);

        while(1)
        {
            // accept
            client_sock = accept(client_listen_sock, (struct sockaddr *)&client_addr6, (socklen_t *)&client_addr6_length);

            flags = fcntl(client_sock, F_GETFL, 0);
            flags &= ~O_NONBLOCK;
            fcntl(client_sock, F_SETFL, flags);

            client_data *client = (struct client_data *)calloc(1, sizeof(client_data));
            client_ip = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            client_ip_scope_id = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            client_port = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            if(client == NULL || client_ip == NULL || client_ip_scope_id == NULL || client_port == NULL)
            {
#ifdef _DEBUG
                printf("[-] listen_client calloc error\n");
#endif

                close(client_sock);
                continue;
            }

            inet_ntop(AF_INET6, &client_addr6.sin6_addr, client_ip, INET6_ADDR_STRING_LENGTH + 1);
            sprintf(client_ip_scope_id, "%d", client_addr6.sin6_scope_id);
            sprintf(client_port, "%d", ntohs(client_addr6.sin6_port));

            client->client_sock = client_sock;
            client->connection_id = connection_id;
            client->client_id = 0;
            client->server_id = 0;
            strcpy(client->client_type, "socks5");
            strcpy(client->client_ip, client_ip);
            strcpy(client->client_ip_scope_id, client_ip_scope_id);
            strcpy(client->client_port, client_port);
            strcpy(client->destination_spider_ip, client_listen->destination_spider_ip);
            client->tv_sec = client_listen->tv_sec;
            client->tv_usec = client_listen->tv_usec;
            client->forwarder_tv_sec = client_listen->forwarder_tv_sec;
            client->forwarder_tv_usec = client_listen->forwarder_tv_usec;
            client->encryption_flag = encryption_flag;
            client->socks5_message_queue = create_queue();
            create_map_client_receive_message(&client->m_client_receive_message, &client->sem_m_client_receive_message);

            free(client_ip);
            free(client_ip_scope_id);
            free(client_port);

            do
            {
                client_id = generate_random_id();
                client->client_id = client_id;
                ret = insert_spider_node(tree_client, &sem_tree_client, client_id, client);
            }while(ret != 0);

#ifdef _DEBUG
            if(client_addr6.sin6_scope_id > 0)
            {
                printf("[+] listen_client connected ip: %s%%%s port: %s\n", client->client_ip, client->client_ip_scope_id, client->client_port);
            }else
            {
                printf("[+] listen_client connected ip: %s port: %s\n", client->client_ip, client->client_port);
            }
#endif

            start_thread(m_thread, (void *)client_worker, (void *)client);
            millisleep(100);
        }
    }

exit_0:
    close(client_listen_sock);
    delete_spider_node(tree_client, &sem_tree_client, client_listen_id);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] listen_client is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] listen_client cannot free stack\n");
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

