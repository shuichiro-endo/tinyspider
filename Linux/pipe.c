/*
 * Title:  pipe.c
 * Author: Shuichiro Endo
 */

#include "pipe.h"

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
extern struct avlt_node_route *routing_table;
extern struct rbt_spider *tree_pipe;
extern struct semaphore sem_tree_pipe;

struct pipe_data *get_destination_pipe(const char *ip)
{
    struct avlt_node_route *route_node = NULL;
    struct route_data *route = NULL;
    struct rbt_node_spider *spider_node = NULL;

    route_node = search_route(routing_table, ip);
    if(route_node == NULL)
    {
        return NULL;
    }

    route = route_node->data;
    if(route->alive == 0)   // route is dead
    {
        return NULL;
    }

    spider_node = search_spider_node(tree_pipe, &sem_tree_pipe, route->pipe_id);
    if(spider_node == NULL)
    {
        return NULL;
    }

    return (struct pipe_data *)spider_node->data;
}

void push_routing_message_pipe(struct stack_head *stack)
{
    struct push_message_queue_function_args_pipe *args = stack->args;
    struct pipe_data *pipe = args->pipe;
    struct spider_message *message = args->message;
    struct map_node_thread *thread = NULL;

    free(args);

    if(pipe->routing_message_queue != NULL)
    {
        enqueue(pipe->routing_message_queue, (void *)message);
    }else
    {
#ifdef _DEBUG
        printf("[-] push_routing_message_pipe routing_message_queue is null\n");
#endif

        free(message);
    }

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_routing_message_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_routing_message_pipe cannot free stack\n");
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

void push_socks5_message_pipe(struct stack_head *stack)
{
    struct push_message_queue_function_args_pipe *args = stack->args;
    struct pipe_data *pipe = args->pipe;
    struct spider_message *message = args->message;
    struct map_node_thread *thread = NULL;

    free(args);

    if(pipe->socks5_message_queue != NULL)
    {
        enqueue(pipe->socks5_message_queue, (void *)message);
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message_pipe socks5_message_queue is null\n");
#endif

        free(message);
    }

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_socks5_message_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message_pipe cannot free stack\n");
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

struct spider_message *pop_routing_message_pipe_timeout(struct pipe_data *pipe, long tv_sec, long tv_usec)
{
    struct timeval start;
    struct timeval end;
    long t = 0;
    struct spider_message *routing_message = NULL;

    if(gettimeofday(&start, NULL) == -1)
    {
#ifdef _DEBUG
        printf("[-] pop_routing_message_pipe_timeout gettimeofday error\n");
#endif
        return NULL;
    }

    do
    {
        if(gettimeofday(&end, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] pop_routing_message_pipe_timeout gettimeofday error\n");
#endif
            return NULL;
        }

        t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
        if(t >= (tv_sec * 1000000 + tv_usec))
        {
#ifdef _DEBUG
            printf("[+] pop_routing_message_pipe_timeout timeout\n");
#endif

            return NULL;
        }

        millisleep(100);
    }while(pipe->routing_message_queue->count <= 0);

    routing_message = (struct spider_message *)dequeue(pipe->routing_message_queue);

    return routing_message;
}

struct spider_message *pop_socks5_message_pipe_timeout(struct pipe_data *pipe, long tv_sec, long tv_usec)
{
    struct timeval start;
    struct timeval end;
    long t = 0;
    struct spider_message *socks5_message = NULL;

    if(gettimeofday(&start, NULL) == -1)
    {
#ifdef _DEBUG
        printf("[-] pop_socks5_message_pipe_timeout gettimeofday error\n");
#endif
        return NULL;
    }

    do
    {
        if(gettimeofday(&end, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] pop_socks5_message_pipe_timeout gettimeofday error\n");
#endif
            return NULL;
        }

        t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
        if(t >= (tv_sec * 1000000 + tv_usec))
        {
#ifdef _DEBUG
            printf("[+] pop_socks5_message_pipe_timeout timeout\n");
#endif

            return NULL;
        }

        millisleep(100);
    }while(pipe->socks5_message_queue->count <= 0);

    socks5_message = (struct spider_message *)dequeue(pipe->socks5_message_queue);

    return socks5_message;
}

int recv_message(struct pipe_data *pipe)
{
    int ret = 0;
    int32_t rec = 0;
    int32_t tmprec = 0;
    struct fd_set readfds;
    int nfds = -1;
    struct timeval tv;
    long tv_sec = 3600;
    long tv_usec = 0;
    char *buffer = (char *)calloc(NODE_BUFFER_SIZE, sizeof(char));
    char *tmp = (char *)calloc(NODE_BUFFER_SIZE, sizeof(char));
    struct spider_message *s_message = NULL;
    struct spider_message *routing_message = NULL;
    struct spider_message *socks5_message = NULL;
    struct spider_message_header *s_header = NULL;
    int spider_message_header_size = sizeof(struct spider_message_header);
    bool recv_header_flag = false;
    int32_t recv_data_size = 0;
    int32_t remaining_size = 0;
    int32_t message_size = 0;
    char destination_node_type;
    uint32_t connection_id = 0;
    uint32_t client_id = 0;
    uint32_t server_id = 0;
    uint32_t pipe_id = 0;
    struct pipe_data *destination_pipe = NULL;
    struct push_message_queue_function_args_pipe *args = NULL;

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(pipe->pipe_sock, &readfds);
        nfds = pipe->pipe_sock + 1;
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(nfds, &readfds, NULL, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[+] recv_message select timeout\n");
#endif

            goto exit_0;
        }

        ret = FD_ISSET(pipe->pipe_sock, &readfds);
        if(ret > 0)
        {
            if(recv_header_flag == false)
            {
                tmprec = read(pipe->pipe_sock, tmp, spider_message_header_size);
            }else
            {
                tmprec = read(pipe->pipe_sock, tmp, remaining_size);
            }

            if(tmprec <= 0)
            {
                if(tmprec == EINTR)
                {
                    continue;
                }else if(tmprec == EAGAIN)
                {
                    millisleep(5);
                    continue;
                }else
                {
#ifdef _DEBUG
                    printf("[-] recv_message read error: %d\n", tmprec);
#endif

                    goto error;
                }
            }else
            {
                memcpy(buffer + rec, tmp, tmprec);
                rec += tmprec;

                memset(tmp, 0, NODE_BUFFER_SIZE);
                tmprec = 0;

#ifdef _DEBUG
//                printf("[+] recv_message pipe_id: %u rec: %d\n", pipe->pipe_id, rec);
//                print_bytes(buffer, rec);
#endif

                if(recv_header_flag == false)
                {
                    if(rec < spider_message_header_size)
                    {
                        remaining_size = spider_message_header_size - rec;
                        continue;
                    }else
                    {
                        recv_header_flag = true;

                        s_message = (struct spider_message *)buffer;

                        recv_data_size = ntohl(s_message->header.data_size);

                        remaining_size = recv_data_size;
                        if(remaining_size > 0)
                        {
                            continue;
                        }
                    }
                }

                if(recv_header_flag == true)
                {
                    if(rec < spider_message_header_size + recv_data_size)
                    {
                        remaining_size = spider_message_header_size + recv_data_size - rec;
                        continue;
                    }else
                    {
                        s_message = (struct spider_message *)buffer;
                        if(s_message->header.message_type == 'r')
                        {
                            message_size = spider_message_header_size + recv_data_size;

                            s_message->header.pipe_id = pipe->pipe_id;
                            s_message->header.data_size = recv_data_size;

                            routing_message = (struct spider_message *)calloc(message_size, sizeof(char));
                            memcpy(routing_message, s_message, message_size);

                            start_thread(m_thread, (void *)push_routing_message, (void *)routing_message);
                        }else if(s_message->header.message_type  == 's')
                        {
                            if(is_spider_ip(ip, (char *)&s_message->header.destination_ip))
                            {
                                message_size = spider_message_header_size + recv_data_size;

                                s_message->header.message_id = ntohl(s_message->header.message_id);
                                s_message->header.connection_id = ntohl(s_message->header.connection_id);
                                s_message->header.client_id = ntohl(s_message->header.client_id);
                                s_message->header.server_id = ntohl(s_message->header.server_id);
                                s_message->header.pipe_id = pipe->pipe_id;
                                s_message->header.tv_sec = ntohl(s_message->header.tv_sec);
                                s_message->header.tv_usec = ntohl(s_message->header.tv_usec);
                                s_message->header.forwarder_tv_sec = ntohl(s_message->header.forwarder_tv_sec);
                                s_message->header.forwarder_tv_usec = ntohl(s_message->header.forwarder_tv_usec);
                                s_message->header.data_size = (int32_t)recv_data_size;

                                socks5_message = (struct spider_message *)calloc(message_size, sizeof(char));
                                memcpy(socks5_message, s_message, message_size);

                                start_thread(m_thread, (void *)push_socks5_message, (void *)socks5_message);
                            }else
                            {
                                destination_pipe = get_destination_pipe((char *)&s_message->header.destination_ip);
                                if(destination_pipe != NULL)
                                {
                                    message_size = spider_message_header_size + recv_data_size;

                                    socks5_message = (struct spider_message *)calloc(message_size + 16, sizeof(char));
                                    memcpy(socks5_message, s_message, message_size);

                                    args = (struct push_message_queue_function_args_pipe *)calloc(1, sizeof(struct push_message_queue_function_args_pipe));
                                    args->pipe = destination_pipe;
                                    args->message = socks5_message;

                                    start_thread(m_thread, (void *)push_socks5_message_pipe, (void *)args);
                                }else
                                {
#ifdef _DEBUG
                                    printf("[-] recv_message cannot transfer pipe message\n");
#endif

                                    goto exit_0;
                                }
                            }
                        }else
                        {
#ifdef _DEBUG
                            printf("[-] recv_message message type error: %c\n", s_message->header.message_type);
#endif

                            goto exit_0;
                        }
                    }
                }
                break;
            }
        }
    }

exit_rec:
    free(tmp);
    free(buffer);

    return rec;

exit_0:
    free(tmp);
    free(buffer);

    return 0;

error:
    free(tmp);
    free(buffer);

    return -1;
}

int send_routing_message(struct pipe_data *pipe)
{
    int ret = 0;
    int32_t sen = 0;
    int32_t send_length = 0;
    int32_t length = 0;
    int32_t len = 0;
    struct fd_set readfds;
    struct fd_set writefds;
    int nfds = -1;
    struct timeval tv;
    long tv_sec = 3600;
    long tv_usec = 0;
    char *buffer = NULL;
    struct spider_message *routing_message = NULL;
    int spider_message_header_size = sizeof(struct spider_message_header);

//    routing_message = (struct spider_message *)pop_routing_message_pipe_timeout(pipe, tv_sec, tv_usec);
    routing_message = (struct spider_message *)dequeue(pipe->routing_message_queue);
    if(routing_message == NULL)
    {
        goto error;
    }

    length = spider_message_header_size + ntohl(routing_message->header.data_size);

    buffer = (char *)routing_message;
    len = length;

#ifdef _DEBUG
//    printf("[+] send_routing_message pipe_id: %u len: %d\n", pipe->pipe_id, len);
//    print_bytes(buffer, len);
#endif

    while(len > 0)
    {
        FD_ZERO(&writefds);
        FD_SET(pipe->pipe_sock, &writefds);
        nfds = pipe->pipe_sock + 1;
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(nfds, NULL, &writefds, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[+] send_routing_message select timeout\n");
#endif

            goto exit_0;
        }

        ret = FD_ISSET(pipe->pipe_sock, &writefds);
        if(ret > 0)
        {
            sen = write(pipe->pipe_sock, buffer + send_length, len);
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
                    printf("[-] send_routing_message send error: %d\n", sen);
#endif

                    goto error;
                }
            }

            send_length += sen;
            len -= sen;
        }
    }

    if(routing_message != NULL)
    {
        free(routing_message);
    }

    return length;

exit_0:
    if(routing_message != NULL)
    {
        free(routing_message);
    }

    return 0;

error:
    if(routing_message != NULL)
    {
        free(routing_message);
    }

    return -1;
}

int send_socks5_message(struct pipe_data *pipe)
{
    int ret = 0;
    int32_t sen = 0;
    int32_t send_length = 0;
    int32_t length = 0;
    int32_t len = 0;
    struct fd_set readfds;
    struct fd_set writefds;
    int nfds = -1;
    struct timeval tv;
    long tv_sec = 3600;
    long tv_usec = 0;
    char *buffer = NULL;
    struct spider_message *socks5_message = NULL;
    int spider_message_header_size = sizeof(spider_message_header);

//    socks5_message = (struct spider_message *)pop_socks5_message_pipe_timeout(pipe, tv_sec, tv_usec);
    socks5_message = (struct spider_message *)dequeue(pipe->socks5_message_queue);
    if(socks5_message == NULL)
    {
        goto error;
    }

    buffer = (char *)socks5_message;
    length = spider_message_header_size + ntohl(socks5_message->header.data_size);

    len = length;

#ifdef _DEBUG
//    printf("[+] send_socks5_message pipe_id: %u len: %d\n", pipe->pipe_id, len);
//    print_bytes(buffer, len);
#endif

    while(len > 0)
    {
        FD_ZERO(&writefds);
        FD_SET(pipe->pipe_sock, &writefds);
        nfds = pipe->pipe_sock + 1;
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(nfds, NULL, &writefds, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[+] send_socks5_message select timeout\n");
#endif

            goto exit_0;
        }

        ret = FD_ISSET(pipe->pipe_sock, &writefds);
        if(ret > 0)
        {
            sen = write(pipe->pipe_sock, buffer + send_length, len);
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
                    printf("[-] send_socks5_message send error: %d\n", sen);
#endif

                    goto error;
                }
            }

            send_length += sen;
            len -= sen;
        }
    }

    if(socks5_message != NULL)
    {
        free(socks5_message);
    }

    return length;

exit_0:
    if(socks5_message != NULL)
    {
        free(socks5_message);
    }

    return 0;

error:
    if(socks5_message != NULL)
    {
        free(socks5_message);
    }

    return -1;
}

void pipe_recv_message(struct stack_head *stack)
{
    struct pipe_data *pipe = stack->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;

    while(1)
    {
        ret = recv_message(pipe);
        if(ret < 0)
        {
            break;
        }
    }

    __asm__ __volatile__
    (
        "lock\n"
        "incl %0"
        : "=m"(stack->join_futex)
        : "m"(stack->join_futex)
        : "cc"
    );

    futex_wake(&stack->join_futex, 1);

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

void pipe_send_routing_message(struct stack_head *stack)
{
    struct pipe_data *pipe = stack->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;

    while(1)
    {
        ret = send_routing_message(pipe);
        if(ret < 0)
        {
            break;
        }
    }

    __asm__ __volatile__
    (
        "lock\n"
        "incl %0"
        : "=m"(stack->join_futex)
        : "m"(stack->join_futex)
        : "cc"
    );

    futex_wake(&stack->join_futex, 1);

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

void pipe_send_socks5_message(struct stack_head *stack)
{
    struct pipe_data *pipe = stack->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;

    while(1)
    {
        ret = send_socks5_message(pipe);
        if(ret < 0)
        {
            break;
        }
    }

    __asm__ __volatile__
    (
        "lock\n"
        "incl %0"
        : "=m"(stack->join_futex)
        : "m"(stack->join_futex)
        : "cc"
    );

    futex_wake(&stack->join_futex, 1);

    __asm__ __volatile__
    (
        "movq $0, %rdi\n"
        "movq $60, %rax\n"
        "syscall"
    );

    __builtin_unreachable();
}

void pipe_worker(struct stack_head *stack_pipe_worker)
{
    struct pipe_data *pipe = stack_pipe_worker->args;
    struct stack_head *stack_pipe_recv_message = NULL;
    struct stack_head *stack_pipe_send_routing_message = NULL;
    struct stack_head *stack_pipe_send_socks5_message = NULL;
    struct map_node_thread *thread_pipe_worker = NULL;
    struct map_node_thread *thread_pipe_recv_message = NULL;
    struct map_node_thread *thread_pipe_send_routing_message = NULL;
    struct map_node_thread *thread_pipe_send_socks5_message = NULL;
    uint32_t pipe_id = pipe->pipe_id;

    stack_pipe_recv_message = start_thread(m_thread, (void *)pipe_recv_message, (void *)pipe);
    millisleep(100);

    stack_pipe_send_routing_message = start_thread(m_thread, (void *)pipe_send_routing_message, (void *)pipe);
    millisleep(100);

    stack_pipe_send_socks5_message = start_thread(m_thread, (void *)pipe_send_socks5_message, (void *)pipe);
    millisleep(100);

    futex_wait(&stack_pipe_recv_message->join_futex, 0);

    pipe->routing_message_queue->finish = true;
    pipe->routing_message_queue->count++;
    futex_wake(&pipe->routing_message_queue->count, 1);
    futex_wait(&stack_pipe_send_routing_message->join_futex, 0);

    pipe->socks5_message_queue->finish = true;
    pipe->socks5_message_queue->count++;
    futex_wake(&pipe->socks5_message_queue->count, 1);
    futex_wait(&stack_pipe_send_socks5_message->join_futex, 0);

    thread_pipe_recv_message = search_map_node_thread(m_thread, stack_pipe_recv_message->thread_id);
    if(thread_pipe_recv_message != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_recv_message is dead\n");
#endif

        thread_pipe_recv_message->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_recv_message cannot free stack\n");
#endif
    }

    thread_pipe_send_routing_message = search_map_node_thread(m_thread, stack_pipe_send_routing_message->thread_id);
    if(thread_pipe_send_routing_message != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_send_routing_message is dead\n");
#endif

        thread_pipe_send_routing_message->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_send_routing_message cannot free stack\n");
#endif
    }

    thread_pipe_send_socks5_message = search_map_node_thread(m_thread, stack_pipe_send_socks5_message->thread_id);
    if(thread_pipe_send_socks5_message != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_send_socks5_message is dead\n");
#endif

        thread_pipe_send_socks5_message->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_send_socks5_message cannot free stack\n");
#endif
    }

    close(pipe->pipe_sock);
    free_queue(pipe->routing_message_queue);
    free_queue(pipe->socks5_message_queue);
    delete_spider_node(tree_pipe, &sem_tree_pipe, pipe->pipe_id);

    register_dead_route(routing_table, pipe_id);
    send_routing_table();

    thread_pipe_worker = search_map_node_thread(m_thread, stack_pipe_worker->thread_id);
    if(thread_pipe_worker != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_worker is dead\n");
#endif

        thread_pipe_worker->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_worker cannot free stack\n");
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

bool check_pipe(uint32_t pipe_id)
{
    bool ret = false;
    struct rbt_node_spider *node = NULL;

    node = search_spider_node(tree_pipe, &sem_tree_pipe, pipe_id);
    if(node != NULL)
    {
        ret = true;
    }

    return ret;
}

void connect_pipe(struct stack_head *stack)
{
    struct pipe_data *pipe = stack->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;
    uint32_t pipe_id = 0;
    struct sockaddr_in pipe_dest_addr;
    struct sockaddr_in6 pipe_dest_addr6;
    uint16_t port_num = 0;
    uint32_t pipe_sock = -1;
    int reuse = 1;
    int flags = 0;
    int pipe_dest_addr_length = 16;
    int pipe_dest_addr6_length = sizeof(pipe_dest_addr6);
    char *pipe_destination_ip_scope_id = NULL;

    memset((char *)&pipe_dest_addr, 0, sizeof(struct sockaddr_in));
    memset((char *)&pipe_dest_addr6, 0, sizeof(struct sockaddr_in6));

    if(strchr(pipe->pipe_destination_ip, ':') == NULL)  // ipv4
    {
        pipe_dest_addr.sin_family = AF_INET;

        ret = inet_pton(AF_INET, pipe->pipe_destination_ip, &pipe_dest_addr.sin_addr);
        if(ret == 0)
        {
            printf("[-] connect_pipe inet_pton error\n");

            free(pipe);
            goto exit_0;
        }

        port_num = atoi(pipe->pipe_destination_port);
        pipe_dest_addr.sin_port = htons(port_num);

        // socket
        pipe_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        flags = fcntl(pipe_sock, F_GETFL, 0);
        flags &= ~O_NONBLOCK;
        fcntl(pipe_sock, F_SETFL, flags);

        printf("[+] connect_pipe connecting ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);

        // connect
        ret = connect(pipe_sock, (struct sockaddr *)&pipe_dest_addr, pipe_dest_addr_length);
        if(ret < 0)
        {
            printf("[-] connect_pipe connect failed: %d\n", ret);

            close(pipe_sock);
            free(pipe);
            goto exit_0;
        }

        printf("[+] connect_pipe connected ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);
    }else   // ipv6
    {
        pipe_dest_addr6.sin6_family = AF_INET6;

        ret = inet_pton(AF_INET6, pipe->pipe_destination_ip, &pipe_dest_addr6.sin6_addr);
        if(ret == 0)
        {
            printf("[-] connect_pipe inet_pton error\n");

            free(pipe);
            goto exit_0;
        }

        port_num = atoi(pipe->pipe_destination_port);
        pipe_dest_addr6.sin6_port = htons(port_num);

        if(strlen(pipe->pipe_destination_ip_scope_id) > 0)
        {
            pipe_dest_addr6.sin6_scope_id = atoi(pipe->pipe_destination_ip_scope_id);
        }

        // socket
        pipe_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

        flags = fcntl(pipe_sock, F_GETFL, 0);
        flags &= ~O_NONBLOCK;
        fcntl(pipe_sock, F_SETFL, flags);

        if(pipe_dest_addr6.sin6_scope_id > 0)
        {
            printf("[+] connect_pipe connecting ip: %s%%%s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_ip_scope_id, pipe->pipe_destination_port);
        }else
        {
            printf("[+] connect_pipe connecting ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);
        }

        // connect
        ret = connect(pipe_sock, (struct sockaddr *)&pipe_dest_addr6, pipe_dest_addr6_length);
        if(ret < 0)
        {
            printf("[-] connect_pipe connect failed: %d\n", ret);

            close(pipe_sock);
            free(pipe);
            goto exit_0;
        }

        if(pipe_dest_addr6.sin6_scope_id > 0)
        {
            printf("[+] connect_pipe connected ip: %s%%%s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_ip_scope_id, pipe->pipe_destination_port);
        }else
        {
            printf("[+] connect_pipe connected ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);
        }
    }

    pipe->pipe_sock = pipe_sock;
    pipe->routing_message_queue = create_queue();
    pipe->socks5_message_queue = create_queue();

    do
    {
        pipe_id = generate_random_id();
        pipe->pipe_id = pipe_id;
        ret = insert_spider_node(tree_pipe, &sem_tree_pipe, pipe_id, pipe);
    }while(ret != 0);

    send_routing_table();

    start_thread(m_thread, (void *)pipe_worker, (void *)pipe);
    millisleep(100);

exit_0:
    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] connect_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] connect_pipe cannot free stack\n");
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

void listen_pipe(struct stack_head *stack)
{
    struct pipe_data *pipe_listen = (pipe_data *)stack->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;
    uint32_t pipe_listen_id = 0;
    uint32_t pipe_id = 0;
    struct sockaddr_in pipe_listen_addr;
    struct sockaddr_in pipe_addr;
    struct sockaddr_in6 pipe_listen_addr6;
    struct sockaddr_in6 pipe_addr6;
    uint16_t port_num = 0;
    uint32_t pipe_listen_sock = -1;
    uint32_t pipe_sock = -1;
    int reuse = 1;
    int flags = 0;
    int pipe_addr_length = 16;
    int pipe_addr6_length = sizeof(pipe_addr6);
    char *pipe_destination_ip = NULL;
    char *pipe_destination_ip_scope_id = NULL;
    char *pipe_destination_port = NULL;

    memset((char *)&pipe_listen_addr, 0, sizeof(struct sockaddr_in));
    memset((char *)&pipe_addr, 0, sizeof(struct sockaddr_in));
    memset((char *)&pipe_listen_addr6, 0, sizeof(struct sockaddr_in6));
    memset((char *)&pipe_addr6, 0, sizeof(struct sockaddr_in6));

    if(strchr(pipe_listen->pipe_ip, ':') == NULL)   // ipv4
    {
        pipe_listen_addr.sin_family = AF_INET;

        ret = inet_pton(AF_INET, pipe_listen->pipe_ip, &pipe_listen_addr.sin_addr);
        if(ret == 0)
        {
            printf("[-] listen_pipe inet_pton error\n");

            goto exit_0;
        }

        port_num = atoi(pipe_listen->pipe_listen_port);
        pipe_listen_addr.sin_port = htons(port_num);

        // socket
        pipe_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        reuse = 1;
        ret = setsockopt(pipe_listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

        // bind
        ret = bind(pipe_listen_sock, (struct sockaddr *)&pipe_listen_addr, pipe_addr_length);
        if(ret < 0)
        {
            printf("[-] listen_pipe bind error: %d\n", ret);

            goto exit_0;
        }

        // listen
        listen(pipe_listen_sock, 5);

        printf("[+] listen_pipe listening ip: %s  port: %s\n", pipe_listen->pipe_ip, pipe_listen->pipe_listen_port);

        pipe_listen->pipe_sock = pipe_listen_sock;
        pipe_listen->routing_message_queue = NULL;
        pipe_listen->socks5_message_queue = NULL;

        do
        {
            pipe_listen_id = generate_random_id();
            pipe_listen->pipe_id = pipe_listen_id;
            ret = insert_spider_node(tree_pipe, &sem_tree_pipe, pipe_listen_id, pipe_listen);
        }while(ret != 0);

        while(1)
        {
            // accept
            pipe_sock = accept(pipe_listen_sock, (struct sockaddr *)&pipe_addr, (socklen_t *)&pipe_addr_length);

            if(pipe_id != 0 && check_pipe(pipe_id))
            {
                close(pipe_sock);
                continue;
            }

            flags = fcntl(pipe_sock, F_GETFL, 0);
            flags &= ~O_NONBLOCK;
            fcntl(pipe_sock, F_SETFL, flags);

            pipe_data *pipe = (pipe_data *)calloc(1, sizeof(struct pipe_data));
            pipe_destination_ip = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            pipe_destination_port = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            if(pipe == NULL || pipe_destination_ip == NULL || pipe_destination_port == NULL)
            {
#ifdef _DEBUG
                printf("[-] listen_pipe calloc error\n");
#endif

                close(pipe_sock);
                continue;
            }

            inet_ntop(AF_INET, &pipe_addr.sin_addr, pipe_destination_ip, INET6_ADDR_STRING_LENGTH + 1);
            sprintf(pipe_destination_port, "%d", ntohs(pipe_addr.sin_port));

            pipe->pipe_sock = pipe_sock;
            strcpy(pipe->pipe_mode, "-");
            strcpy(pipe->pipe_ip, pipe_listen->pipe_ip);
            strcpy(pipe->pipe_destination_ip, pipe_destination_ip);
            strcpy(pipe->pipe_destination_port, pipe_destination_port);
            pipe->routing_message_queue = create_queue();
            pipe->socks5_message_queue = create_queue();

            free(pipe_destination_ip);
            free(pipe_destination_port);

            do
            {
                pipe_id = generate_random_id();
                pipe->pipe_id = pipe_id;
                ret = insert_spider_node(tree_pipe, &sem_tree_pipe, pipe_id, pipe);
            }while(ret != 0);

#ifdef _DEBUG
            printf("[+] listen_pipe connected ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);
#endif

            send_routing_table();

            start_thread(m_thread, (void *)pipe_worker, (void *)pipe);
            millisleep(100);
        }
    }else   // ipv6
    {
        pipe_listen_addr6.sin6_family = AF_INET6;

        ret = inet_pton(AF_INET6, pipe_listen->pipe_ip, &pipe_listen_addr6.sin6_addr);
        if(ret == 0)
        {
            printf("[-] listen_pipe inet_pton error\n");

            goto exit_0;
        }

        port_num = atoi(pipe_listen->pipe_listen_port);
        pipe_listen_addr6.sin6_port = htons(port_num);

        if(strlen(pipe_listen->pipe_ip_scope_id) > 0)
        {
            pipe_listen_addr6.sin6_scope_id = atoi(pipe_listen->pipe_ip_scope_id);
        }

        // socket
        pipe_listen_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        reuse = 1;
        ret = setsockopt(pipe_listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

        // bind
        ret = bind(pipe_listen_sock, (struct sockaddr *)&pipe_listen_addr6, sizeof(pipe_listen_addr6));
        if(ret == -1)
        {
            printf("[-] listen_pipe bind error: %d\n", ret);

            goto exit_0;
        }

        // listen
        listen(pipe_listen_sock, 5);

        if(pipe_listen_addr6.sin6_scope_id > 0)
        {
            printf("[+] listen_pipe listening ip:  %s%%%s port: %s\n", pipe_listen->pipe_ip, pipe_listen->pipe_ip_scope_id, pipe_listen->pipe_listen_port);
        }else
        {
            printf("[+] listen_pipe listening ip: %s port: %s\n", pipe_listen->pipe_ip, pipe_listen->pipe_listen_port);
        }

        pipe_listen->pipe_sock = pipe_listen_sock;
        pipe_listen->routing_message_queue = NULL;
        pipe_listen->socks5_message_queue = NULL;

        do
        {
            pipe_listen_id = generate_random_id();
            pipe_listen->pipe_id = pipe_listen_id;
            ret = insert_spider_node(tree_pipe, &sem_tree_pipe, pipe_listen_id, pipe_listen);
        }while(ret != 0);

        while(1)
        {
            // accept
            pipe_sock = accept(pipe_listen_sock, (struct sockaddr *)&pipe_addr6, (socklen_t *)&pipe_addr6_length);

            if(pipe_id != 0 && check_pipe(pipe_id))
            {
                close(pipe_sock);
                continue;
            }

            flags = fcntl(pipe_sock, F_GETFL, 0);
            flags &= ~O_NONBLOCK;
            fcntl(pipe_sock, F_SETFL, flags);

            pipe_data *pipe = (pipe_data *)calloc(1, sizeof(struct pipe_data));
            pipe_destination_ip = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            pipe_destination_ip_scope_id = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            pipe_destination_port = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            if(pipe == NULL || pipe_destination_ip == NULL || pipe_destination_ip_scope_id == NULL || pipe_destination_port == NULL)
            {
#ifdef _DEBUG
                printf("[-] listen_pipe calloc error\n");
#endif

                close(pipe_sock);
                continue;
            }

            inet_ntop(AF_INET6, &pipe_addr6.sin6_addr, pipe_destination_ip, INET6_ADDR_STRING_LENGTH + 1);
            sprintf(pipe_destination_ip_scope_id, "%d", pipe_addr6.sin6_scope_id);
            sprintf(pipe_destination_port, "%d", ntohs(pipe_addr6.sin6_port));

            pipe->pipe_sock = pipe_sock;
            strcpy(pipe->pipe_mode, "-");
            strcpy(pipe->pipe_ip, pipe_listen->pipe_ip);
            strcpy(pipe->pipe_ip_scope_id, pipe_listen->pipe_ip_scope_id);
            strcpy(pipe->pipe_destination_ip, pipe_destination_ip);
            strcpy(pipe->pipe_destination_ip_scope_id, pipe_destination_ip_scope_id);
            strcpy(pipe->pipe_destination_port, pipe_destination_port);
            pipe->routing_message_queue = create_queue();
            pipe->socks5_message_queue = create_queue();

            free(pipe_destination_ip);
            free(pipe_destination_ip_scope_id);
            free(pipe_destination_port);

            do
            {
                pipe_id = generate_random_id();
                pipe->pipe_id = pipe_id;
                ret = insert_spider_node(tree_pipe, &sem_tree_pipe, pipe_id, pipe);
            }while(ret != 0);

#ifdef _DEBUG
            if(pipe_addr6.sin6_scope_id > 0)
            {
                printf("[+] listen_pipe connected ip: %s%%%s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_ip_scope_id, pipe->pipe_destination_port);
            }else
            {
                printf("[+] listen_pipe connected ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);
            }
#endif

            send_routing_table();

            start_thread(m_thread, (void *)pipe_worker, (void *)pipe);
            millisleep(100);
        }
    }

exit_0:
    close(pipe_listen_sock);
    delete_spider_node(tree_pipe, &sem_tree_pipe, pipe_listen_id);

    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] listen_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] listen_pipe cannot free stack\n");
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

