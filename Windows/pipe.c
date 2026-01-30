/*
 * Title:  pipe.c
 * Author: Shuichiro Endo
 */

#include "pipe.h"

extern _WSAGetLastError WSAGetLastError;
extern _select select;
extern _socket socket;
extern _setsockopt setsockopt;
extern _bind bind;
extern _listen listen;
extern _accept accept;
extern _connect connect;
extern _recv recv;
extern _send send;
extern _closesocket closesocket;

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
extern struct avlt_node_route *routing_table;
extern struct rbt_spider *tree_pipe;
extern HANDLE mutex_tree_pipe;

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

    spider_node = search_spider_node(tree_pipe, mutex_tree_pipe, route->pipe_id);
    if(spider_node == NULL)
    {
        return NULL;
    }

    return (struct pipe_data *)spider_node->data;
}

void push_routing_message_pipe(struct function_args *args)
{
    struct push_message_queue_args_pipe *push_message_queue_args_pipe = args->args;
    struct pipe_data *pipe = push_message_queue_args_pipe->pipe;
    struct spider_message *message = push_message_queue_args_pipe->message;
    struct map_node_thread *thread = NULL;

    free(push_message_queue_args_pipe);

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

    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_routing_message_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_routing_message_pipe cannot close handle\n");
#endif
    }

    free(args);
}

void push_socks5_message_pipe(struct function_args *args)
{
    struct push_message_queue_args_pipe *push_message_queue_args_pipe = args->args;
    struct pipe_data *pipe = push_message_queue_args_pipe->pipe;
    struct spider_message *message = push_message_queue_args_pipe->message;
    struct map_node_thread *thread = NULL;

    free(push_message_queue_args_pipe);

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

    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_socks5_message_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message_pipe cannot close handle\n");
#endif
    }

    free(args);
}

struct spider_message *pop_routing_message_pipe_timeout(struct pipe_data *pipe, long long tv_sec, long long tv_usec)
{
    struct timeval start;
    struct timeval end;
    long long t = 0;
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

struct spider_message *pop_socks5_message_pipe_timeout(struct pipe_data *pipe, long long tv_sec, long long tv_usec)
{
    struct timeval start;
    struct timeval end;
    long long t = 0;
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
    int32_t err = 0;
    int32_t tmprec = 0;
    struct fd_set readfds;
    struct timeval tv;
    long long tv_sec = 3600;
    long long tv_usec = 0;
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
    struct function_args *function_args = NULL;
    struct push_message_queue_args_pipe *push_message_queue_args_pipe = NULL;

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(pipe->pipe_sock, &readfds);
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(0, &readfds, NULL, NULL, &tv);
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
                tmprec = recv(pipe->pipe_sock, tmp, spider_message_header_size, 0);
            }else
            {
                tmprec = recv(pipe->pipe_sock, tmp, remaining_size, 0);
            }

            if(tmprec == SOCKET_ERROR)
            {
                err = WSAGetLastError();
                if(err == WSAEWOULDBLOCK)
                {
                    millisleep(5);
                    continue;
                }
#ifdef _DEBUG
                printf("[-] recv_message recv error: %d\n", err);
#endif

                goto error;
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

                            function_args = (struct function_args *)calloc(1, sizeof(function_args));
                            function_args->args = (void *)routing_message;
                            start_thread(m_thread, (void *)push_routing_message, (void *)function_args);
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

                                function_args = (struct function_args *)calloc(1, sizeof(function_args));
                                function_args->args = (void *)socks5_message;
                                start_thread(m_thread, (void *)push_socks5_message, (void *)function_args);
                            }else
                            {
                                destination_pipe = get_destination_pipe((char *)&s_message->header.destination_ip);
                                if(destination_pipe != NULL)
                                {
                                    message_size = spider_message_header_size + recv_data_size;

                                    socks5_message = (struct spider_message *)calloc(message_size + 16, sizeof(char));
                                    memcpy(socks5_message, s_message, message_size);

                                    push_message_queue_args_pipe = (struct push_message_queue_args_pipe *)calloc(1, sizeof(struct push_message_queue_args_pipe));
                                    push_message_queue_args_pipe->pipe = destination_pipe;
                                    push_message_queue_args_pipe->message = socks5_message;

                                    function_args = (struct function_args *)calloc(1, sizeof(function_args));
                                    function_args->args = (void *)push_message_queue_args_pipe;
                                    start_thread(m_thread, (void *)push_socks5_message_pipe, (void *)function_args);
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
    int32_t err = 0;
    int32_t send_length = 0;
    int32_t length = 0;
    int32_t len = 0;
    struct fd_set readfds;
    struct fd_set writefds;
    struct timeval tv;
    long long tv_sec = 3600;
    long long tv_usec = 0;
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
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(0, NULL, &writefds, NULL, &tv);
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
            sen = send(pipe->pipe_sock, buffer + send_length, len, 0);
            if(sen == SOCKET_ERROR)
            {
                err = WSAGetLastError();
                if(err == WSAEWOULDBLOCK)
                {
                    millisleep(5);
                    continue;
                }
#ifdef _DEBUG
                printf("[-] send_routing_message send error: %d\n", err);
#endif

                goto error;
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
    int32_t err = 0;
    int32_t send_length = 0;
    int32_t length = 0;
    int32_t len = 0;
    struct fd_set readfds;
    struct fd_set writefds;
    struct timeval tv;
    long long tv_sec = 3600;
    long long tv_usec = 0;
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
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(0, NULL, &writefds, NULL, &tv);
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
            sen = send(pipe->pipe_sock, buffer + send_length, len, 0);
            if(sen == SOCKET_ERROR)
            {
                err = WSAGetLastError();
                if(err == WSAEWOULDBLOCK)
                {
                    millisleep(5);
                    continue;
                }
#ifdef _DEBUG
                printf("[-] send_socks5_message send error: %d\n", err);
#endif

                goto error;
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

void pipe_recv_message(struct function_args *args)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct pipe_recv_message_args *pipe_recv_message_args = args->args;
    struct pipe_data *pipe = pipe_recv_message_args->pipe;
    struct map_node_thread *thread = NULL;
    int ret = 0;

    status = NtWaitForSingleObject(pipe_recv_message_args->mutex_pipe_recv_message, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_recv_message NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    while(1)
    {
        ret = recv_message(pipe);
        if(ret < 0)
        {
            break;
        }
    }

    status = NtReleaseMutant(pipe_recv_message_args->mutex_pipe_recv_message, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_recv_message NtReleaseMutant error: %x\n", status);
#endif
        goto error;
    }

error:
    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_recv_message is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_recv_message cannot close handle\n");
#endif
    }

    free(pipe_recv_message_args);
    free(args);
}

void pipe_send_routing_message(struct function_args *args)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct pipe_send_routing_message_args *pipe_send_routing_message_args = args->args;
    struct pipe_data *pipe = pipe_send_routing_message_args->pipe;;
    struct map_node_thread *thread = NULL;
    int ret = 0;

    status = NtWaitForSingleObject(pipe_send_routing_message_args->mutex_pipe_send_routing_message, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_send_routing_message NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    while(1)
    {
        ret = send_routing_message(pipe);
        if(ret < 0)
        {
            break;
        }
    }

    status = NtReleaseMutant(pipe_send_routing_message_args->mutex_pipe_send_routing_message, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_send_routing_message NtReleaseMutant error: %x\n", status);
#endif
        goto error;
    }

error:
    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_send_routing_message is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_send_routing_message cannot close handle\n");
#endif
    }

    free(pipe_send_routing_message_args);
    free(args);
}

void pipe_send_socks5_message(struct function_args *args)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct pipe_send_socks5_message_args *pipe_send_socks5_message_args = args->args;
    struct pipe_data *pipe = pipe_send_socks5_message_args->pipe;
    struct map_node_thread *thread = NULL;
    int ret = 0;

    status = NtWaitForSingleObject(pipe_send_socks5_message_args->mutex_pipe_send_socks5_message, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_send_socks5_message NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    while(1)
    {
        ret = send_socks5_message(pipe);
        if(ret < 0)
        {
            break;
        }
    }

    status = NtReleaseMutant(pipe_send_socks5_message_args->mutex_pipe_send_socks5_message, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_send_socks5_message NtReleaseMutant error: %x\n", status);
#endif
        goto error;
    }

error:
    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_send_socks5_message is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_send_socks5_message cannot close handle\n");
#endif
    }

    free(pipe_send_socks5_message_args);
    free(args);
}

void pipe_worker(struct function_args *args)
{
    NTSTATUS status;
    LONG previousCount_semaphore = 0;
    LONG previousCount_mutex = 0;
    struct pipe_data *pipe = (struct pipe_data *)args->args;
    struct map_node_thread *thread_pipe_worker = NULL;
    struct map_node_thread *thread_pipe_recv_message = NULL;
    struct map_node_thread *thread_pipe_send_routing_message = NULL;
    struct map_node_thread *thread_pipe_send_socks5_message = NULL;
    uint32_t pipe_id = pipe->pipe_id;
    HANDLE mutex_pipe_recv_message = NULL;
    HANDLE mutex_pipe_send_routing_message = NULL;
    HANDLE mutex_pipe_send_socks5_message = NULL;
    struct pipe_recv_message_args *pipe_recv_message_args = NULL;
    struct pipe_send_routing_message_args *pipe_send_routing_message_args = NULL;
    struct pipe_send_socks5_message_args *pipe_send_socks5_message_args = NULL;
    struct function_args *pipe_recv_message_function_args = NULL;
    struct function_args *pipe_send_routing_message_function_args = NULL;
    struct function_args *pipe_send_socks5_message_function_args = NULL;

    status = NtCreateMutant(&mutex_pipe_recv_message, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_worker NtCreateMutant error: %x\n", status);
#endif
        return;
    }

    status = NtCreateMutant(&mutex_pipe_send_routing_message, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_worker NtCreateMutant error: %x\n", status);
#endif
        NtClose(mutex_pipe_recv_message);
        return;
    }

    status = NtCreateMutant(&mutex_pipe_send_socks5_message, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_worker NtCreateMutant error: %x\n", status);
#endif
        NtClose(mutex_pipe_recv_message);
        NtClose(mutex_pipe_send_routing_message);
        return;
    }

    pipe_recv_message_args = (struct pipe_recv_message_args *)calloc(1, sizeof(struct pipe_recv_message_args));
    pipe_recv_message_args->pipe = pipe;
    pipe_recv_message_args->mutex_pipe_recv_message = mutex_pipe_recv_message;

    pipe_recv_message_function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
    pipe_recv_message_function_args->args = (void *)pipe_recv_message_args;
    start_thread(m_thread, (void *)pipe_recv_message, (void *)pipe_recv_message_function_args);

    pipe_send_routing_message_args = (struct pipe_send_routing_message_args *)calloc(1, sizeof(pipe_send_routing_message_args));
    pipe_send_routing_message_args->pipe = pipe;
    pipe_send_routing_message_args->mutex_pipe_send_routing_message = mutex_pipe_send_routing_message;

    pipe_send_routing_message_function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
    pipe_send_routing_message_function_args->args = (void *)pipe_send_routing_message_args;
    start_thread(m_thread, (void *)pipe_send_routing_message, (void *)pipe_send_routing_message_function_args);

    pipe_send_socks5_message_args = (struct pipe_send_socks5_message_args *)calloc(1, sizeof(struct pipe_send_socks5_message_args));
    pipe_send_socks5_message_args->pipe = pipe;
    pipe_send_socks5_message_args->mutex_pipe_send_socks5_message = mutex_pipe_send_socks5_message;

    pipe_send_socks5_message_function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
    pipe_send_socks5_message_function_args->args = (void *)pipe_send_socks5_message_args;
    start_thread(m_thread, (void *)pipe_send_socks5_message, (void *)pipe_send_socks5_message_function_args);

    millisleep(1000);

    status = NtWaitForSingleObject(mutex_pipe_recv_message, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_worker NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    pipe->routing_message_queue->finish = true;
    status = NtReleaseSemaphore(pipe->routing_message_queue->semaphore, 1, &previousCount_semaphore);
    status = NtReleaseMutant(pipe->routing_message_queue->mutex, &previousCount_mutex);

    status = NtWaitForSingleObject(mutex_pipe_send_routing_message, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_worker NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    pipe->socks5_message_queue->finish = true;
    status = NtReleaseSemaphore(pipe->socks5_message_queue->semaphore, 1, &previousCount_semaphore);
    status = NtReleaseMutant(pipe->socks5_message_queue->mutex, &previousCount_mutex);

    status = NtWaitForSingleObject(mutex_pipe_send_socks5_message, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] pipe_worker NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    closesocket(pipe->pipe_sock);

    free_queue(pipe->routing_message_queue);
    free_queue(pipe->socks5_message_queue);

    delete_spider_node(tree_pipe, mutex_tree_pipe, pipe->pipe_id);

    register_dead_route(routing_table, pipe_id);
    send_routing_table();

error:
    thread_pipe_worker = search_map_node_thread(m_thread, args->handle);
    if(thread_pipe_worker != NULL)
    {
#ifdef _DEBUG
        printf("[+] pipe_worker is dead\n");
#endif

        thread_pipe_worker->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] pipe_worker cannot close handle\n");
#endif
    }

    NtClose(mutex_pipe_recv_message);
    NtClose(mutex_pipe_send_routing_message);
    NtClose(mutex_pipe_send_socks5_message);

    free(args);
}

bool check_pipe(uint32_t pipe_id)
{
    bool ret = false;
    struct rbt_node_spider *node = NULL;

    node = search_spider_node(tree_pipe, mutex_tree_pipe, pipe_id);
    if(node != NULL)
    {
        ret = true;
    }

    return ret;
}

void connect_pipe(struct function_args *args)
{
    struct pipe_data *pipe = (pipe_data *)args->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;
    uint32_t pipe_id = 0;
    struct sockaddr_in pipe_dest_addr;
    struct sockaddr_in6 pipe_dest_addr6;
    uint16_t port_num = 0;
    SOCKET pipe_sock = -1;
    BOOL reuse = 1;
    int pipe_dest_addr_length = sizeof(struct sockaddr_in);
    int pipe_dest_addr6_length = sizeof(struct sockaddr_in6);
    char *pipe_destination_ip_scope_id = NULL;
    struct function_args *function_args = NULL;

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
        if(pipe_sock == INVALID_SOCKET)
        {
            printf("[-] connect_pipe socket error: %d\n", WSAGetLastError());

            free(pipe);
            goto exit_0;
        }

        printf("[+] connect_pipe connecting ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);

        // connect
        ret = connect(pipe_sock, (struct sockaddr *)&pipe_dest_addr, pipe_dest_addr_length);
        if(ret == SOCKET_ERROR)
        {
            printf("[-] connect_pipe connect failed: %d\n", WSAGetLastError());

            closesocket(pipe_sock);
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
        if(pipe_sock == INVALID_SOCKET)
        {
            printf("[-] connect_pipe socket error: %d\n", WSAGetLastError());

            free(pipe);
            goto exit_0;
        }

        if(pipe_dest_addr6.sin6_scope_id > 0)
        {
            printf("[+] connect_pipe connecting ip: %s%%%s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_ip_scope_id, pipe->pipe_destination_port);
        }else
        {
            printf("[+] connect_pipe connecting ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);
        }

        // connect
        ret = connect(pipe_sock, (struct sockaddr *)&pipe_dest_addr6, pipe_dest_addr6_length);
        if(ret == SOCKET_ERROR)
        {
            printf("[-] connect_pipe connect failed: %d\n", WSAGetLastError());

            closesocket(pipe_sock);
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
        ret = insert_spider_node(tree_pipe, mutex_tree_pipe, pipe_id, pipe);
    }while(ret != 0);

    send_routing_table();

    function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
    function_args->args = (void *)pipe;
    start_thread(m_thread, (void *)pipe_worker, (void *)function_args);

exit_0:
    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] connect_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] connect_pipe cannot close handle\n");
#endif
    }
}

void listen_pipe(struct function_args *args)
{
    struct pipe_data *pipe_listen = (pipe_data *)args->args;
    struct map_node_thread *thread = NULL;
    int ret = 0;
    uint32_t pipe_listen_id = 0;
    uint32_t pipe_id = 0;
    struct sockaddr_in pipe_listen_addr;
    struct sockaddr_in pipe_addr;
    struct sockaddr_in6 pipe_listen_addr6;
    struct sockaddr_in6 pipe_addr6;
    uint16_t port_num = 0;
    SOCKET pipe_listen_sock = -1;
    SOCKET pipe_sock = -1;
    BOOL reuse = 1;
    int pipe_addr_length = sizeof(struct sockaddr_in);
    int pipe_addr6_length = sizeof(struct sockaddr_in6);
    char *pipe_destination_ip = NULL;
    char *pipe_destination_ip_scope_id = NULL;
    char *pipe_destination_port = NULL;
    struct function_args *function_args = NULL;

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

            free(pipe_listen);
            goto exit_0;
        }

        port_num = atoi(pipe_listen->pipe_listen_port);
        pipe_listen_addr.sin_port = htons(port_num);

        // socket
        pipe_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(pipe_listen_sock == INVALID_SOCKET)
        {
            printf("[-] listen_pipe socket error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

        reuse = 1;
        ret = setsockopt(pipe_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(int));
        if(ret == SOCKET_ERROR)
        {
            printf("[-] listen_pipe setsockopt error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

        // bind
        ret = bind(pipe_listen_sock, (struct sockaddr *)&pipe_listen_addr, pipe_addr_length);
        if(ret == SOCKET_ERROR)
        {
            printf("[-] listen_pipe bind error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

        // listen
        ret = listen(pipe_listen_sock, 5);
        if(ret == SOCKET_ERROR)
        {
            printf("[-] listen_pipe listen error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

        printf("[+] listen_pipe listening ip: %s  port: %s\n", pipe_listen->pipe_ip, pipe_listen->pipe_listen_port);

        pipe_listen->pipe_sock = pipe_listen_sock;
        pipe_listen->routing_message_queue = NULL;
        pipe_listen->socks5_message_queue = NULL;

        do
        {
            pipe_listen_id = generate_random_id();
            pipe_listen->pipe_id = pipe_listen_id;
            ret = insert_spider_node(tree_pipe, mutex_tree_pipe, pipe_listen_id, pipe_listen);
        }while(ret != 0);

        while(1)
        {
            // accept
            pipe_sock = accept(pipe_listen_sock, (struct sockaddr *)&pipe_addr, (socklen_t *)&pipe_addr_length);

            if(pipe_id != 0 && check_pipe(pipe_id))
            {
                closesocket(pipe_sock);
                continue;
            }

            pipe_data *pipe = (pipe_data *)calloc(1, sizeof(struct pipe_data));
            pipe_destination_ip = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            pipe_destination_port = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            if(pipe == NULL || pipe_destination_ip == NULL || pipe_destination_port == NULL)
            {
#ifdef _DEBUG
                printf("[-] listen_pipe calloc error\n");
#endif

                closesocket(pipe_sock);
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
                ret = insert_spider_node(tree_pipe, mutex_tree_pipe, pipe_id, pipe);
            }while(ret != 0);

#ifdef _DEBUG
            printf("[+] listen_pipe connected ip: %s port: %s\n", pipe->pipe_destination_ip, pipe->pipe_destination_port);
#endif

            send_routing_table();

            function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
            function_args->args = (void *)pipe;
            start_thread(m_thread, (void *)pipe_worker, (void *)function_args);
        }
    }else   // ipv6
    {
        pipe_listen_addr6.sin6_family = AF_INET6;

        ret = inet_pton(AF_INET6, pipe_listen->pipe_ip, &pipe_listen_addr6.sin6_addr);
        if(ret == 0)
        {
            printf("[-] listen_pipe inet_pton error\n");

            free(pipe_listen);
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
        if(pipe_listen_sock == INVALID_SOCKET)
        {
            printf("[-] listen_pipe socket error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

        reuse = 1;
        ret = setsockopt(pipe_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(int));
        if(ret == SOCKET_ERROR)
        {
            printf("[-] listen_pipe setsockopt error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

        // bind
        ret = bind(pipe_listen_sock, (struct sockaddr *)&pipe_listen_addr6, sizeof(pipe_listen_addr6));
        if(ret == SOCKET_ERROR)
        {
            printf("[-] listen_pipe bind error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

        // listen
        ret = listen(pipe_listen_sock, 5);
        if(ret == SOCKET_ERROR)
        {
            printf("[-] listen_pipe listen error: %d\n", WSAGetLastError());

            free(pipe_listen);
            goto exit_0;
        }

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
            ret = insert_spider_node(tree_pipe, mutex_tree_pipe, pipe_listen_id, pipe_listen);
        }while(ret != 0);

        while(1)
        {
            // accept
            pipe_sock = accept(pipe_listen_sock, (struct sockaddr *)&pipe_addr6, (socklen_t *)&pipe_addr6_length);

            if(pipe_id != 0 && check_pipe(pipe_id))
            {
                closesocket(pipe_sock);
                continue;
            }

            pipe_data *pipe = (pipe_data *)calloc(1, sizeof(struct pipe_data));
            pipe_destination_ip = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            pipe_destination_ip_scope_id = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            pipe_destination_port = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
            if(pipe == NULL || pipe_destination_ip == NULL || pipe_destination_ip_scope_id == NULL || pipe_destination_port == NULL)
            {
#ifdef _DEBUG
                printf("[-] listen_pipe calloc error\n");
#endif

                closesocket(pipe_sock);
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
                ret = insert_spider_node(tree_pipe, mutex_tree_pipe, pipe_id, pipe);
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

            function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
            function_args->args = (void *)pipe;
            start_thread(m_thread, (void *)pipe_worker, (void *)function_args);
        }
    }

exit_0:
    closesocket(pipe_listen_sock);
    delete_spider_node(tree_pipe, mutex_tree_pipe, pipe_listen_id);

    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] listen_pipe is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] listen_pipe cannot close handle\n");
#endif
    }
}

