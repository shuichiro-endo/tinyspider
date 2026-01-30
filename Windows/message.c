/*
 * Title:  message.c
 * Author: Shuichiro Endo
 */

#include "message.h"

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
extern int encryption_flag;
extern struct rbt_spider *tree_pipe;
extern HANDLE mutex_tree_pipe;
extern struct rbt_spider *tree_client;
extern HANDLE mutex_tree_client;
extern struct rbt_spider *tree_server;
extern HANDLE mutex_tree_server;

struct queue *routing_message_queue = NULL;
struct queue *socks5_message_queue = NULL;

void push_routing_message(struct function_args *args)
{
    struct spider_message *message = args->args;
    struct map_node_thread *thread = NULL;

    if(routing_message_queue != NULL)
    {
        enqueue(routing_message_queue, (void *)message);
    }else
    {
#ifdef _DEBUG
        printf("[-] push_routing_message routing_message_queue is null\n");
#endif

        free(message);
    }

    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_routing_message is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_routing_message cannot close handle\n");
#endif
    }

    free(args);
}

void push_socks5_message(struct function_args *args)
{
    struct spider_message *message = args->args;
    struct map_node_thread *thread = NULL;

    if(socks5_message_queue != NULL)
    {
        enqueue(socks5_message_queue, (void *)message);
    }else
    {
#ifdef _DEBUG
        printf("[-] push_routing_message socks5_message_queue is null\n");
#endif

        free(message);
    }

    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] push_socks5_message is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] push_socks5_message cannot close handle\n");
#endif
    }

    free(args);
}

struct spider_message *pop_routing_message()
{
    struct spider_message *routing_message = NULL;

    if(routing_message_queue != NULL)
    {
        routing_message = (struct spider_message *)dequeue(routing_message_queue);
    }

    return routing_message;
}

struct spider_message *pop_socks5_message()
{
    struct spider_message *socks5_message = NULL;

    if(socks5_message_queue != NULL)
    {
        socks5_message = (struct spider_message *)dequeue(socks5_message_queue);
    }

    return socks5_message;
}

struct spider_message *transfer_socks5_message()
{
    struct spider_message *socks5_message = NULL;
    struct rbt_node_spider *spider_node = NULL;
    struct client_data *client = NULL;
    struct server_data *server = NULL;
    struct pipe_data *pipe = NULL;

    socks5_message = pop_socks5_message();
    if(socks5_message != NULL)
    {
        if(socks5_message->header.message_type == 's')  // socks5 message
        {
            if(is_spider_ip(ip, (char *)&socks5_message->header.destination_ip))
            {
                if(socks5_message->header.destination_node_type == 'c')    // client
                {
                    spider_node = search_spider_node(tree_client, mutex_tree_client, socks5_message->header.client_id);
                    if(spider_node != NULL)
                    {
                        client = (struct client_data *)spider_node->data;

                        if(socks5_message->header.receive_flag == 1)
                        {
                            struct insert_map_node_client_receive_message_thread_args *insert_map_node_client_receive_message_thread_args = (struct insert_map_node_client_receive_message_thread_args *)calloc(1, sizeof(struct insert_map_node_client_receive_message_thread_args));
                            insert_map_node_client_receive_message_thread_args->client = client;
                            insert_map_node_client_receive_message_thread_args->message_id = socks5_message->header.message_id;
                            insert_map_node_client_receive_message_thread_args->message = socks5_message;

                            struct function_args *function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
                            function_args->args = (void *)insert_map_node_client_receive_message_thread_args;
                            start_thread(m_thread, (void *)insert_map_node_client_receive_message_thread, (void *)function_args);
                        }else
                        {
                            struct push_message_queue_args_client *push_message_queue_args_client = (struct push_message_queue_args_client *)calloc(1, sizeof(struct push_message_queue_args_client));
                            push_message_queue_args_client->client = client;
                            push_message_queue_args_client->message = socks5_message;

                            struct function_args *function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
                            function_args->args = (void *)push_message_queue_args_client;
                            start_thread(m_thread, (void *)push_socks5_message_client, (void *)function_args);
                        }
                    }else
                    {
#ifdef _DEBUG
                        printf("[-] transfer_socks5_message cannot transfer client message\n");
#endif

                        free(socks5_message);
                    }
                }else if(socks5_message->header.destination_node_type == 's')  // server
                {
                    spider_node = search_spider_node(tree_server, mutex_tree_server, socks5_message->header.server_id);
                    if(spider_node != NULL)
                    {
                        server = (struct server_data *)spider_node->data;

                        if(socks5_message->header.receive_flag == 1)
                        {
                            struct insert_map_node_server_receive_message_thread_args *insert_map_node_server_receive_message_thread_args = (struct insert_map_node_server_receive_message_thread_args *)calloc(1, sizeof(struct insert_map_node_server_receive_message_thread_args));
                            insert_map_node_server_receive_message_thread_args->server = server;
                            insert_map_node_server_receive_message_thread_args->message_id = socks5_message->header.message_id;
                            insert_map_node_server_receive_message_thread_args->message = socks5_message;

                            struct function_args *function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
                            function_args->args = (void *)insert_map_node_server_receive_message_thread_args;
                            start_thread(m_thread, (void *)insert_map_node_server_receive_message_thread, (void *)function_args);
                        }else
                        {
                            struct push_message_queue_args_server *push_message_queue_args_server = (struct push_message_queue_args_server *)calloc(1, sizeof(struct push_message_queue_args_server));
                            push_message_queue_args_server->server = server;
                            push_message_queue_args_server->message = socks5_message;

                            struct function_args *function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
                            function_args->args = (void *)push_message_queue_args_server;
                            start_thread(m_thread, (void *)push_socks5_message_server, (void *)function_args);
                        }
                    }else
                    {
                        // generate server
                        return socks5_message;
                    }
                }else
                {
#ifdef _DEBUG
                    printf("[-] transfer_socks5_message cannot transfer socks5 message\n");
#endif

                    free(socks5_message);
                }
            }else
            {
                pipe = get_destination_pipe((char *)&socks5_message->header.destination_ip);
                if(pipe != NULL)
                {
                    struct push_message_queue_args_pipe *push_message_queue_args_pipe = (struct push_message_queue_args_pipe *)calloc(1, sizeof(struct push_message_queue_args_pipe));
                    push_message_queue_args_pipe->pipe = pipe;
                    push_message_queue_args_pipe->message = socks5_message;

                    struct function_args *function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
                    function_args->args = (void *)push_message_queue_args_pipe;
                    start_thread(m_thread, (void *)push_socks5_message_pipe, (void *)function_args);
                }else
                {
#ifdef _DEBUG
                    printf("[-] transfer_socks5_message cannot transfer pipe message\n");
#endif

                    free(socks5_message);
                }
            }
        }else
        {
#ifdef _DEBUG
            printf("[-] transfer_socks5_message unknown message type: %c\n", socks5_message->header.message_type);
#endif

            free(socks5_message);
        }
    }

    return NULL;
}

void message_worker(struct function_args *args)
{
    bool *prevent_spider_server_startup_flag = args->args;
    struct map_node_thread *thread = NULL;

    int ret = 0;
    struct spider_message *socks5_message = NULL;
    struct server_data *server = NULL;
    uint32_t server_id = 0;

    while(1)
    {
        socks5_message = transfer_socks5_message();
        if(socks5_message != NULL && *prevent_spider_server_startup_flag == false)  // generate server
        {
            server = (struct server_data *)calloc(1, sizeof(struct server_data));

            server->server_sock = -1;
            server->connection_id = socks5_message->header.connection_id;
            server->client_id = socks5_message->header.client_id;
            strcpy(server->server_ip, socks5_message->header.destination_ip);
            strcpy(server->client_destination_ip, socks5_message->header.source_ip);
            server->tv_sec = socks5_message->header.tv_sec;
            server->tv_usec = socks5_message->header.tv_usec;
            server->forwarder_tv_sec = socks5_message->header.forwarder_tv_sec;
            server->forwarder_tv_usec = socks5_message->header.forwarder_tv_usec;
            server->encryption_flag = encryption_flag;
            server->socks5_message_queue = create_queue();
            create_map_server_receive_message(&server->m_server_receive_message, &server->mutex_m_server_receive_message);

            do
            {
                server_id = generate_random_id();
                server->server_id = server_id;
                ret = insert_spider_node(tree_server, mutex_tree_server, server_id, server);
            }while(ret != 0);

#ifdef _DEBUG
            printf("[+] message_worker generate server: %u\n", server->server_id);

#endif
            struct server_worker_args *server_worker_args = (struct server_worker_args *)calloc(1, sizeof(struct server_worker_args));
            server_worker_args->server = server;
            server_worker_args->message = socks5_message;

            struct function_args *function_args = (struct function_args *)calloc(1, sizeof(struct function_args));
            function_args->args = (void *)server_worker_args;
            start_thread(m_thread, (void *)server_worker, (void *)function_args);
        }else if(*prevent_spider_server_startup_flag == true)
        {
#ifdef _DEBUG
            printf("[+] message_worker prevent spider server startup\n");
#endif
        }
    }

    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] message_worker is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] message_worker cannot close handle\n");
#endif
    }

    free(args);
}

