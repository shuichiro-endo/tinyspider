/*
 * Title:  spidercommmand.c
 * Author: Shuichiro Endo
 */

#include "spidercommand.h"

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
extern struct rbt_spider *tree_pipe;
extern struct semaphore sem_tree_pipe;
extern struct rbt_spider *tree_client;
extern struct semaphore sem_tree_client;
extern struct rbt_spider *tree_server;
extern struct semaphore sem_tree_server;

void add_node_spider_pipe()
{
    struct pipe_data *pipe = (struct pipe_data *)calloc(1, sizeof(struct pipe_data));
    char *buffer = (char *)calloc(1, INET6_ADDR_STRING_LENGTH + 1);
    char *ptr = NULL;

    if(pipe == NULL || buffer == NULL)
    {
        printf("[-] add_node_spider_pipe calloc error\n");

        return;
    }

    while(1)
    {
        print_routing_table();
        printf("\n");

        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        printf("pipe mode (client:c server:s)                  > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            continue;
        }else if(strcmp(buffer, "c") == 0)  // client
        {
            strcpy(pipe->pipe_mode, buffer);
            memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

            printf("pipe ip                                        > ");
            ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
            if(ptr == NULL)
            {
                printf("[-] input error\n");

                continue;
            }

            if(is_not_spider_ip(ip, buffer))
            {
                printf("[-] please input spider ipv4 or ipv6\n");

                continue;
            }

            strcpy(pipe->pipe_ip, buffer);

            if(strcmp(buffer, ip->spider_ipv6_link_local) == 0)
            {
                strcpy(pipe->pipe_ip_scope_id, ip->spider_ipv6_link_local_scope_id);
            }

            memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

            printf("pipe destination ip                            > ");
            ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
            if(ptr == NULL)
            {
                printf("[-] input error\n");

                continue;
            }

            strcpy(pipe->pipe_destination_ip, buffer);
            memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

            if(strlen(pipe->pipe_ip_scope_id) > 0)
            {
                strcpy(pipe->pipe_destination_ip_scope_id, ip->spider_ipv6_link_local_scope_id);
            }

            printf("pipe destination port                          > ");
            ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
            if(ptr == NULL)
            {
                printf("[-] input error\n");

                continue;
            }

            strcpy(pipe->pipe_destination_port, buffer);
            memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

            printf("\n");
            printf("pipe mode                    : %s\n", pipe->pipe_mode);
            printf("pipe ip                      : %s\n", pipe->pipe_ip);
            if(strlen(pipe->pipe_ip_scope_id) > 0)
            {
                printf("pipe ip scope id             : %s\n", pipe->pipe_ip_scope_id);
            }
            printf("pipe destination ip          : %s\n", pipe->pipe_destination_ip);
            if(strlen(pipe->pipe_destination_ip_scope_id) > 0)
            {
                printf("pipe destination ip scope id : %s\n", pipe->pipe_destination_ip_scope_id);
            }
            printf("pipe destination port        : %s\n", pipe->pipe_destination_port);
            printf("\n");

            printf("ok? (yes:y no:n quit:q)                        > ");
            ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
            if(ptr == NULL)
            {
                printf("[-] input error\n");

                continue;
            }

            if(strcmp(buffer, "y") == 0)
            {
                start_thread(m_thread, (void *)connect_pipe, (void *)pipe);
                sleep(5);

                break;
            }else if(strcmp(buffer, "n") == 0)
            {
                continue;
            }else
            {
                goto exit_0;
            }
        }else if(strcmp(buffer, "s") == 0)  // server
        {
            strcpy(pipe->pipe_mode, buffer);
            memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

            printf("pipe listen ip                                 > ");
            ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
            if(ptr == NULL)
            {
                printf("[-] input error\n");

                continue;
            }

            if(is_not_spider_ip(ip, buffer))
            {
                printf("[-] please input spider ipv4 or ipv6\n");

                continue;
            }

            strcpy(pipe->pipe_ip, buffer);

            if(strcmp(buffer, ip->spider_ipv6_link_local) == 0)
            {
                strcpy(pipe->pipe_ip_scope_id, ip->spider_ipv6_link_local_scope_id);
            }

            memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

            printf("pipe listen port                               > ");
            ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
            if(ptr == NULL)
            {
                printf("[-] input error\n");

                continue;
            }

            strcpy(pipe->pipe_listen_port, buffer);
            memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

            printf("\n");
            printf("pipe mode                 : %s\n", pipe->pipe_mode);
            printf("pipe listen ip            : %s\n", pipe->pipe_ip);
            if(strlen(pipe->pipe_ip_scope_id) > 0)
            {
                printf("pipe listen ip scope id   : %s\n", pipe->pipe_ip_scope_id);
            }
            printf("pipe listen port          : %s\n", pipe->pipe_listen_port);
            printf("\n");

            printf("ok? (yes:y no:n quit:q)                        > ");
            ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
            if(ptr == NULL)
            {
                printf("[-] input error\n");

                continue;
            }

            if(strcmp(buffer, "y") == 0)
            {
                start_thread(m_thread, (void *)listen_pipe, (void *)pipe);
                sleep(5);

                break;
            }else if(strcmp(buffer, "n") == 0)
            {
                continue;
            }else
            {
                goto exit_0;
            }

        }else
        {
            printf("[-] input error\n");

            break;
        }
    }

exit_0:
    free(buffer);

    return;
}

void add_node_spider_client()
{
    struct client_data *client = (struct client_data *)calloc(1, sizeof(struct client_data));
    char *buffer = (char *)calloc(1, INET6_ADDR_STRING_LENGTH + 1);
    char *ptr = NULL;

    if(client == NULL || buffer == NULL)
    {
        printf("[-] add_node_spider_client calloc error\n");

        return;
    }

    while(1)
    {
        print_routing_table();
        printf("\n");

        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        printf("client listen ip                               > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            continue;
        }

        if(is_not_spider_ip(ip, buffer))
        {
            printf("[-] please input spider ipv4 or ipv6\n");

            continue;
        }

        strcpy(client->client_ip, buffer);

        if(strcmp(buffer, ip->spider_ipv6_link_local) == 0)
        {
            strcpy(client->client_ip_scope_id, ip->spider_ipv6_link_local_scope_id);
        }

        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        printf("client listen port                             > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            continue;
        }

        strcpy(client->client_listen_port, buffer);
        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        printf("client destination spider ip                   > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            continue;
        }

        strcpy(client->destination_spider_ip, buffer);
        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        printf("recv/send tv_sec  (timeout 0-60 sec)           > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            client->tv_sec = 3;
        }else
        {
            client->tv_sec = atoi(buffer);
            if(client->tv_sec < 0 || client->tv_sec > 60)
            {
                client->tv_sec = 3;
            }
        }

        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        printf("recv/send tv_usec (timeout 0-1000000 microsec) > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            client->tv_usec = 0;
        }else
        {
            client->tv_usec = atoi(buffer);
            if(client->tv_usec < 0 || client->tv_usec > 10000000)
            {
                client->tv_usec = 0;
            }
        }

        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        if(client->tv_sec == 0 && client->tv_usec == 0){
            client->tv_sec = 3;
            client->tv_usec = 0;
        }

        printf("forwarder tv_sec  (timeout 0-3600 sec)         > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            client->forwarder_tv_sec = 30;
        }else
        {
            client->forwarder_tv_sec = atoi(buffer);
            if(client->forwarder_tv_sec < 0 || client->forwarder_tv_sec > 3600)
            {
                client->forwarder_tv_sec = 30;
            }
        }

        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        printf("forwarder tv_usec (timeout 0-1000000 microsec) > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            client->forwarder_tv_usec = 0;
        }else
        {
            client->forwarder_tv_usec = atoi(buffer);
            if(client->forwarder_tv_usec < 0 || client->forwarder_tv_usec > 10000000)
            {
                client->forwarder_tv_usec = 0;
            }
        }

        memset(buffer, 0, INET6_ADDR_STRING_LENGTH + 1);

        if(client->forwarder_tv_sec == 0 && client->forwarder_tv_usec == 0){
            client->forwarder_tv_sec = 30;
            client->forwarder_tv_usec = 0;
        }

        printf("\n");
        printf("client listen ip             : %s\n", client->client_ip);
        if(strlen(client->client_ip_scope_id) > 0)
        {
            printf("client listen ip scope id    : %s\n", client->client_ip_scope_id);
        }
        printf("client listen port           : %s\n", client->client_listen_port);
        printf("client destination spider ip : %s\n", client->destination_spider_ip);
        printf("recv/send tv_sec             : %7d sec\n", client->tv_sec);
        printf("recv/send tv_usec            : %7d microsec\n", client->tv_usec);
        printf("forwarder_tv_sec             : %7d sec\n", client->forwarder_tv_sec);
        printf("forwarder_tv_usec            : %7d microsec\n", client->forwarder_tv_usec);
        printf("\n");

        printf("ok? (yes:y no:n quit:q)                        > ");
        ptr = fgets(buffer, INET6_ADDR_STRING_LENGTH + 1, STDIN_FILENO);
        if(ptr == NULL)
        {
            printf("[-] input error\n");

            continue;
        }

        if(strcmp(buffer, "y") == 0)
        {
            start_thread(m_thread, (void *)listen_client, (void *)client);
            sleep(5);

            break;
        }else if(strcmp(buffer, "n") == 0)
        {
            continue;
        }else
        {
            goto exit_0;
        }
    }

exit_0:
    free(buffer);

    return;
}

void show_node_information()
{
    // pipe
    print_spider_node_pipe(tree_pipe, &sem_tree_pipe);

    // client
    print_spider_node_client(tree_client, &sem_tree_client);

    // server
    print_spider_node_server(tree_server, &sem_tree_server);

    return;
}

void show_routing_table()
{
    print_routing_table();

    return;
}

