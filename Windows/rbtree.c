/*
 * Title:  rbtree.c
 * Author: Shuichiro Endo
 */

#include "rbtree.h"

struct rbt_spider *tree_pipe = NULL;
HANDLE mutex_tree_pipe = NULL;
struct rbt_spider *tree_client = NULL;
HANDLE mutex_tree_client = NULL;
struct rbt_spider *tree_server = NULL;
HANDLE mutex_tree_server = NULL;

static void init_rbt_spider(struct rbt_spider **tree)
{
    struct rbt_node_spider *nil = NULL;

    *tree = (struct rbt_spider *)calloc(1, sizeof(struct rbt_spider));
    nil = (struct rbt_node_spider *)calloc(1, sizeof(struct rbt_node_spider));

    nil->color = BLACK;
    nil->left = nil;
    nil->right = nil;
    nil->parent = nil;

    (*tree)->nil = nil;
    (*tree)->root = nil;
}

static void left_rotate_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *x)
{
    rbt_node_spider *y = x->right;
    x->right = y->left;

    if(y->left != tree->nil)
    {
        y->left->parent = x;
    }

    y->parent = x->parent;

    if(x->parent == tree->nil)
    {
        tree->root = y;
    }else if(x == x->parent->left)
    {
        x->parent->left = y;
    }else
    {
        x->parent->right = y;
    }

    y->left = x;
    x->parent = y;
}

static void right_rotate_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *y)
{
    struct rbt_node_spider *x = y->left;
    y->left = x->right;

    if(x->right != tree->nil)
    {
        x->right->parent = y;
    }

    x->parent = y->parent;

    if(y->parent == tree->nil)
    {
        tree->root = x;
    }else if(y == y->parent->right)
    {
        y->parent->right = x;
    }else
    {
        y->parent->left = x;
    }

    x->right = y;
    y->parent = x;
}

static void insert_fixup_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *node)
{
    while(node->parent != tree->nil && node->parent->color == RED)
    {
        if(node->parent == node->parent->parent->left)
        {
            rbt_node_spider *uncle = node->parent->parent->right;

            if(uncle->color == RED)
            {
                node->parent->color = BLACK;
                uncle->color = BLACK;
                node->parent->parent->color = RED;
                node = node->parent->parent;
            }else
            {
                if(node == node->parent->right)
                {
                    node = node->parent;
                    left_rotate_rbt_node_spider(tree, node);
                }

                node->parent->color = BLACK;
                node->parent->parent->color = RED;
                right_rotate_rbt_node_spider(tree, node->parent->parent);
            }
        }else
        {
            rbt_node_spider *uncle = node->parent->parent->left;

            if(uncle->color == RED)
            {
                node->parent->color = BLACK;
                uncle->color = BLACK;
                node->parent->parent->color = RED;
                node = node->parent->parent;
            }else
            {
                if(node == node->parent->left)
                {
                    node = node->parent;
                    right_rotate_rbt_node_spider(tree, node);
                }

                node->parent->color = BLACK;
                node->parent->parent->color = RED;
                left_rotate_rbt_node_spider(tree, node->parent->parent);
            }
        }
    }

    tree->root->color = BLACK;
}

static void insert_rbt_node_spider(struct rbt_spider *tree, uint32_t id, void *data)
{
    struct rbt_node_spider *node = NULL;

    node = (struct rbt_node_spider *)calloc(1, sizeof(struct rbt_node_spider));
    node->id = id;
    node->data = data;
    node->color = RED;
    node->left = tree->nil;
    node->right = tree->nil;
    node->parent = tree->nil;

    rbt_node_spider *x = tree->root;
    rbt_node_spider *y = tree->nil;

    while(x != tree->nil)
    {
        y = x;
        if(node->id < x->id)
        {
            x = x->left;
        }else
        {
            x = x->right;
        }
    }

    node->parent = y;
    if(y == tree->nil)
    {
        tree->root = node;
    }else if(node->id < y->id)
    {
        y->left = node;
    }else
    {
        y->right = node;
    }

    insert_fixup_rbt_node_spider(tree, node);
}

static struct rbt_node_spider *search_rbt_node_spider(struct rbt_spider *tree, uint32_t id)
{
    struct rbt_node_spider *current = tree->root;

    while(current != tree->nil)
    {
        if(id == current->id)
        {
            return current;
        }else if(id < current->id)
        {
            current = current->left;
        }else
        {
            current = current->right;
        }
    }

    return NULL;
}

static void transplant_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *u, struct rbt_node_spider *v)
{
    if(u->parent == tree->nil)
    {
        tree->root = v;
    }else if(u == u->parent->left)
    {
        u->parent->left = v;
    }else
    {
        u->parent->right = v;
    }

    v->parent = u->parent;
}

static void delete_fixup_rbt_node_spider(struct rbt_spider *tree, struct rbt_node_spider *x)
{
    while(x != tree->root && x->color == BLACK)
    {
        if(x == x->parent->left)
        {
            struct rbt_node_spider *w = x->parent->right;

            if(w->color == RED)
            {
                w->color == BLACK;
                x->parent->color = RED;
                left_rotate_rbt_node_spider(tree, x->parent);
                w = x->parent->right;
            }

            if(w->left->color == BLACK && w->right->color == BLACK)
            {
                w->color = RED;
                x = x->parent;
            }else
            {
                if(w->right->color == BLACK)
                {
                    w->left->color = BLACK;
                    w->color = RED;
                    right_rotate_rbt_node_spider(tree, w);
                    w = x->parent->right;
                }

                w->color = x->parent->color;
                w->parent->color = BLACK;
                w->right->color = BLACK;
                left_rotate_rbt_node_spider(tree, x->parent);
                x = tree->root;
            }
        }else
        {
            struct rbt_node_spider *w = x->parent->left;

            if(w->color == RED)
            {
                w->color = BLACK;
                x->parent->color = RED;
                right_rotate_rbt_node_spider(tree, x->parent);
                w = x->parent->left;
            }

            if(w->right->color == BLACK && w->left->color == BLACK)
            {
                w->color = RED;
                x = x->parent;
            }else
            {
                if(w->left->color == BLACK)
                {
                    w->right->color = BLACK;
                    w->color = RED;
                    left_rotate_rbt_node_spider(tree, w);
                    w = x->parent->left;
                }

                w->color = x->parent->color;
                x->parent->color = BLACK;
                w->left->color = BLACK;
                right_rotate_rbt_node_spider(tree, x->parent);
                x = tree->root;
            }
        }
    }

    x->color = BLACK;
}

static void delete_rbt_node_spider(struct rbt_spider *tree, uint32_t id)
{
    struct rbt_node_spider *z = search_rbt_node_spider(tree, id);
    if(z == NULL)
    {
#ifdef _DEBUG
        printf("[-] delete_rbt_node_spider search_rbt_node_spider error: %u\n", id);
#endif
        return;
    }

    struct rbt_node_spider *y = z;
    struct rbt_node_spider *x;
    rbt_node_color original_color = y->color;

    if(z->left == tree->nil)
    {
        x = z->right;
        transplant_rbt_node_spider(tree, z, z->right);
    }else if(z->right == tree->nil)
    {
        x = z->left;
        transplant_rbt_node_spider(tree, z, z->left);
    }else
    {
        y = z->right;

        while(y->left != tree->nil)
        {
            y = y->left;
        }

        original_color = y->color;
        x = y->right;

        if(y->parent == z)
        {
            x->parent = y;
        }else
        {
            transplant_rbt_node_spider(tree, y, y->right);
            y->right = z->right;
            y->right->parent = y;
        }

        transplant_rbt_node_spider(tree, z, y);
        y->left = z->left;
        y->left->parent = y;
        y->color = z->color;
    }

    free(z->data);
    free(z);

    if(original_color == BLACK)
    {
        delete_fixup_rbt_node_spider(tree, x);
    }
}

static void inorder_rbt_node_pipe(struct rbt_node_spider *node, struct rbt_node_spider *nil)
{
    struct pipe_data *data = NULL;

    if(node != nil)
    {
        inorder_rbt_node_pipe(node->left, nil);

        data = (pipe_data *)node->data;

        printf("|%10u|%s   |%-46s|             %3s|           %-5s|%-46s|                         %3s|                %-5s|      %5d|\n",
               data->pipe_id,
               data->pipe_mode,
               data->pipe_ip,
               data->pipe_ip_scope_id,
               data->pipe_listen_port,
               data->pipe_destination_ip,
               data->pipe_destination_ip_scope_id,
               data->pipe_destination_port,
               data->pipe_sock);

        inorder_rbt_node_pipe(node->right, nil);
    }
}

static void inorder_rbt_node_client(struct rbt_node_spider *node, struct rbt_node_spider *nil)
{
    struct client_data *data = NULL;

    if(node != nil)
    {
        inorder_rbt_node_client(node->left, nil);

        data = (client_data *)node->data;

        printf("|%-6s|   %10u|%10u|%10u|%-46s|               %3s|             %-5s|      %-5s|%-46s|%-46s|      %-5s|        %5d|%7d|%7d|         %7d|          %7d|\n",
               data->client_type,
               data->connection_id,
               data->client_id,
               data->server_id,
               data->client_ip,
               data->client_ip_scope_id,
               data->client_listen_port,
               data->client_port,
               data->destination_spider_ip,
               data->target_ip,
               data->target_port,
               data->client_sock,
               data->tv_sec,
               data->tv_usec,
               data->forwarder_tv_sec,
               data->forwarder_tv_usec);

        inorder_rbt_node_client(node->right, nil);
    }
}

static void inorder_rbt_node_server(struct rbt_node_spider *node, struct rbt_node_spider *nil)
{
    struct server_data *data = NULL;

    if(node != nil)
    {
        inorder_rbt_node_server(node->left, nil);

        data = (server_data *)node->data;

        printf("|   %10u|%10u|%10u|%-46s|      %-5s|%-46s|        %5d|%-46s|      %-5s|        %5d|%7d|%7d|         %7d|          %7d|\n",
               data->connection_id,
               data->client_id,
               data->server_id,
               data->server_ip,
               data->server_port,
               data->client_destination_ip,
               data->server_sock,
               data->target_ip,
               data->target_port,
               data->target_sock,
               data->tv_sec,
               data->tv_usec,
               data->forwarder_tv_sec,
               data->forwarder_tv_usec);

         inorder_rbt_node_server(node->right, nil);
    }
}

static void inorder_tree_rbt_node_pipe(struct rbt_spider *tree)
{
    inorder_rbt_node_pipe(tree->root, tree->nil);
}

static void inorder_tree_rbt_node_client(struct rbt_spider *tree)
{
    inorder_rbt_node_client(tree->root, tree->nil);
}

static void inorder_tree_rbt_node_server(struct rbt_spider *tree)
{
    inorder_rbt_node_server(tree->root, tree->nil);
}

static void free_rbt_node_spider(struct rbt_node_spider *node, struct rbt_node_spider *nil)
{
    if(node != nil)
    {
        free_rbt_node_spider(node->left, nil);
        free_rbt_node_spider(node->right, nil);

        free(node->data);
        free(node);
    }
}

int init_tree_spider_node()
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    status = NtCreateMutant(&mutex_tree_pipe, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtCreateMutant error: %x\n", status);
#endif
        goto error;
    }

    status = NtCreateMutant(&mutex_tree_client, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtCreateMutant error: %x\n", status);
#endif
        goto error;
    }

    status = NtCreateMutant(&mutex_tree_server, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtCreateMutant error: %x\n", status);
#endif
        goto error;
    }

    status = NtWaitForSingleObject(mutex_tree_pipe, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    init_rbt_spider(&tree_pipe);

    status = NtReleaseMutant(mutex_tree_pipe, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtReleaseMutant error: %x\n", status);
#endif
        goto error;
    }

    status = NtWaitForSingleObject(mutex_tree_client, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    init_rbt_spider(&tree_client);

    status = NtReleaseMutant(mutex_tree_client, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtReleaseMutant error: %x\n", status);
#endif
        goto error;
    }

    status = NtWaitForSingleObject(mutex_tree_server, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    init_rbt_spider(&tree_server);

    status = NtReleaseMutant(mutex_tree_server, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init_tree_spider_node NtReleaseMutant error: %x\n", status);
#endif
        goto error;
    }

    return 0;

error:
    NtClose(mutex_tree_pipe);
    NtClose(mutex_tree_client);
    NtClose(mutex_tree_server);

    return -1;
}

int insert_spider_node(struct rbt_spider *tree, HANDLE handle, uint32_t id, void *data)
{
    struct rbt_node_spider *node = NULL;
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] insert_spider_node NtWaitForSingleObject error: %x\n", status);
#endif
        return -1;
    }

    node = search_rbt_node_spider(tree, id);
    if(node != NULL)
    {
        return -1;
    }

    insert_rbt_node_spider(tree, id, data);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] insert_spider_node NtReleaseMutant error: %x\n", status);
#endif
        return -1;
    }

    return 0;
}

struct rbt_node_spider *search_spider_node(struct rbt_spider *tree, HANDLE handle, uint32_t id)
{
    struct rbt_node_spider *node = NULL;
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] search_spider_node NtWaitForSingleObject error: %x\n", status);
#endif
        return node;
    }

    node = search_rbt_node_spider(tree, id);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] search_spider_node NtReleaseMutant error: %x\n", status);
#endif
        return node;
    }

    return node;
}

void delete_spider_node(struct rbt_spider *tree, HANDLE handle, uint32_t id)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] delete_spider_node NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    delete_rbt_node_spider(tree, id);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] delete_spider_node NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

static void send_routing_table_inorder_rbt_node_pipe(struct rbt_node_spider *node, struct rbt_node_spider *nil, char *buffer, int32_t buffer_length)
{
    struct spider_message *routing_message = NULL;
    int spider_message_header_size = sizeof(struct spider_message_header);
    struct pipe_data *data = NULL;

    if(node != nil)
    {
        send_routing_table_inorder_rbt_node_pipe(node->left, nil, buffer, buffer_length);

        data = (struct pipe_data *)node->data;
        if(strcmp((char *)&data->pipe_mode, "s") != 0)
        {
            routing_message = (struct spider_message *)calloc(spider_message_header_size + buffer_length, sizeof(char));
            routing_message->header.message_type = 'r';
            routing_message->header.pipe_id = htonl(0);
            routing_message->header.data_size = htonl(buffer_length);
            memcpy(&routing_message->data, buffer, buffer_length);

#ifdef _DEBUG
//            print_bytes((char *)routing_message, spider_message_header_size + buffer_length);
#endif

            enqueue(data->routing_message_queue, (void *)routing_message);
        }

        send_routing_table_inorder_rbt_node_pipe(node->right, nil, buffer, buffer_length);
    }
}

void send_routing_table_inorder_tree_rbt_node_pipe(struct rbt_spider *tree, HANDLE handle, char *buffer, int32_t buffer_length)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] send_routing_table_inorder_tree_rbt_node_pipe NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    send_routing_table_inorder_rbt_node_pipe(tree->root, tree->nil, buffer, buffer_length);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] send_routing_table_inorder_tree_rbt_node_pipe NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

void print_spider_node_pipe(struct rbt_spider *tree, HANDLE handle)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    printf("----------------------------------------------------------------------------------------------------- pipe -----------------------------------------------------------------------------------------------------\n");
    printf("|pipe id   |mode|pipe ip                                       |pipe ip scope id|pipe listen port|pipe destination ip                           |pipe destination ip scope id|pipe destination port|pipe socket|\n");
    printf("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_spider_node_pipe NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    inorder_tree_rbt_node_pipe(tree);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_spider_node_pipe NtReleaseMutant error: %x\n", status);
#endif
        return;
    }

    printf("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("\n");
}

void print_spider_node_client(struct rbt_spider *tree, HANDLE handle)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    printf("-------------------------------------------------------------------------------------------------------------------------------------------------------- client --------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("|type  |connection id|client id |server id |client ip                                     |client ip scope id|client listen port|client port|destination spider ip                         |target ip                                     |target port|client socket|tv_sec |tv_usec|forwarder_tv_sec|forwarder_tv_usec|\n");
    printf("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_spider_node_client NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    inorder_tree_rbt_node_client(tree);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_spider_node_client NtReleaseMutant error: %x\n", status);
#endif
        return;
    }

    printf("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("\n");
}

void print_spider_node_server(struct rbt_spider *tree, HANDLE handle)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    printf("---------------------------------------------------------------------------------------------------------------------------------------- server -----------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("|connection id|client id |server id |server ip                                     |server port|client destination ip                         |server socket|target ip                                     |target port|target socket|tv_sec |tv_usec|forwarder_tv_sec|forwarder_tv_usec|\n");
    printf("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_spider_node_server NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    inorder_tree_rbt_node_server(tree);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_spider_node_server NtReleaseMutant error: %x\n", status);
#endif
        return;
    }

    printf("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("\n");
}

void free_rbt_tree_spider(struct rbt_spider *tree, HANDLE handle)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    status = NtWaitForSingleObject(handle, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] free_rbt_tree_spider NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    if(tree->root != tree->nil)
    {
        free_rbt_node_spider(tree->root, tree->nil);
    }

    free(tree->nil);
    free(tree);

    status = NtReleaseMutant(handle, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] free_rbt_tree_spider NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

