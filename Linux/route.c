/*
 * Title:  route.c
 * Author: Shuichiro Endo
 */

#include "route.h"

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
extern int encryption_flag;
extern struct queue *routing_message_queue;
extern struct queue *socks5_message_queue;
extern struct rbt_spider *tree_pipe;
extern struct semaphore sem_tree_pipe;
extern struct xor_key *x_key;
extern struct aes_key *a_key;

struct avlt_node_route *routing_table = NULL;
struct semaphore sem_routing_table;

static struct avlt_node_route *create_avlt_node_route(const char *ip_address, struct route_data *data)
{
    struct avlt_node_route *node = NULL;

    node = (struct avlt_node_route *)calloc(1, sizeof(struct avlt_node_route));
    node->ip = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
    strcpy(node->ip, ip_address);
    node->data = data;
    node->left = NULL;
    node->right = NULL;
    node->height = 1;

    return node;
}

static int get_height_avlt_node_route(struct avlt_node_route *node)
{
    return node ? node->height : 0;
}

static int get_balance_avlt_node_route(struct avlt_node_route *node)
{
    return node ? get_height_avlt_node_route(node->left) - get_height_avlt_node_route(node->right) : 0;
}

static struct avlt_node_route *left_rotate_avlt_node_route(struct avlt_node_route *x)
{
    struct avlt_node_route *y = x->right;
    struct avlt_node_route *t2 = y->left;

    y->left = x;
    x->right = t2;

    x->height = 1 + (get_height_avlt_node_route(x->left) > get_height_avlt_node_route(x->right) ? get_height_avlt_node_route(x->left) : get_height_avlt_node_route(x->right));
    y->height = 1 + (get_height_avlt_node_route(y->left) > get_height_avlt_node_route(y->right) ? get_height_avlt_node_route(y->left) : get_height_avlt_node_route(y->right));

    return y;
}

static struct avlt_node_route *right_rotate_avlt_node_route(struct avlt_node_route *y)
{
    struct avlt_node_route *x = y->left;
    struct avlt_node_route *t2 = x->right;

    x->right = y;
    y->left = t2;

    y->height = 1 + (get_height_avlt_node_route(y->left) > get_height_avlt_node_route(y->right) ? get_height_avlt_node_route(y->left) : get_height_avlt_node_route(y->right));
    x->height = 1 + (get_height_avlt_node_route(x->left) > get_height_avlt_node_route(x->right) ? get_height_avlt_node_route(x->left) : get_height_avlt_node_route(x->right));

    return x;
}

static struct avlt_node_route *insert_avlt_node_route(struct avlt_node_route *node, const char *ip, struct route_data *data)
{
    int balance = 0;

    if(node == NULL)
    {
        return create_avlt_node_route(ip, data);
    }

    if(strcmp(ip, node->ip) < 0)
    {
        node->left = insert_avlt_node_route(node->left, ip, data);
    }else if(strcmp(ip, node->ip) > 0)
    {
        node->right = insert_avlt_node_route(node->right, ip, data);
    }else
    {
        return node;
    }

    node->height = 1 + (get_height_avlt_node_route(node->left) > get_height_avlt_node_route(node->right) ? get_height_avlt_node_route(node->left) : get_height_avlt_node_route(node->right));

    balance = get_balance_avlt_node_route(node);

    if(balance > 1 && strcmp(ip, node->left->ip) < 0)
    {
        return right_rotate_avlt_node_route(node);
    }

    if(balance < -1 && strcmp(ip, node->right->ip) > 0)
    {
        return left_rotate_avlt_node_route(node);
    }

    if(balance > 1 && strcmp(ip, node->left->ip) > 0)
    {
        node->left = left_rotate_avlt_node_route(node->left);
        return right_rotate_avlt_node_route(node);
    }

    if(balance < -1 && strcmp(ip, node->right->ip) < 0)
    {
        node->right = right_rotate_avlt_node_route(node->right);
        return left_rotate_avlt_node_route(node);
    }

    return node;
}

static struct avlt_node_route *search_avlt_node_route(struct avlt_node_route *root, const char *ip_address)
{
    if(root == NULL || strcmp(ip_address, root->ip) == 0)
    {
        return root;
    }

    if(strcmp(ip_address, root->ip) < 0)
    {
        return search_avlt_node_route(root->left, ip_address);
    }else
    {
        return search_avlt_node_route(root->right, ip_address);
    }
}

static struct avlt_node_route *delete_avlt_node_route(struct avlt_node_route *root, const char *ip_address)
{
    int balance = 0;

    if(root == NULL)
    {
        return root;
    }

    if(strcmp(ip_address, root->ip) < 0)
    {
        root->left = delete_avlt_node_route(root->left, ip_address);
    }else if(strcmp(ip_address, root->ip) > 0)
    {
        root->right = delete_avlt_node_route(root->right, ip_address);
    }else
    {
        if(root->left == NULL || root->right == NULL)
        {
            avlt_node_route *tmp = root->left ? root->left : root->right;

            if(tmp == NULL)
            {
                free_avlt_node_route(root);

                return NULL;
            }else
            {
                *root = *tmp;

                free_avlt_node_route(tmp);
            }
        }else
        {
            avlt_node_route *tmp = root->right;

            while(tmp ->left != NULL)
            {
                tmp = tmp->left;
            }

            memcpy(root->ip, tmp->ip, INET6_ADDR_STRING_LENGTH + 1);
            memcpy(root->data, tmp->data, sizeof(struct route_data));

            root->right = delete_avlt_node_route(root->right, tmp->ip);
        }
    }

    root->height = 1 + (get_height_avlt_node_route(root->left) > get_height_avlt_node_route(root->right) ? get_height_avlt_node_route(root->left) : get_height_avlt_node_route(root->right));

    balance = get_balance_avlt_node_route(root);

    if(balance > 1 && get_balance_avlt_node_route(root->left) >= 0)
    {
        return right_rotate_avlt_node_route(root);
    }

    if(balance < -1 && get_balance_avlt_node_route(root->right) <= 0)
    {
        return left_rotate_avlt_node_route(root);
    }

    if(balance > 1 && get_balance_avlt_node_route(root->left) < 0)
    {
        root->left = left_rotate_avlt_node_route(root->left);
        return right_rotate_avlt_node_route(root);
    }

    if(balance < -1 && get_balance_avlt_node_route(root->right) > 0)
    {
        root->right = right_rotate_avlt_node_route(root->right);
        return right_rotate_avlt_node_route(root);
    }

    return root;
}

static void register_dead_route_2(struct avlt_node_route *root, uint32_t pipe_id)
{
    if(root != NULL)
    {
        register_dead_route_2(root->left, pipe_id);

        if(pipe_id == root->data->pipe_id)
        {
            root->data->alive = 0;

            if(gettimeofday(&root->data->time, NULL) == -1)
            {
#ifdef _DEBUG
                printf("[-] register_dead_route_2 gettimeofday error\n");
#endif
            }
        }

        register_dead_route_2(root->right, pipe_id);
    }
}

static void inorder_avlt_node_route(struct avlt_node_route *root)
{
    if(root != NULL)
    {
        inorder_avlt_node_route(root->left);

        printf("|%c   |%-46s|   %3d|%10u|%5d|%24s|\n", root->data->mode, root->ip, root->data->metric, root->data->pipe_id, root->data->alive, ctime(&root->data->time.tv_sec));

        inorder_avlt_node_route(root->right);
    }
}

static void free_avlt_node_route(struct avlt_node_route *root)
{
    free(root->ip);

    if(root->data != NULL)
    {
        free(root->data);
    }

    free(root);
}

static void free_avlt_tree_node_route(struct avlt_node_route *root)
{
    if(root != NULL)
    {
        free_avlt_tree_node_route(root->left);
        free_avlt_tree_node_route(root->right);

        free_avlt_node_route(root);
    }
}

void insert_route(struct avlt_node_route **node, const char *ip_address, struct route_data *data)
{
    semaphore_wait(&sem_routing_table);

    *node = insert_avlt_node_route(*node, ip_address, data);

    semaphore_post(&sem_routing_table);
}

struct avlt_node_route *search_route(struct avlt_node_route *root, const char *ip_address)
{
    semaphore_wait(&sem_routing_table);

    root = search_avlt_node_route(root, ip_address);

    semaphore_post(&sem_routing_table);

    return root;
}

void delete_route(struct avlt_node_route **root, const char *ip_address)
{
    semaphore_wait(&sem_routing_table);

    *root = delete_avlt_node_route(*root, ip_address);

    semaphore_post(&sem_routing_table);
}

void register_dead_route(struct avlt_node_route *root, uint32_t pipe_id)
{
    semaphore_wait(&sem_routing_table);

    register_dead_route_2(root, pipe_id);

    semaphore_post(&sem_routing_table);
}

void free_routing_table(struct avlt_node_route *root)
{
    semaphore_wait(&sem_routing_table);

    free_avlt_tree_node_route(root);

    semaphore_post(&sem_routing_table);
}

void init_routing_table()
{
    route_data *data = NULL;

    semaphore_init(&sem_routing_table, 1);

    // self
    if(strlen(ip->spider_ipv4) > 0)
    {
        data = (route_data *)calloc(1, sizeof(struct route_data));
        data->mode = '-';
        data->metric = 0;
        data->pipe_id = 0;
        data->alive = 1;

        if(gettimeofday(&data->time, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] init_routing_table gettimeofday error\n");
#endif
            data->time.tv_sec = 0;
            data->time.tv_usec = 0;
        }

        insert_route(&routing_table, ip->spider_ipv4, data);
    }

    if(strlen(ip->spider_ipv6_global) > 0)
    {
        data = (route_data *)calloc(1, sizeof(struct route_data));
        data->mode = '-';
        data->metric = 0;
        data->pipe_id = 0;
        data->alive = 1;

        if(gettimeofday(&data->time, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] init_routing_table gettimeofday error\n");
#endif
            data->time.tv_sec = 0;
            data->time.tv_usec = 0;
        }

        insert_route(&routing_table, ip->spider_ipv6_global, data);
    }

    if(strlen(ip->spider_ipv6_unique_local) > 0)
    {
        data = (route_data *)calloc(1, sizeof(struct route_data));
        data->mode = '-';
        data->metric = 0;
        data->pipe_id = 0;
        data->alive = 1;

        if(gettimeofday(&data->time, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] init_routing_table gettimeofday error\n");
#endif
            data->time.tv_sec = 0;
            data->time.tv_usec = 0;
        }

        insert_route(&routing_table, ip->spider_ipv6_unique_local, data);
    }

    if(strlen(ip->spider_ipv6_link_local) > 0)
    {
        data = (route_data *)calloc(1, sizeof(struct route_data));
        data->mode = '-';
        data->metric = 0;
        data->pipe_id = 0;
        data->alive = 1;

        if(gettimeofday(&data->time, NULL) == -1)
        {
#ifdef _DEBUG
            printf("[-] init_routing_table gettimeofday error\n");
#endif
            data->time.tv_sec = 0;
            data->time.tv_usec = 0;
        }

        insert_route(&routing_table, ip->spider_ipv6_link_local, data);
    }
}

void print_routing_table()
{
    if(routing_table == NULL)
    {
        return;
    }

    printf("------------------------------------------- routing  table -------------------------------------------\n");
    printf("|mode|ip address                                    |metric|pipe id   |alive|time                    |\n");
    printf("------------------------------------------------------------------------------------------------------\n");

    semaphore_wait(&sem_routing_table);

    inorder_avlt_node_route(routing_table);

    semaphore_post(&sem_routing_table);

    printf("------------------------------------------------------------------------------------------------------\n");
}

static void send_routing_table_inorder_avlt_node_route(struct avlt_node_route *root, char *buffer, int *buffer_length, int buffer_size)
{
    if(root != NULL)
    {
        send_routing_table_inorder_avlt_node_route(root->left, buffer, buffer_length, buffer_size);

        if(*buffer_length + INET6_ADDR_STRING_LENGTH + 1 + sizeof(struct route_data) <= buffer_size)
        {
            memcpy(buffer + *buffer_length, root->ip, INET6_ADDR_STRING_LENGTH + 1);
            *buffer_length += INET6_ADDR_STRING_LENGTH + 1;

            memcpy(buffer + *buffer_length, (char *)root->data, sizeof(struct route_data));
            *buffer_length += sizeof(struct route_data);
        }else
        {
            return;
        }

        send_routing_table_inorder_avlt_node_route(root->right, buffer, buffer_length, buffer_size);
    }
}

void send_routing_table()
{
    int32_t ret = 0;
    char *buffer = NULL;
    int32_t buffer_length = 0;
    int32_t buffer_size = 0;

    buffer = (char *)calloc(SPIDER_MESSAGE_DATA_MAX_SIZE, sizeof(char));
    buffer_size = SPIDER_MESSAGE_DATA_MAX_SIZE;

    semaphore_wait(&sem_routing_table);

    send_routing_table_inorder_avlt_node_route(routing_table, buffer, &buffer_length, SPIDER_MESSAGE_DATA_SIZE);

    semaphore_post(&sem_routing_table);

    if(encryption_flag == 1)    // xor
    {
        ret = xor_encrypt(x_key, buffer, buffer_length, buffer_size);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] send_routing_table xor_encrypt error: %d\n", ret);
#endif
            goto exit;
        }

        buffer_length = ret;
    }else if(encryption_flag == 2)  // aes
    {
        ret = aes_encrypt(a_key, buffer, buffer_length, buffer_size);
        if(ret <= 0)
        {
#ifdef _DEBUG
            printf("[-] send_routing_table aes_encrypt error: %d\n", ret);
#endif
            goto exit;
        }

        buffer_length = ret;
    }

    send_routing_table_inorder_tree_rbt_node_pipe(tree_pipe, &sem_tree_pipe, buffer, buffer_length);

exit:
    free(buffer);
}

int update_route(char *ip_address, struct route_data *r_data_new)
{
    int ret = 0;
    struct avlt_node_route *r_node = NULL;
    struct route_data *r_data = NULL;

    r_node = search_route(routing_table, ip_address);
    if(r_node != NULL)
    {
        if(r_data_new->metric < r_node->data->metric)
        {
            r_node->data->mode = r_data_new->mode;
            r_node->data->metric = r_data_new->metric;
            r_node->data->pipe_id = r_data_new->pipe_id;
            r_node->data->alive = r_data_new->alive;
            r_node->data->time = r_data_new->time;

            free(r_data_new);
            ret = 1;
        }else if((r_data_new->metric == r_node->data->metric) &&
                 (r_data_new->pipe_id == r_node->data->pipe_id) &&
                 (r_data_new->alive == 0) &&
                 (r_node->data->alive == 1))
        {

            r_node->data->alive = r_data_new->alive;
            r_node->data->time = r_data_new->time;

            free(r_data_new);
            ret = 1;
        }else if((r_node->data->pipe_id == 0) &&
                 (r_data_new->alive == 1))
        {
            r_node->data->mode = r_data_new->mode;
            r_node->data->metric = r_data_new->metric;
            r_node->data->pipe_id = r_data_new->pipe_id;
            r_node->data->alive = r_data_new->alive;
            r_node->data->time = r_data_new->time;

            free(r_data_new);
            ret = 1;
        }
    }else
    {
        insert_route(&routing_table, ip_address, r_data_new);

        ret = 1;
    }

    return ret;
}

void update_routing_table(struct stack_head *stack)
{
    struct map_node_thread *thread = NULL;
    struct spider_message *routing_message = NULL;
    int32_t ret = 0;
    char *ip_address = NULL;
    char mode;
    uint8_t metric;
    uint32_t pipe_id;
    byte alive;
    struct timeval time;
    int32_t data_size;
    char *data = NULL;
    int32_t i = 0;
    int32_t ip_address_and_route_data_size = INET6_ADDR_STRING_LENGTH + 1 + sizeof(struct route_data);
    route_data *r_data = NULL;
    route_data *r_data_new = NULL;
    bool update_routing_table_flag = false;

    while(1)
    {
        routing_message = pop_routing_message();
        if(routing_message != NULL)
        {
            if(routing_message->header.message_type == 'r') // routing message
            {
                pipe_id = routing_message->header.pipe_id;
                data_size = routing_message->header.data_size;
                data = (char *)&routing_message->data;

                if(encryption_flag == 1)    // xor
                {
                    ret = xor_decrypt(x_key, data, data_size, data_size);
                    if(ret <= 0)
                    {
#ifdef _DEBUG
                        printf("[-] update_routing_table xor_decrypt error: %d\n", ret);
#endif

                        free(routing_message);

                        continue;
                    }

                    data_size = ret;
                }else if(encryption_flag == 2)  // aes
                {
                    ret = aes_decrypt(a_key, data, data_size, data_size);
                    if(ret <= 0)
                    {
#ifdef _DEBUG
                        printf("[-] update_routing_table aes_decrypt error: %d\n", ret);
#endif

                        free(routing_message);

                        continue;
                    }

                    data_size = ret;
                }

                for(i = 0; i + ip_address_and_route_data_size <= data_size; data += ip_address_and_route_data_size, i += ip_address_and_route_data_size)
                {
                    ip_address = data;
                    if(is_spider_ip(ip, ip_address))
                    {
                        continue;
                    }

                    r_data = (route_data *)(data + INET6_ADDR_STRING_LENGTH + 1);

                    r_data_new = (route_data *)calloc(1, sizeof(struct route_data));

                    r_data_new->mode = 'a';

                    if(r_data->metric < UINT8_MAX)
                    {
                        r_data_new->metric = r_data->metric + 1;    // +1
                    }else
                    {
                        r_data_new->metric = UINT8_MAX;
                    }

                    r_data_new->pipe_id = pipe_id;

                    r_data_new->alive = r_data->alive;

                    if(gettimeofday(&r_data_new->time, NULL) == -1)
                    {
#ifdef _DEBUG
                        printf("[-] update_routing_table gettimeofday error\n");
#endif
                        r_data_new->time.tv_sec = 0;
                        r_data_new->time.tv_usec = 0;
                    }

#ifdef _DEBUG
//                    printf("[+] update_routing_table ip: %s pipe_id: %u metric: %d alive: %d\n", ip_address, r_data_new->pipe_id, r_data_new->metric, r_data_new->alive);
#endif

                    ret = update_route(ip_address, r_data_new);
                    if(ret == 1)
                    {
                        update_routing_table_flag = true;
                    }
                }

                if(update_routing_table_flag)
                {
                    send_routing_table();
                    update_routing_table_flag = false;
                }
            }else
            {
#ifdef _DEBUG
                printf("[-] update_routing_table unknown message type: %c\n", routing_message->header.message_type);
#endif
            }

            free(routing_message);
        }

        millisleep(5);
    }

error:
    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] update_routing_table is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] update_routing_table cannot free stack\n");
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

static void delete_routing_table_inorder_avlt_node_route(struct avlt_node_route *root, char *ip_address)
{
    int ret = 0;
    struct timeval now;
    long d = 0;

    if(root != NULL)
    {
        delete_routing_table_inorder_avlt_node_route(root->left, ip_address);

        if(root->data->alive == 0 && strlen(ip_address) == 0)  // dead
        {
            ret = gettimeofday(&now, NULL);
            if(ret == 1)
            {
#ifdef _DEBUG
                printf("[-] delete_routing_table_inorder_avlt_node_route gettimeofday error\n");
#endif
                return;
            }

            d = now.tv_sec - root->data->time.tv_sec;

            if(d >= DELETE_ROUTE_TIME)
            {
                strcpy(ip_address, root->ip);
            }
        }

        delete_routing_table_inorder_avlt_node_route(root->right, ip_address);
    }
}

void delete_routing_table(struct stack_head *stack)
{
    map_node_thread *thread = NULL;
    char *ip_address = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));

    if(routing_table == NULL)
    {
        goto error;
    }

    while(1)
    {
        semaphore_wait(&sem_routing_table);

        delete_routing_table_inorder_avlt_node_route(routing_table, ip_address);

        semaphore_post(&sem_routing_table);

        if(strlen(ip_address) > 0)
        {
            delete_route(&routing_table, ip_address);

            memset(ip_address, 0, INET6_ADDR_STRING_LENGTH + 1);
        }

        millisleep(100);
    }

error:
    thread = search_map_node_thread(m_thread, stack->thread_id);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] delete_routing_table is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] delete_routing_table cannot free stack\n");
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

