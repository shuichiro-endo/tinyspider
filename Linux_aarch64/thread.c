/*
 * Title:  thread.c
 * Author: Shuichiro Endo
 */

#include "thread.h"

extern long new_thread(stack_head *stack);

struct map_thread *m_thread = NULL;
struct semaphore sem_m_thread __attribute__((aligned(16)));

void create_map_thread(struct map_thread **map)
{
    semaphore_init(&sem_m_thread, 1);

    semaphore_wait(&sem_m_thread);

    *map = (map_thread *)calloc(1, sizeof(struct map_thread));
    (*map)->head = NULL;

    semaphore_post(&sem_m_thread);
}

void insert_map_node_thread(struct map_thread *map, tid_t thread_id, byte alive, void *stack)
{
    struct map_node_thread *node = NULL;

    semaphore_wait(&sem_m_thread);

    node = (struct map_node_thread *)calloc(1, sizeof(struct map_node_thread));
    node->thread_id = thread_id;
    node->alive = alive;
    node->stack = stack;
    node->next = map->head;
    map->head = node;

    semaphore_post(&sem_m_thread);
}

struct map_node_thread *search_map_node_thread(struct map_thread *map, tid_t thread_id)
{
    struct map_node_thread *current = NULL;

    semaphore_wait(&sem_m_thread);

    current = map->head;

    while(current != NULL)
    {
        if(current->thread_id == thread_id)
        {
            semaphore_post(&sem_m_thread);

            return current;
        }
        current = current->next;
    }

    semaphore_post(&sem_m_thread);

    return NULL;
}

struct map_node_thread *search_map_node_thread_dead_thread(struct map_thread *map)
{
    struct map_node_thread *current = NULL;

    semaphore_wait(&sem_m_thread);

    current = map->head;

    while(current != NULL)
    {
        if(current->alive == 0)
        {
            semaphore_post(&sem_m_thread);

            return current;
        }
        current = current->next;
    }

    semaphore_post(&sem_m_thread);

    return NULL;
}

void delete_map_node_thread(struct map_thread *map, tid_t thread_id)
{
    struct map_node_thread *current = NULL;
    struct map_node_thread *previous = NULL;

    semaphore_wait(&sem_m_thread);

    current = map->head;

    while(current != NULL && current->thread_id != thread_id)
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

    if(current->stack != NULL)
    {
        free(current->stack);
    }

    if(current != NULL)
    {
        free(current);
    }

    semaphore_post(&sem_m_thread);
}

void delete_map_node_thread_dead_thread(struct map_thread *map)
{
    struct map_node_thread *current = NULL;
    struct map_node_thread *previous = NULL;

    semaphore_wait(&sem_m_thread);

    current = map->head;

    while(current != NULL)
    {
        if(current->alive == 0) // dead
        {
            if(previous == NULL)
            {
                map->head = current->next;
            }else
            {
                previous->next = current->next;
            }

            if(current->stack != NULL)
            {
                free(current->stack);
            }

            free(current);

            if(previous == NULL)
            {
                current = map->head;
            }else
            {
                current = previous->next;
            }
        }else
        {
            previous = current;
            current = current->next;
        }
    }

    semaphore_post(&sem_m_thread);
}

void print_map_node_thread(struct map_thread *map)
{
    struct map_node_thread *current = NULL;

    semaphore_wait(&sem_m_thread);

    current = map->head;

    while(current != NULL)
    {
#ifdef _DEBUG
        printf("[+] print_map_node_thread thread_id: %d alive: %d stack: %x\n", current->thread_id, current->alive, current->stack);
#endif
        current = current->next;
    }

    semaphore_post(&sem_m_thread);
}

void free_map_thread(struct map_thread *map)
{
    struct map_node_thread *current = NULL;
    struct map_node_thread *next = NULL;

    semaphore_wait(&sem_m_thread);

    current = map->head;

    while(current != NULL)
    {
        next = current->next;

        if(current->stack != NULL)
        {
            free(current->stack);
        }

        free(current);

        current = next;
    }

    free(map);

    semaphore_post(&sem_m_thread);
}

void free_thread_stack(tid_t thread_id, struct stack_head *stack_head)
{
    while(1)
    {
        delete_map_node_thread_dead_thread(m_thread);

//        print_map_node_thread(m_thread);

        millisleep(500);
    }

    __asm__ __volatile__
    (
        "mov x0, #0x0\n"
        "mov w8, #0x5d\n"   // exit 93
        "svc #0x0"
    );
    __builtin_unreachable();
}

struct stack_head *start_thread(struct map_thread *map, void *entry, void *args)
{
    unsigned char *s_end = NULL;
    unsigned char *s_start = NULL;
    struct stack_head *s_head = NULL;
    tid_t thread_id = 0;

    s_end = (unsigned char *)calloc(STACK_SIZE, sizeof(unsigned char));
    s_start = s_end + STACK_SIZE;
    s_head = (struct stack_head *)(s_start - sizeof(struct stack_head));
    s_head->entry = (void *)entry;
    s_head->args = (void *)args;
    thread_id = (tid_t)new_thread(s_head);
    s_head->thread_id = thread_id;
    insert_map_node_thread(map, thread_id, 1, s_end);

    return s_head;
}

