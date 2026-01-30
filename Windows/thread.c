/*
 * Title:  thread.c
 * Author: Shuichiro Endo
 */

#include "thread.h"

struct map_thread *m_thread = NULL;
HANDLE mutex_m_thread = NULL;

int create_map_thread(struct map_thread **map)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;

    status = NtCreateMutant(&mutex_m_thread, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] create_map_thread NtCreateMutant error: %x\n", status);
#endif
        goto error;
    }

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] create_map_thread NtWaitForSingleObject error: %x\n", status);
#endif
        goto error;
    }

    *map = (map_thread *)calloc(1, sizeof(struct map_thread));
    (*map)->head = NULL;

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] create_map_thread NtReleaseMutant error: %x\n", status);
#endif
        goto error;
    }

    return 0;

error:
    NtClose(mutex_m_thread);

    return -1;
}

void insert_map_node_thread(struct map_thread *map, HANDLE handle, byte alive)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct map_node_thread *node = NULL;

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] insert_map_node_thread NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    node = (struct map_node_thread *)calloc(1, sizeof(struct map_node_thread));
    node->handle = handle;
    node->alive = alive;
    node->next = map->head;
    map->head = node;

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] insert_map_node_thread NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

struct map_node_thread *search_map_node_thread(struct map_thread *map, HANDLE handle)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct map_node_thread *current = NULL;

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] search_map_node_thread NtWaitForSingleObject error: %x\n", status);
#endif
        return NULL;
    }

    current = map->head;

    while(current != NULL)
    {
        if(current->handle == handle)
        {
            status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] search_map_node_thread NtReleaseMutant error: %x\n", status);
#endif
                return NULL;
            }

            return current;
        }
        current = current->next;
    }

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] search_map_node_thread NtReleaseMutant error: %x\n", status);
#endif
        return NULL;
    }

    return NULL;
}

struct map_node_thread *search_map_node_thread_dead_thread(struct map_thread *map)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct map_node_thread *current = NULL;

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] search_map_node_thread_dead_thread NtWaitForSingleObject error: %x\n", status);
#endif
        return NULL;
    }

    current = map->head;

    while(current != NULL)
    {
        if(current->alive == 0)
        {
            status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] search_map_node_thread_dead_thread NtReleaseMutant error: %x\n", status);
#endif
                return NULL;
            }

            return current;
        }
        current = current->next;
    }

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] search_map_node_thread_dead_thread NtReleaseMutant error: %x\n", status);
#endif
        return NULL;
    }

    return NULL;
}

void delete_map_node_thread(struct map_thread *map, HANDLE handle)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct map_node_thread *current = NULL;
    struct map_node_thread *previous = NULL;

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] delete_map_node_thread NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    current = map->head;

    while(current != NULL && current->handle != handle)
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

    if(current->handle != NULL)
    {
        NtClose(current->handle);
    }

    if(current != NULL)
    {
        free(current);
    }

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] delete_map_node_thread NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

void delete_map_node_thread_dead_thread(struct map_thread *map)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct map_node_thread *current = NULL;
    struct map_node_thread *previous = NULL;

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] delete_map_node_thread_dead_thread NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

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

            if(current->handle != NULL)
            {
                NtClose(current->handle);
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

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] delete_map_node_thread_dead_thread NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

void print_map_node_thread(struct map_thread *map)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct map_node_thread *current = NULL;

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_map_node_thread NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    current = map->head;

    while(current != NULL)
    {
#ifdef _DEBUG
        printf("[+] print_map_node_thread handle: %x alive: %d\n", current->handle, current->alive);
#endif
        current = current->next;
    }

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] print_map_node_thread NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

void free_map_thread(struct map_thread *map)
{
    NTSTATUS status;
    LONG previousCount_mutex = 0;
    struct map_node_thread *current = NULL;
    struct map_node_thread *next = NULL;

    status = NtWaitForSingleObject(mutex_m_thread, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] free_map_thread NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    current = map->head;

    while(current != NULL)
    {
        next = current->next;

        if(current->handle != NULL)
        {
            NtClose(current->handle);
        }

        free(current);

        current = next;
    }

    free(map);

    status = NtReleaseMutant(mutex_m_thread, &previousCount_mutex);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] free_map_thread NtReleaseMutant error: %x\n", status);
#endif
        return;
    }
}

void free_thread_stack(struct function_args *args)
{
    struct map_node_thread *thread = NULL;

    while(1)
    {
        delete_map_node_thread_dead_thread(m_thread);

//        print_map_node_thread(m_thread);

        millisleep(500);
    }

error:
    thread = search_map_node_thread(m_thread, args->handle);
    if(thread != NULL)
    {
#ifdef _DEBUG
        printf("[+] free_thread_stack is dead\n");
#endif

        thread->alive = 0;
    }else
    {
#ifdef _DEBUG
        printf("[-] free_thread_stack cannot close handle\n");
#endif
    }

    free(args);
}

void start_thread(struct map_thread *map, void *entry, struct function_args *args)
{
    NTSTATUS status;

    status = NtCreateThreadEx(&args->handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), entry, args, 0, 0, 0, 0, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] start_thread NtCreateThreadEx error: %x\n", status);
#endif
        return;
    }

    insert_map_node_thread(map, args->handle, 1);
}

