/*
 * Title:  queue.c
 * Author: Shuichiro Endo
 */

#include "queue.h"

struct queue *create_queue()
{
    NTSTATUS status;
    struct queue *q = (struct queue *)calloc(1, sizeof(struct queue));
    HANDLE rootdir = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING str;

    q->front = NULL;
    q->rear = NULL;
    q->count = 0;

    status = BaseGetNamedObjectDirectory(&rootdir);
    if(!NT_SUCCESS(status))
    {
        return NULL;
    }

    RtlInitUnicodeString(&str, NULL);

    InitializeObjectAttributes(&objectAttributes, rootdir, &str, 0x80, NULL, NULL);

    status = NtCreateSemaphore(&q->semaphore, 0x1F0003, &objectAttributes, 0, QUEUE_MAX_SIZE);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] create_queue NtCreateSemaphore error: %x\n", status);
#endif
        goto error;
    }

    status = NtCreateMutant(&q->mutex, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] create_queue NtCreateMutant error: %x\n", status);
#endif
        goto error;
    }

    q->finish = false;

    NtClose(rootdir);

    return q;

error:
    NtClose(rootdir);

    return NULL;
}

int is_empty(struct queue *q)
{
    return (q->count == 0);
}

void *peek(struct queue *q)
{
    if(!is_empty(q))
    {
        return q->front->data;
    }

    return NULL;
}

void enqueue(struct queue *q, void *data)
{
    NTSTATUS status;
    LONG previousCount_semaphore = 0;
    LONG previousCount_mutex = 0;

    while(1)
    {
        status = NtWaitForSingleObject(q->mutex, false, NULL);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] enqueue NtWaitForSingleObject error: %x\n", status);
#endif
            q->finish = true;
            return;
        }

        if(q->finish)
        {
            return;
        }

        if(q->count >= QUEUE_MAX_SIZE)
        {
            status = NtReleaseMutant(q->mutex, &previousCount_mutex);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] enqueue NtReleaseMutant error: %x\n", status);
#endif
                q->finish = true;
                return;
            }

            continue;
        }

        struct queue_node *node = (struct queue_node *)calloc(1, sizeof(struct queue_node));
        node->data = data;
        node->next = NULL;

        if(q->rear == NULL)
        {
            q->front = node;
            q->rear = node;
        }else
        {
            q->rear->next = node;
            q->rear = node;
        }

        q->count++;

        status = NtReleaseSemaphore(q->semaphore, 1, &previousCount_semaphore);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] enqueue NtReleaseSemaphore error: %x\n", status);
#endif
            q->finish = true;
            return;
        }

        status = NtReleaseMutant(q->mutex, &previousCount_mutex);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] enqueue NtReleaseMutant error: %x\n", status);
#endif
            q->finish = true;
            return;
        }

        break;
    }
}

void enqueue_timeout(struct queue *q, void *data, LONGLONG timeout)
{
    NTSTATUS status;
    LARGE_INTEGER timeout_mutex;
    LONG previousCount_semaphore = 0;
    LONG previousCount_mutex = 0;

    timeout_mutex.QuadPart = timeout * -1LL;

    while(1)
    {
        status = NtWaitForSingleObject(q->mutex, false, &timeout_mutex);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] enqueue_timeout NtWaitForSingleObject error: %x\n", status);
#endif
            q->finish = true;
            return;
        }

        if(q->finish)
        {
            return;
        }

        if(q->count >= QUEUE_MAX_SIZE)
        {
            status = NtReleaseMutant(q->mutex, &previousCount_mutex);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] enqueue_timeout NtReleaseMutant error: %x\n", status);
#endif
                q->finish = true;
                return;
            }

            continue;
        }

        struct queue_node *node = (struct queue_node *)calloc(1, sizeof(struct queue_node));
        node->data = data;
        node->next = NULL;

        if(q->rear == NULL)
        {
            q->front = node;
            q->rear = node;
        }else
        {
            q->rear->next = node;
            q->rear = node;
        }

        q->count++;

        status = NtReleaseSemaphore(q->semaphore, 1, &previousCount_semaphore);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] enqueue_timeout NtReleaseSemaphore error: %x\n", status);
#endif
            q->finish = true;
            return;
        }

        status = NtReleaseMutant(q->mutex, &previousCount_mutex);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] enqueue_timeout NtReleaseMutant error: %x\n", status);
#endif
            q->finish = true;
            return;
        }

        break;
    }
}

void *dequeue(struct queue *q)
{
    NTSTATUS status;
    LONG previousCount_semaphore = 0;
    LONG previousCount_mutex = 0;

    while(1)
    {
        status = NtWaitForSingleObject(q->semaphore, false, NULL);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] dequeue NtWaitForSingleObject error: %x\n", status);
#endif
            q->finish = true;
            return NULL;
        }

        if(q->finish)
        {
            return NULL;
        }

        status = NtWaitForSingleObject(q->mutex, false, NULL);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] dequeue NtWaitForSingleObject error: %x\n", status);
#endif
            q->finish = true;
            return NULL;
        }

        if(q->finish)
        {
            return NULL;
        }

        if(q->count <= 0)
        {
            status = NtReleaseMutant(q->mutex, &previousCount_mutex);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] dequeue NtReleaseMutant error: %x\n", status);
#endif
                q->finish = true;
                return NULL;
            }

            status = NtReleaseSemaphore(q->semaphore, 1, &previousCount_semaphore);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] dequeue NtReleaseSemaphore error: %x\n", status);
#endif
                q->finish = true;
                return NULL;
            }

            continue;
        }

        struct queue_node *node = q->front;
        void *data = node->data;
        q->front = q->front->next;

        if(q->front == NULL)
        {
            q->rear = NULL;
        }

        q->count--;

        free(node);

        status = NtReleaseMutant(q->mutex, &previousCount_mutex);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] dequeue NtReleaseMutant error: %x\n", status);
#endif
            q->finish = true;
            return NULL;
        }

        return data;
    }
}

void *dequeue_timeout(struct queue *q, LONGLONG timeout)
{
    NTSTATUS status;
    LARGE_INTEGER timeout_mutex;
    LARGE_INTEGER timeout_semaphore;
    LONG previousCount_mutex = 0;
    LONG previousCount_semaphore = 0;

    timeout_mutex.QuadPart = timeout * -1LL;
    timeout_semaphore.QuadPart = timeout * -1LL;

    while(1)
    {
        status = NtWaitForSingleObject(q->semaphore, false, &timeout_mutex);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] dequeue_timeout NtWaitForSingleObject error: %x\n", status);
#endif
            q->finish = true;
            return NULL;
        }

        if(q->finish)
        {
            return NULL;
        }

        status = NtWaitForSingleObject(q->mutex, false, &timeout_semaphore);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] dequeue_timeout NtWaitForSingleObject error: %x\n", status);
#endif
            q->finish = true;
            return NULL;
        }

        if(q->finish)
        {
            return NULL;
        }

        if(q->count <= 0)
        {
            status = NtReleaseMutant(q->mutex, &previousCount_mutex);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] dequeue_timeout NtReleaseMutant error: %x\n", status);
#endif
                q->finish = true;
                return NULL;
            }

            status = NtReleaseSemaphore(q->semaphore, 1, &previousCount_semaphore);
            if(!NT_SUCCESS(status))
            {
#ifdef _DEBUG
                printf("[-] dequeue_timeout NtReleaseSemaphore error: %x\n", status);
#endif
                q->finish = true;
                return NULL;
            }

            continue;
        }

        struct queue_node *node = q->front;
        void *data = node->data;
        q->front = q->front->next;

        if(q->front == NULL)
        {
            q->rear = NULL;
        }

        q->count--;

        free(node);

        status = NtReleaseMutant(q->mutex, &previousCount_mutex);
        if(!NT_SUCCESS(status))
        {
#ifdef _DEBUG
            printf("[-] dequeue_timeout NtReleaseMutant error: %x\n", status);
#endif
            q->finish = true;
            return NULL;
        }

        return data;
    }
}

void free_queue(struct queue *q)
{
    NTSTATUS status;

    status = NtWaitForSingleObject(q->mutex, false, NULL);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] free_queue NtWaitForSingleObject error: %x\n", status);
#endif
        return;
    }

    while(1)
    {
        if(q->count <= 0)
        {
            break;
        }

        struct queue_node *node = q->front;
        void *data = node->data;
        q->front = q->front->next;

        if(q->front == NULL)
        {
            q->rear = NULL;
        }

        q->count--;

        free(node);
        free(data);
    }

    NtClose(q->mutex);
    NtClose(q->semaphore);

    free(q);

    return;
}

