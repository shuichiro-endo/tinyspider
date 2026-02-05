/*
 * Title:  queue.c
 * Author: Shuichiro Endo
 */

#include "stdfunc.h"
#include "queue.h"

struct queue *create_queue()
{
    struct queue *q = (struct queue *)calloc(1, sizeof(struct queue));
    q->front = NULL;
    q->rear = NULL;
    q->count = 0;
    semaphore_init(&q->sem, 1);
    q->finish = false;

    return q;
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
    while(1)
    {
        semaphore_wait(&q->sem);

        if(q->count >= QUEUE_MAX_SIZE)
        {
            semaphore_post(&q->sem);
            futex_wait(&q->count, q->count);

            if(q->finish)
            {
                q->count++;
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

        if(q->count >= 1)
        {
            futex_wake(&q->count, 1);
        }

        semaphore_post(&q->sem);
        break;
    }
}

void *dequeue(struct queue *q)
{
    while(1)
    {
        semaphore_wait(&q->sem);

        if(q->count <= 0)
        {
            semaphore_post(&q->sem);
            futex_wait(&q->count, q->count);

            if(q->finish)
            {
                q->count--;
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

        if(q->count <= QUEUE_MAX_SIZE)
        {
            futex_wake(&q->count, 1);
        }

        free(node);
        semaphore_post(&q->sem);

        return data;
    }
}

void free_queue(struct queue *q)
{
    semaphore_wait(&q->sem);

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

    free(q);

//  semaphore_post(&q->sem);
}

