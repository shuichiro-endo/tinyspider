/*
 * Title:  queue.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef QUEUE_H_
#define QUEUE_H_

#define QUEUE_MAX_SIZE  100

#include "stdfunc.h"
#include "semaphore.h"

typedef struct queue_node
{
    void *data;
    struct queue_node *next;
} queue_node;

typedef struct queue
{
    struct queue_node *front;
    struct queue_node *rear;
    int count;
    struct semaphore sem;
    bool finish;
} queue;

queue *create_queue();
int is_empty(struct queue *q);
void *peek(struct queue *q);
void enqueue(struct queue *q, void *data);
void *dequeue(struct queue *q);
void free_queue(struct queue *q);

#endif /* QUEUE_H_ */

