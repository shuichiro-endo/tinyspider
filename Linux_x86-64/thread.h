/*
 * Title:  thread.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef THREAD_H_
#define THREAD_H_

#include "stdfunc.h"
#include "semaphore.h"

typedef struct map_node_thread
{
    tid_t thread_id;
    byte alive;  // dead:0 alive:1
    void *stack;
    struct map_node_thread *next;
} map_node_thread;

typedef struct map_thread
{
    struct map_node_thread *head;
} map_thread;

void create_map_thread(struct map_thread **map);
void insert_map_node_thread(struct map_thread *map, tid_t thread_id, byte alive, void *stack);
struct map_node_thread *search_map_node_thread(struct map_thread *map, tid_t thread_id);
struct map_node_thread *search_map_node_thread_dead_thread(struct map_thread *map);
void delete_map_node_thread(struct map_thread *map, tid_t thread_id);
void delete_map_node_thread_dead_thread(struct map_thread *map);
void print_map_node_thread(struct map_thread *map);
void free_map_thread(struct map_thread *map);

void free_thread_stack(struct stack_head *stack_head);

struct stack_head *start_thread(struct map_thread *map, void *entry, void *args);

#endif /* THREAD_H_ */

