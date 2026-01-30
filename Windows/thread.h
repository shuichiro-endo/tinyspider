/*
 * Title:  thread.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef THREAD_H_
#define THREAD_H_

#include "stdfunc.h"

typedef struct map_node_thread
{
    HANDLE handle;
    byte alive;  // dead:0 alive:1
    struct map_node_thread *next;
} map_node_thread;

typedef struct map_thread
{
    struct map_node_thread *head;
} map_thread;

typedef struct function_args
{
    HANDLE handle;
    void *args;
} function_args;

int create_map_thread(struct map_thread **map);
void insert_map_node_thread(struct map_thread *map, HANDLE handle, byte alive);
struct map_node_thread *search_map_node_thread(struct map_thread *map, HANDLE handle);
struct map_node_thread *search_map_node_thread_dead_thread(struct map_thread *map);
void delete_map_node_thread(struct map_thread *map, HANDLE handle);
void delete_map_node_thread_dead_thread(struct map_thread *map);
void print_map_node_thread(struct map_thread *map);
void free_map_thread(struct map_thread *map);

void free_thread_stack(struct function_args *args);

void start_thread(struct map_thread *map, void *entry, struct function_args *args);

#endif /* THREAD_H_ */

