/*
 * Title:  semaphore.c
 * Author: Shuichiro Endo
 */

#include "semaphore.h"

void semaphore_init(struct semaphore *sem, int initial_value)
{
    sem->count = initial_value;
}

void semaphore_wait(struct semaphore *sem)
{
    while(1)
    {
        while(sem->count <= 0)
        {
            futex_wait(&sem->count, sem->count);
        }

        __asm__ __volatile__
        (
            "lock\n"
            "decl %0"
            : "=m"(sem->count)
            : "m"(sem->count)
            : "cc"
        );

        if(sem->count >= 0)
        {
            break;
        }
    }
}

void semaphore_post(struct semaphore *sem)
{
    __asm__ __volatile__
    (
        "lock\n"
        "incl %0"
        : "=m"(sem->count)
        : "m"(sem->count)
        : "cc"
    );

    if(sem->count > 0)
    {
        futex_wake(&sem->count, 1);
    }
}

