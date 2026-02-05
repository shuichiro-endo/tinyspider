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
    long val = 0;
    int tmp = 0;
    int *count = (int *)&sem->count;

    while(1)
    {
        while(sem->count <= 0)
        {
            futex_wait(&sem->count, sem->count);
        }

        __asm__ __volatile__
        (
            "semaphore_wait_1:\n"
            "ldaxr %x0, [%[count]]\n"
            "sub %x0, %x0, #0x1\n"
            "stlxr %w1, %x0, [%[count]]\n"
            "cbnz %w1, semaphore_wait_1"
            : "=&r"(val),
              "=&r"(tmp),
              [count] "+r"(count)
            :
            : "memory", "cc"
        );

        if(sem->count >= 0)
        {
            break;
        }
    }
}

void semaphore_post(struct semaphore *sem)
{
    long val = 0;
    int tmp = 0;
    int *count = (int *)&sem->count;

    __asm__ __volatile__
    (
        "semaphore_post_1:\n"
        "ldaxr %x0, [%[count]]\n"
        "add %x0, %x0, #0x1\n"
        "stlxr %w1, %x0, [%[count]]\n"
        "cbnz %w1, semaphore_post_1"
        : "=&r"(val),
          "=&r"(tmp),
          [count] "+r"(count)
     :
     : "memory", "cc"
    );

    if(sem->count > 0)
    {
        futex_wake(&sem->count, 1);
    }
}

