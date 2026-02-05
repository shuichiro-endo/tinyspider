/*
 * Title:  semaphore.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef SEMAPHORE_H_
#define SEMAPHORE_H_

#include "stdfunc.h"

typedef struct semaphore
{
    volatile int count;
} semaphore;

void semaphore_init(struct semaphore *sem, int initial_value);
void semaphore_wait(struct semaphore *sem);
void semaphore_post(struct semaphore *sem);

#endif /* SEMAPHORE_H_ */

