/*
 * Title:  spidercommmand.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef SPIDERCOMMAND_H_
#define SPIDERCOMMAND_H_

#include "stdfunc.h"
#include "semaphore.h"
#include "queue.h"
#include "route.h"
#include "message.h"
#include "thread.h"
#include "pipe.h"
#include "client.h"
#include "server.h"
#include "spiderip.h"

void add_node_spider_pipe();
void add_node_spider_client();
void show_node_information();
void show_routing_table();

#endif /* SPIDERCOMMAND_H_ */

