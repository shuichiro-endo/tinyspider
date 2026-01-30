/*
 * Title:  tinyspider.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef TINYSPIDER_H_
#define TINYSPIDER_H_

#define SPIDER_COMMAND_ADD_NODE_SPIDER_PIPE                         1
#define SPIDER_COMMAND_ADD_NODE_SPIDER_CLIENT                       2
#define SPIDER_COMMAND_SHOW_NODE_INFORMATION                        3
#define SPIDER_COMMAND_SHOW_ROUTING_TABLE                           4
#define SPIDER_COMMAND_EXIT                                         0

#include "stdfunc.h"
#include "spiderip.h"
#include "dns.h"
#include "thread.h"
#include "route.h"
#include "queue.h"
#include "rbtree.h"
#include "xor.h"
#include "aes.h"
#include "message.h"
#include "pipe.h"
#include "client.h"
#include "server.h"
#include "spidercommand.h"

static void print_title();
static void usage(char *filename);
static int getopt(int argc, char **argv, const char *optstring);
int init(void);
int finish(void);
void __main(void);
int main(int argc, char **argv);
void _start(void) __attribute((force_align_arg_pointer));

#endif /* TINYSPIDER_H_ */

