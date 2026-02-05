/*
 * Title:  spiderip.h
 * Author: Shuichiro Endo
 */

#pragma once

#ifndef SPIDERIP_H_
#define SPIDERIP_H_

#include "stdfunc.h"

typedef struct spider_ip
{
    char *spider_ipv4;
    char *spider_ipv6_global;
    char *spider_ipv6_unique_local;
    char *spider_ipv6_link_local;
    char *spider_ipv6_link_local_scope_id;
} spider_ip;

int is_spider_ip(spider_ip *ip, char *buffer);
int is_not_spider_ip(struct spider_ip *s_ip, char *buffer);

void free_spider_ip(struct spider_ip *ip);

#endif /* SPIDERIP_H_ */
