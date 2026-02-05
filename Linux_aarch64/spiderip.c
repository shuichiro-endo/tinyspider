/*
 * Title:  spiderip.c
 * Author: Shuichiro Endo
 */

#include "spiderip.h"

spider_ip *ip = NULL;

int is_spider_ip(struct spider_ip *s_ip, char *buffer)
{
    if((strcmp(s_ip->spider_ipv4, buffer) == 0) ||
       (strcmp(s_ip->spider_ipv6_global, buffer) == 0) ||
       (strcmp(s_ip->spider_ipv6_unique_local, buffer) == 0) ||
       (strcmp(s_ip->spider_ipv6_link_local, buffer) == 0))
    {
        return 1;
    }

    return 0;
}

int is_not_spider_ip(struct spider_ip *s_ip, char *buffer)
{
    if((strcmp(s_ip->spider_ipv4, buffer) != 0) &&
       (strcmp(s_ip->spider_ipv6_global, buffer) != 0) &&
       (strcmp(s_ip->spider_ipv6_unique_local, buffer) != 0) &&
       (strcmp(s_ip->spider_ipv6_link_local, buffer) != 0))
    {
        return 1;
    }

    return 0;
}

void free_spider_ip(struct spider_ip *s_ip)
{
    if(s_ip != NULL)
    {
        if(s_ip->spider_ipv4 != NULL)
        {
            free(s_ip->spider_ipv4);
        }

        if(s_ip->spider_ipv6_global != NULL)
        {
            free(s_ip->spider_ipv6_global);
        }

        if(s_ip->spider_ipv6_unique_local != NULL)
        {
            free(s_ip->spider_ipv6_unique_local);
        }

        if(s_ip->spider_ipv6_link_local != NULL)
        {
            free(s_ip->spider_ipv6_link_local);
        }

        if(s_ip->spider_ipv6_link_local_scope_id != NULL)
        {
            free(s_ip->spider_ipv6_link_local_scope_id);
        }

        free(s_ip);
    }
}

