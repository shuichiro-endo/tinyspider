/*
 * Title:  tinyspider.c
 * Author: Shuichiro Endo
 * Ver:    0.0.1
 */

#include "tinyspider.h"

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
extern struct avlt_node_route *routing_table;
extern struct queue *routing_message_queue;
extern struct queue *socks5_message_queue;

static int optstring_index = 0;
static char *optarg = NULL;
int encryption_flag = 0;    // no:0 xor:1 aes:2
struct xor_key *x_key = NULL;
struct aes_key *a_key = NULL;

static void print_title()
{
    printf("\n");
    printf(" .-.  _                          _    .-.           \n");
    printf(".' `.:_;                        :_;   : :           \n");
    printf("`. .'.-.,-.,-..-..-. .--. .---. .-. .-' : .--. .--. \n");
    printf(" : : : :: ,. :: :; :`._-.': .; `: :' .; :' '_.': ..'\n");
    printf(" :_; :_;:_;:_;`._. ;`.__.': ._.':_;`.__.'`.__.':_;  \n");
    printf("               .-. :      : :                     🕷️\n");
    printf("               `._.'      :_;        Linux Ver: 0.01\n");
    printf("                              Author: Shuichiro Endo\n");
    printf("\n");
}

static void usage(char *filename)
{
    printf("\n");
    printf("usage   : %s\n", filename);
    printf("        : [-4 spider_ipv4] [-6 spider_ipv6_global] [-u spider_ipv6_unique_local] [-l spider_ipv6_link_local]\n");
    printf("        : [-e x(xor encryption)] [-k key(hexstring)]\n");
    printf("        : [-e a(aes-256-cbc encryption)] [-k key(hexstring)] [-v iv(hexstring)]\n");
    printf("        : [-s (prevent spider server startup)]\n");
    printf("example : %s -4 192.168.0.10\n", filename);
    printf("        : %s -6 2001::xxxx:xxxx:xxxx:xxxx\n", filename);
    printf("        : %s -u fd00::xxxx:xxxx:xxxx:xxxx\n", filename);
    printf("        : %s -l fe80::xxxx:xxxx:xxxx:xxxx%%2\n", filename);
    printf("        : %s -4 192.168.0.10 -6 2001::xxxx:xxxx:xxxx:xxxx -u fd00::xxxx:xxxx:xxxx:xxxx -l fe80::xxxx:xxxx:xxxx:xxxx%%2\n", filename);
    printf("        : %s -4 192.168.0.10 -e x -k deadbeef\n", filename);
    printf("        : %s -4 192.168.0.10 -e a -k 47a2baa1e39fa16752a2ea8e8e3e24256b3c360f382b9782e2e57d4affb19f8c -v c87114c8b36088074c7ec1398f5c168a\n", filename);
    printf("        : %s -4 192.168.0.10 -s\n", filename);
    printf("\n");
}

static int getopt(int argc, char **argv, const char *optstring)
{
    unsigned char opt = '\0';
    unsigned char next = '\0';
    char *argtmp = NULL;

    while(1){
        opt = *(optstring + optstring_index);
        optstring_index++;
        if(opt == '\0'){
            break;
        }

        next = *(optstring + optstring_index);
        if(next == ':'){
            optstring_index++;
        }

        for(int i=1; i<argc; i++){
            argtmp = argv[i];
            if(argtmp[0] == '-'){
                if(argtmp[1] == opt){
                    if(next == ':'){
                        optarg = argv[i+1];
                        return (int)opt;
                    }else{
                        return (int)opt;
                    }
                }
            }
        }
    }

    return 0;
}

void dummy()
{
    return;
}

int main(int argc, char **argv, char **envp)
{
    int opt;
    const char *optstring = "h:4:6:u:l:e:k:v:s";
    int opterr = 0;
    char *spider_ipv4 = NULL;
    char *spider_ipv6_global = NULL;
    char *spider_ipv6_unique_local = NULL;
    char *spider_ipv6_link_local = NULL;
    char *pos = NULL;
    int32_t ret = 0;
    int i = 0;
    char *routing_mode = "a";
    char *encryption_type = NULL;
    char *key = NULL;
    char *iv = NULL;
    bool xor_flag = false;
    bool aes_flag = false;
    char *xor_key_hex_string = NULL;
    char *aes_key_hex_string = NULL;
    char *aes_iv_hex_string = NULL;
    bool prevent_spider_server_startup_flag = false;
    char *dns_server = NULL;
    char buffer[10] = {0};
    int spider_command_input = 0;

    while((opt = getopt(argc, argv, optstring)) > 0)
    {
        switch(opt)
        {
            case 'h':
                print_title();
                usage(argv[0]);
                return -1;

            case '4':
                spider_ipv4 = optarg;
                break;

            case '6':
                spider_ipv6_global = optarg;
                break;

            case 'u':
                spider_ipv6_unique_local = optarg;
                break;

            case 'l':
                spider_ipv6_link_local = optarg;
                break;

            case 'e':
                encryption_type = optarg;
                break;

            case 'k':
                key = optarg;
                break;

            case 'v':
                iv = optarg;
                break;

            case 's':
                prevent_spider_server_startup_flag = true;
                break;

            default:
                print_title();
                usage(argv[0]);
                return -1;
        }
    }

    print_title();

    sigaction_ign sa;
    memset(&sa, 0, sizeof(struct sigaction));

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTORER;
    sa.sa_restorer = dummy;

    ret = rt_sigaction(SIGPIPE, (struct sigaction *)&sa, NULL, 8);
    if(ret < 0)
    {
        printf("[-] rt_sigaction error: %d\n", ret);

        return -1;
    }

    if(spider_ipv4 == NULL && spider_ipv6_global == NULL && spider_ipv6_unique_local == NULL && spider_ipv6_link_local == NULL)
    {
        usage(argv[0]);

        return -1;
    }else
    {
        ip = (spider_ip *)calloc(1, sizeof(struct spider_ip));
        ip->spider_ipv4 = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
        ip->spider_ipv6_global = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
        ip->spider_ipv6_unique_local = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
        ip->spider_ipv6_link_local = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));
        ip->spider_ipv6_link_local_scope_id = (char *)calloc(INET6_ADDR_STRING_LENGTH + 1, sizeof(char));

        if(spider_ipv4 != NULL)
        {
            strcpy(ip->spider_ipv4, spider_ipv4);
        }

        if(spider_ipv6_global != NULL)
        {
            strcpy(ip->spider_ipv6_global, spider_ipv6_global);
        }

        if(spider_ipv6_unique_local != NULL)
        {
            strcpy(ip->spider_ipv6_unique_local, spider_ipv6_unique_local);
        }

        if(spider_ipv6_link_local != NULL)
        {
            strcpy(ip->spider_ipv6_link_local, spider_ipv6_link_local);

            pos = strstr(ip->spider_ipv6_link_local, "%");
            if(pos == NULL)
            {
#ifdef _DEBUG
                printf("[-] ipv6 link local address does not include a scope id\n");
#endif
                print_title();
                usage(argv[0]);

                return -1;
            }

            *pos++ = '\0';

            strcpy(ip->spider_ipv6_link_local_scope_id, pos);

            if(!atoi(ip->spider_ipv6_link_local_scope_id))
            {
#ifdef _DEBUG
                printf("[-] scope id is not a number\n");
#endif
                print_title();
                usage(argv[0]);

                return -1;
            }

            for(i = 0; i < strlen(pos); i++)
            {
                *pos++ = '\0';
            }
        }
    }

    if(encryption_type != NULL && *encryption_type == 'x') // xor
    {
        encryption_flag = 1;
        xor_flag = true;
        xor_key_hex_string = key;

        ret = init_xor(&x_key, key);
        if(ret < 0)
        {
            goto error;
        }
    }else if(encryption_type != NULL && *encryption_type == 'a')   // aes
    {
        encryption_flag = 2;
        aes_flag = true;
        aes_key_hex_string = key;
        aes_iv_hex_string = iv;

        ret = init_aes(&a_key, key, iv);
        if(ret < 0)
        {
            goto error;
        }
    }else   // no
    {
        encryption_flag = 0;
    }

    dns_server = get_dns_name_servers();
    if(dns_server == NULL)
    {
        goto error;
    }

    init_tree_spider_node();

    create_map_thread(&m_thread);

    start_thread(m_thread, (void *)free_thread_stack, NULL);

    init_routing_table();

    routing_message_queue = create_queue();
    socks5_message_queue = create_queue();

    if(routing_mode != NULL && (strcmp(routing_mode, "a") == 0)) // auto
    {
        start_thread(m_thread, (void *)update_routing_table, NULL);
        sleep(0.1);

        start_thread(m_thread, (void *)delete_routing_table, NULL);
        sleep(0.1);
    }

    start_thread(m_thread, (void *)message_worker, &prevent_spider_server_startup_flag);

    while(1)
    {
        printf("\n");
        printf("---------------------------------------- tiny spider ------------------------------------------\n");
        if(strlen(ip->spider_ipv4) > 0)
        {
            printf(" spider ipv4                     : %s\n", ip->spider_ipv4);
        }
        if(strlen(ip->spider_ipv6_global) > 0)
        {
            printf(" spider ipv6 global              : %s\n", ip->spider_ipv6_global);
        }
        if(strlen(ip->spider_ipv6_unique_local) > 0)
        {
            printf(" spider ipv6 unique local        : %s\n", ip->spider_ipv6_unique_local);
        }
        if(strlen(ip->spider_ipv6_link_local) > 0)
        {
            printf(" spider ipv6 link local          : %s\n", ip->spider_ipv6_link_local);
            if(strlen(ip->spider_ipv6_link_local_scope_id) > 0)
            {
                printf(" spider ipv6 link local scope id : %s\n", ip->spider_ipv6_link_local_scope_id);
            }
        }
        printf(" dns server                      : %s\n", dns_server);
        printf(" xor encryption                  : %s\n", (xor_flag ? "on" : "off"));
        printf(" xor key hex string              : %s\n", (xor_key_hex_string ? xor_key_hex_string : ""));
        printf(" aes encryption                  : %s\n", (aes_flag ? "on" : "off"));
        printf(" aes key hex string              : %s\n", (aes_key_hex_string ? aes_key_hex_string : ""));
        printf(" aes iv hex string               : %s\n", (aes_iv_hex_string ? aes_iv_hex_string : ""));
        printf(" prevent spider server startup   : %s\n", (prevent_spider_server_startup_flag ? "on" : "off"));
        printf("--------------------------------------- spider command ----------------------------------------\n");
        printf(" %d: add node (spider pipe)\n", SPIDER_COMMAND_ADD_NODE_SPIDER_PIPE);
        printf(" %d: add node (spider client)\n", SPIDER_COMMAND_ADD_NODE_SPIDER_CLIENT);
        printf(" %d: show node information\n", SPIDER_COMMAND_SHOW_NODE_INFORMATION);
        printf(" %d: show routing table\n", SPIDER_COMMAND_SHOW_ROUTING_TABLE);
        printf(" %d: exit\n", SPIDER_COMMAND_EXIT);
        printf("-----------------------------------------------------------------------------------------------\n");
        printf("\n");
        printf("command > ");

        char *ptr = fgets(buffer, 10, STDIN_FILENO);
        if(ptr != NULL)
        {
            spider_command_input = atoi(ptr);
            if(spider_command_input >= 0 && spider_command_input <=4)
            {
                switch(spider_command_input)
                {
                    case SPIDER_COMMAND_ADD_NODE_SPIDER_PIPE:
                        printf("[+] add node (spider pipe)\n");
                        add_node_spider_pipe();
                        break;

                    case SPIDER_COMMAND_ADD_NODE_SPIDER_CLIENT:
                        printf("[+] add node (spider client)\n");
                        add_node_spider_client();
                        break;

                    case SPIDER_COMMAND_SHOW_NODE_INFORMATION:
                        printf("[+] show node information\n");
                        show_node_information();
                        break;

                    case SPIDER_COMMAND_SHOW_ROUTING_TABLE:
                        printf("[+] show routing table\n");
                        show_routing_table();
                        break;

                    case SPIDER_COMMAND_EXIT:
                        printf("[+] exit\n");
                        goto exit_0;
                        break;

                    default:
                        break;
                }
            }

            memset(buffer, 0, 10);
        }
    }

exit_0:
/*
    free_avlt_tree_node_route(routing_table);
    free_xor_key(x_key);
    free_aes_key(a_key);
    free_spider_ip(ip);
*/
    return 0;

error:
/*
    free_avlt_tree_node_route(routing_table);
    free_xor_key(x_key);
    free_aes_key(a_key);
    free_spider_ip(ip);
*/
    return -1;
}

void _start(void)
{
    __asm__ __volatile__
    (
        "movq 0(%rsp), %rdi\n"
        "lea 8(%rsp), %rsi\n"
        "movq %rdi, %rax\n"
        "addq $2, %rax\n"
        "shl $3, %rax\n"
        "addq %rsp, %rax\n"
        "lea 0(%rax), %rdx\n"
        "call main\n"
        "movq %rax, %rdi\n"
        "movq $231, %rax\n"
        "syscall"
    );
}

