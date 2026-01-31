/*
 * Title:  tinyspider.c
 * Author: Shuichiro Endo
 */

#include "tinyspider.h"

extern HANDLE stdin;
extern HANDLE stdout;
extern HANDLE mallocaddress_mutex;
extern void *syscalladdress;

extern _WSAStartup WSAStartup;
extern _WSACleanup WSACleanup;
extern _WSAGetLastError WSAGetLastError;
extern _select select;
extern _socket socket;
extern _setsockopt setsockopt;
extern _bind bind;
extern _listen listen;
extern _accept accept;
extern _connect connect;
extern _recv recv;
extern _send send;
extern _recvfrom recvfrom;
extern _sendto sendto;
extern _closesocket closesocket;

extern struct spider_ip *ip;
extern struct map_thread *m_thread;
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
    printf("               .-. :      : :                       \n");
    printf("               `._.'      :_;      Windows Ver: 0.01\n");
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

int init(void)
{
    NTSTATUS status;
    _LoadLibraryA LoadLibraryA = NULL;
    HMODULE ws2_32_dll = NULL;

    syscalladdress = search_syscall_address("NtTestAlert");

    stdin = GetStdHandle(STD_INPUT_HANDLE);
    if(stdin == INVALID_HANDLE_VALUE)
    {
#ifdef _DEBUG
        printf("[-] stdin is INVALID_HANDLE_VALUE\n");
#endif
        return -1;
    }

    stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if(stdout == INVALID_HANDLE_VALUE)
    {
#ifdef _DEBUG
        printf("[-] stdout is INVALID_HANDLE_VALUE\n");
#endif
        return -1;
    }

    status = NtCreateMutant(&mallocaddress_mutex, 0x1F0001, NULL, false);
    if(!NT_SUCCESS(status))
    {
#ifdef _DEBUG
        printf("[-] init NtCreateMutant error: %x\n", status);
#endif
        return -1;
    }

    LoadLibraryA = GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryA");
    if(LoadLibraryA == NULL)
    {
#ifdef _DEBUG
        printf("[-] LoadLibraryA is null\n");
#endif
        return -1;
    }

    ws2_32_dll = LoadLibraryA("ws2_32.dll");
    if(ws2_32_dll == NULL)
    {
#ifdef _DEBUG
        printf("[-] ws2_32_dll is null\n");
#endif
        return -1;
    }

    WSAStartup = GetProcAddress(ws2_32_dll, "WSAStartup");
    if(WSAStartup == NULL)
    {
#ifdef _DEBUG
        printf("[-] WSAStartup is null\n");
#endif
        return -1;
    }

    WSACleanup = GetProcAddress(ws2_32_dll, "WSACleanup");
    if(WSACleanup == NULL)
    {
#ifdef _DEBUG
        printf("[-] WSACleanup is null\n");
#endif
        return -1;
    }

    WSAGetLastError = GetProcAddress(ws2_32_dll, "WSAGetLastError");
    if(WSAGetLastError == NULL)
    {
#ifdef _DEBUG
        printf("[-] WSAGetLastError is null\n");
#endif
        return -1;
    }

    select = GetProcAddress(ws2_32_dll, "select");
    if(select == NULL)
    {
#ifdef _DEBUG
        printf("[-] select is null\n");
#endif
        return -1;
    }

    socket = GetProcAddress(ws2_32_dll, "socket");
    if(socket == NULL)
    {
#ifdef _DEBUG
        printf("[-] socket is null\n");
#endif
        return -1;
    }

    setsockopt = GetProcAddress(ws2_32_dll, "setsockopt");
    if(setsockopt == NULL)
    {
#ifdef _DEBUG
        printf("[-] setsockopt is null\n");
#endif
        return -1;
    }

    bind = GetProcAddress(ws2_32_dll, "bind");
    if(bind == NULL)
    {
#ifdef _DEBUG
        printf("[-] bind is null\n");
#endif
        return -1;
    }

    listen = GetProcAddress(ws2_32_dll, "listen");
    if(listen == NULL)
    {
#ifdef _DEBUG
        printf("[-] listen is null\n");
#endif
        return -1;
    }

    accept = GetProcAddress(ws2_32_dll, "accept");
    if(accept == NULL)
    {
#ifdef _DEBUG
        printf("[-] accept is null\n");
#endif
        return -1;
    }

    connect = GetProcAddress(ws2_32_dll, "connect");
    if(connect == NULL)
    {
#ifdef _DEBUG
        printf("[-] connect is null\n");
#endif
        return -1;
    }

    recv = GetProcAddress(ws2_32_dll, "recv");
    if(recv == NULL)
    {
#ifdef _DEBUG
        printf("[-] recv is null\n");
#endif
        return -1;
    }

    send = GetProcAddress(ws2_32_dll, "send");
    if(send == NULL)
    {
#ifdef _DEBUG
        printf("[-] send is null\n");
#endif
        return -1;
    }

    recvfrom = GetProcAddress(ws2_32_dll, "recvfrom");
    if(recvfrom == NULL)
    {
#ifdef _DEBUG
        printf("[-] recvfrom is null\n");
#endif
        return -1;
    }

    sendto = GetProcAddress(ws2_32_dll, "sendto");
    if(sendto == NULL)
    {
#ifdef _DEBUG
        printf("[-] sendto is null\n");
#endif
        return -1;
    }

    closesocket = GetProcAddress(ws2_32_dll, "closesocket");
    if(closesocket == NULL)
    {
#ifdef _DEBUG
        printf("[-] closesocket is null\n");
#endif
        return -1;
    }

    return 0;
}

int finish(void)
{
    NTSTATUS status;

    status = NtClose(stdin);
    if(!NT_SUCCESS(status))
    {
        return -1;
    }

    status = NtClose(stdout);
    if(!NT_SUCCESS(status))
    {
        return -1;
    }

    status = NtClose(mallocaddress_mutex);
    if(!NT_SUCCESS(status))
    {
        return -1;
    }

    return 0;
}

void __main(void)
{

}

int main(int argc, char **argv)
{
    NTSTATUS status;
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
    WSADATA wsaData;
    char *dns_server = NULL;
    char buffer[10] = {0};
    struct function_args *free_thread_stack_args = NULL;
    struct function_args *update_routing_table_args = NULL;
    struct function_args *delete_routing_table_args = NULL;
    struct function_args *message_worker_args = NULL;
    int spider_command_input = 0;

    ret = init();
    if(ret != 0)
    {
        return -1;
    }

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

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    dns_server = get_dns_name_servers();
    if(dns_server == NULL)
    {
        goto error;
    }

    ret = init_tree_spider_node();
    if(ret != 0)
    {
        goto error;
    }

    ret = create_map_thread(&m_thread);
    if(ret != 0)
    {
        goto error;
    }

    free_thread_stack_args = (struct function_args *)calloc(1, sizeof(struct function_args));
    start_thread(m_thread, (void *)free_thread_stack, (void *)free_thread_stack_args);

    ret = init_routing_table();
    if(ret != 0)
    {
        goto error;
    }

    routing_message_queue = create_queue();
    socks5_message_queue = create_queue();

    if(routing_mode != NULL && (strcmp(routing_mode, "a") == 0)) // auto
    {
        update_routing_table_args = (struct function_args *)calloc(1, sizeof(struct function_args));
        start_thread(m_thread, (void *)update_routing_table, (void *)update_routing_table_args);

        delete_routing_table_args = (struct function_args *)calloc(1, sizeof(struct function_args));
        start_thread(m_thread, (void *)delete_routing_table, (void *)delete_routing_table_args);
    }

    message_worker_args = (struct function_args *)calloc(1, sizeof(struct function_args));
    message_worker_args->args = &prevent_spider_server_startup_flag;
    start_thread(m_thread, (void *)message_worker, (void *)message_worker_args);

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

        char *ptr = fgets(stdin, buffer, 10);
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
    if(update_routing_table_args = NULL)
    {
        NtTerminateThread(update_routing_table_args->handle, 0);
        NtClose(update_routing_table_args->handle);
        free(update_routing_table_args->handle);
    }

    if(delete_routing_table_args = NULL)
    {
        NtTerminateThread(delete_routing_table_args->handle, 0);
        NtClose(delete_routing_table_args->handle);
        free(delete_routing_table_args->handle);
    }

    if(message_worker_args = NULL)
    {
        NtTerminateThread(message_worker_args->handle, 0);
        NtClose(message_worker_args->handle);
        free(message_worker_args->handle);
    }

    if(free_thread_stack_args != NULL)
    {
        NtTerminateThread(free_thread_stack_args->handle, 0);
        NtClose(free_thread_stack_args->handle);
        free(free_thread_stack_args->handle);
    }

    WSACleanup();

    ret = finish();

    return 0;

error:
    if(update_routing_table_args = NULL)
    {
        NtTerminateThread(update_routing_table_args->handle, 0);
        NtClose(update_routing_table_args->handle);
        free(update_routing_table_args->handle);
    }

    if(delete_routing_table_args = NULL)
    {
        NtTerminateThread(delete_routing_table_args->handle, 0);
        NtClose(delete_routing_table_args->handle);
        free(delete_routing_table_args->handle);
    }

    if(message_worker_args = NULL)
    {
        NtTerminateThread(message_worker_args->handle, 0);
        NtClose(message_worker_args->handle);
        free(message_worker_args->handle);
    }

    if(free_thread_stack_args != NULL)
    {
        NtTerminateThread(free_thread_stack_args->handle, 0);
        NtClose(free_thread_stack_args->handle);
        free(free_thread_stack_args->handle);
    }

    WSACleanup();

    ret = finish();

    return -1;
}

void _start(void)
{
    static char *argv[CMDLINE_ARGV_MAX];
    int argc = 0;
    int ret = 0;

    argc = CmdlineToArgv(GetCommandLineW(), argv);

    ret = main(argc, argv);

    NtTerminateProcess(NtCurrentProcess(), ret);
}

