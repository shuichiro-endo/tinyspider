/*
 * Title:  dns.c
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
 * https://www.binarytides.com/dns-query-code-in-c-with-winsock/
 * https://www.ietf.org/rfc/rfc1035.txt
 * https://en.wikipedia.org/wiki/Domain_Name_System
 */

#include "dns.h"

extern _WSAGetLastError WSAGetLastError;
extern _socket socket;
extern _setsockopt setsockopt;
extern _recvfrom recvfrom;
extern _sendto sendto;
extern _closesocket closesocket;

char dns_servers[DNS_SERVERS_MAX_COUNT][DNS_SERVERS_MAX_SIZE] = { {0} };
int dns_server_count = 0;

unsigned char *read_name(unsigned char *reader, unsigned char *buffer, int *count)
{
    unsigned char *name = (unsigned char *)calloc(256, sizeof(unsigned char));
    unsigned int p = 0;
    unsigned int jumped = 0;
    unsigned int offset = 0;
    int i = 0;
    int j = 0;
    int name_len = 0;

    *count = 1;

    while(*reader != 0)
    {
        if(*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader + 1) - 49152;   // 49152 = 11000000 00000000
            reader = buffer + offset - 1;
            jumped = 1;
        }else
        {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if(jumped == 0)
        {
            *count = *count + 1;
        }
    }

    name[p] = '\0';

    if(jumped == 1)
    {
        *count = *count + 1;
    }

    name_len = strlen((const char *)name);

    for(i = 0; i < name_len; i++)
    {
        p = name[i];

        for(j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i++;
        }

        name[i] = '.';
    }

    name[i - 1] = '\0';

    return name;
}

void change_to_dns_name_format(unsigned char *dns_name, unsigned char *host)
{
    int lock = 0;
    int i = 0;
    int host_length = 0;

    char *ptr = dns_name;

    strcat((char *)host, ".");
    host_length = strlen((char *)host);

    for(i = 0; i < host_length; i++)
    {
        if(host[i] == '.')
        {
            *dns_name++ = i - lock;

            while(lock < i)
            {
                *dns_name++ = host[lock++];
            }

            lock++;
        }
    }

    *dns_name++ = '\0';
}


int get_host_by_name(char *host, int query_type, void *host_addr, int host_addr_size)
{
    if(dns_server_count <= 0)
    {
        return -1;
    }

    unsigned char *buffer = (unsigned char *)calloc(DNS_BUFFER_SIZE, sizeof(unsigned char));
    int buffer_len = 0;
    unsigned char *qname = NULL;
    unsigned char *reader = NULL;
    int i = 0;
    int j = 0;
    int stop = 0;
    int sock = 0;
    int32_t sen = 0;
    int32_t rec = 0;
    int32_t err = 0;
    char *colon = NULL;
    DWORD timeout = 0;
    struct sockaddr_in dst;
    struct sockaddr_in6 dst6;
    int sockaddr_len = 0;
    struct resource_record *answer_records = (struct resource_record *)calloc(20, sizeof(struct resource_record));
    struct resource_record *authority_records = (struct resource_record *)calloc(20, sizeof(resource_record));
    struct resource_record *additional_records = (struct resource_record *)calloc(20, sizeof(resource_record));
    struct dns_header *dns = NULL;
    struct question *qinfo = NULL;
    unsigned short qdcount = 0;
    unsigned short ancount = 0;
    unsigned short nscount = 0;
    unsigned short arcount = 0;
    unsigned short rdlength = 0;
    long *p = NULL;
    bool host_addr_flag = false;
    unsigned short pid = (unsigned short)NtGetCurrentProcessorNumber();

    dns = (dns_header *)buffer;
    dns->id = (unsigned short)htons(pid);
    dns->qr = 0;
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    qname = (unsigned char *)(buffer + sizeof(struct dns_header));
    change_to_dns_name_format(qname, (unsigned char *)host);

    qinfo = (question *)(buffer + sizeof(struct dns_header) + (strlen((const char *)qname) + 1));
    qinfo->qtype = htons(query_type);
    qinfo->qclass = htons(1);

    colon = strstr(dns_servers[0], ":");
    if(colon == NULL)   // ipv4
    {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(sock == INVALID_SOCKET)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name socket error: %d\n", WSAGetLastError());
#endif
            goto error;
        }

        timeout = DNS_TIMEOUT_MILLISECOND;

        if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(DWORD)) == SOCKET_ERROR)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name setsockopt error: %d\n", WSAGetLastError());
#endif
            closesocket(sock);
            goto error;
        }

        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53);
        dst.sin_addr.s_addr = inet_addr(dns_servers[0]);

        sen = sendto(sock, (char *)buffer, sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct question), 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));
        if(sen == SOCKET_ERROR)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name sendto error: %d\n", WSAGetLastError());
#endif
            closesocket(sock);
            goto error;
        }

        memset(buffer, 0, DNS_BUFFER_SIZE);

        sockaddr_len = sizeof(struct sockaddr_in);
        rec = recvfrom(sock, (char *)buffer, DNS_BUFFER_SIZE, 0, (struct sockaddr *)&dst, (socklen_t *)&sockaddr_len);
        if(rec == SOCKET_ERROR)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name recvfrom error: %d\n", WSAGetLastError());
#endif
            closesocket(sock);
            goto error;
        }
    }else   // ipv6
    {
        sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if(sock == INVALID_SOCKET)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name socket error: %d\n", WSAGetLastError());
#endif
            goto error;
        }

        timeout = DNS_TIMEOUT_MILLISECOND;

        if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == SOCKET_ERROR)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name setsockopt error: %d\n", WSAGetLastError());
#endif
            closesocket(sock);
            goto error;
        }

        memset(&dst6, 0, sizeof(dst6));
        dst6.sin6_family = AF_INET6;
        dst6.sin6_port = htons(53);
        if(inet_pton(AF_INET6, dns_servers[0], &dst6.sin6_addr) <= 0)
        {
            closesocket(sock);
            goto error;
        }

        sen = sendto(sock, (char *)buffer, sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct question), 0, (struct sockaddr *)&dst6, sizeof(struct sockaddr_in6));
        if(sen == SOCKET_ERROR)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name sendto error: %d\n", WSAGetLastError());
#endif
            closesocket(sock);
            goto error;
        }

        memset(buffer, 0, DNS_BUFFER_SIZE);

        sockaddr_len = sizeof(struct sockaddr_in6);
        rec = recvfrom(sock, (char *)buffer, DNS_BUFFER_SIZE, 0, (struct sockaddr *)&dst6, (socklen_t *)&sockaddr_len);
        if(rec == SOCKET_ERROR)
        {
#ifdef _DEBUG
            printf("[-] get_host_by_name recvfrom error: %d\n", WSAGetLastError());
#endif
            closesocket(sock);
            goto error;
        }
    }

    dns = (dns_header *)buffer;
    reader = buffer + sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct question);

    qdcount = ntohs(dns->qdcount);
    ancount = ntohs(dns->ancount);
    nscount = ntohs(dns->nscount);
    arcount = ntohs(dns->arcount);

    stop = 0;

    for(i = 0; i < ancount; i++)
    {
        answer_records[i].name = read_name(reader, buffer, &stop);
        reader = reader + stop;

        answer_records[i].resource = (struct r_record *)reader;
        reader = reader + sizeof(struct r_record);

        if(ntohs(answer_records[i].resource->type) == TYPE_A || ntohs(answer_records[i].resource->type) == TYPE_AAAA)
        {
            rdlength = ntohs(answer_records[i].resource->rdlength);
            answer_records[i].rdata = (unsigned char *)calloc(rdlength, sizeof(unsigned char));

            for(j = 0; j < rdlength; j++)
            {
                answer_records[i].rdata[j] = reader[j];
            }

            answer_records[i].rdata[rdlength] = '\0';
            reader = reader + rdlength;
        }else
        {
            answer_records[i].rdata = read_name(reader, buffer, &stop);
            reader = reader + stop;
        }
    }
/*
    for(i = 0; i < nscount; i++)
    {
        authority_records[i].name = read_name(reader, buffer, &stop);
        reader += stop;

        authority_records[i].resource = (r_record *)reader;
        reader += sizeof(r_record);

        authority_records[i].rdata = read_name(reader, buffer, &stop);
        reader += stop;
    }

    for(i = 0; i < arcount; i++)
    {
        additional_records[i].name = read_name(reader, buffer, &stop);
        reader += stop;

        additional_records[i].resource = (r_record *)reader;
        reader += sizeof(r_record);

        if(ntohs(additional_records[i].resource->type) == TYPE_A || ntohs(additional_records[i].resource->type) == TYPE_AAAA)
        {
            rdlength = ntohs(additional_records[i].resource->rdlength);
            additional_records[i].rdata = (unsigned char *)calloc(rdlength, sizeof(unsigned char));

            for(j=0; j < rdlength; j++)
            {
                additional_records[i].rdata[j] = reader[j];
            }

            additional_records[i].rdata[rdlength] = '\0';
            reader += rdlength;
        }else
        {
            additional_records[i].rdata = read_name(reader, buffer, &stop);
            reader += stop;
        }
    }
*/

    for(i = 0; i < ancount; i++)
    {
        if(ntohs(answer_records[i].resource->type) == TYPE_A)
        {
            p = (long *)answer_records[i].rdata;

            if(host_addr_flag == false && host_addr_size >= sizeof(struct sockaddr_in))
            {
                memcpy(&((struct sockaddr_in *)host_addr)->sin_addr, p, sizeof(struct in_addr));
                host_addr_flag = true;
            }
        }else if(ntohs(answer_records[i].resource->type) == TYPE_AAAA)
        {
            p = (long *)answer_records[i].rdata;

            if(host_addr_flag == false && host_addr_size >= sizeof(sockaddr_in6))
            {
                memcpy(&((struct sockaddr_in6 *)host_addr)->sin6_addr, p, sizeof(struct in6_addr));
                host_addr_flag = true;
            }
        }

        free(answer_records[i].name);
        free(answer_records[i].rdata);
    }
/*
    for(i = 0; i < nscount; i++)
    {
        free(authority_records[i].name);
        free(authority_records[i].rdata);
    }

    for(i = 0; i < arcount; i++)
    {
        free(additional_records[i].name);
        free(additional_records[i].rdata);
    }
*/
    free(answer_records);
    free(authority_records);
    free(additional_records);
    free(buffer);

    return 0;

error:
    free(answer_records);
    free(authority_records);
    free(additional_records);
    free(buffer);

    return -1;
}

char *get_dns_name_servers()
{
    NTSTATUS status;
    HANDLE rootKeyHandle = NULL;
    HANDLE keyHandle1 = NULL;
    HANDLE keyHandle2 = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING str;
    const char *registryPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
    KEY_FULL_INFORMATION keyFullInfo1;
    KEY_FULL_INFORMATION keyFullInfo2;
    ULONG ResultLength = 0;
    PKEY_NODE_INFORMATION pKeyNodeInfo = (PKEY_NODE_INFORMATION)calloc(1024, sizeof(char));
    PKEY_VALUE_FULL_INFORMATION pKeyValueFullInfo = (PKEY_VALUE_FULL_INFORMATION)calloc(2048, sizeof(char));
    char *buffer = (char *)calloc(1024, sizeof(char));
    char *path = (char *)calloc(2048, sizeof(char));
    wchar_t *pathWide = (wchar_t *)calloc(1024, sizeof(wchar_t));
    int i = 0;
    int j = 0;
    char *ptr = NULL;
    int nameServerLen = strlen("NameServer");
    int dhcpNameServerLen = strlen("DhcpNameServer");

    RtlInitUnicodeString(&str, L"\\Registry\\Machine");
    InitializeObjectAttributes(&objectAttributes, NULL, &str, 0x40, NULL, NULL);

    status = NtOpenKey(&rootKeyHandle, KEY_READ, &objectAttributes);
    if(!NT_SUCCESS(status))
    {
        goto error;
    }

    RtlInitUnicodeString(&str, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");
    InitializeObjectAttributes(&objectAttributes, rootKeyHandle, &str, 0x40, NULL, NULL);

    status = NtOpenKey(&keyHandle1, KEY_READ, &objectAttributes);
    if(!NT_SUCCESS(status))
    {
        goto error;
    }

    status = NtQueryKey(keyHandle1, KeyFullInformation, &keyFullInfo1, sizeof(KEY_FULL_INFORMATION), &ResultLength);
    if(!NT_SUCCESS(status))
    {
        goto error;
    }

    for(i = 0; i < keyFullInfo1.SubKeys; i++)
    {
        status = NtEnumerateKey(keyHandle1, i, KeyNodeInformation, pKeyNodeInfo, 1024, &ResultLength);
        if(!NT_SUCCESS(status))
        {
            goto error;
        }

        wcharToChar((wchar_t *)pKeyNodeInfo->Name, (char *)buffer, 1024);

        strcpy(path, registryPath);
        strcat(path, "\\");
        strcat(path, buffer);

        charToWchar(path, pathWide, sizeof(wchar_t) * 1024);

        RtlInitUnicodeString(&str, (PCWSTR)pathWide);
        InitializeObjectAttributes(&objectAttributes, rootKeyHandle, &str, 0x40, NULL, NULL);

        status = NtOpenKey(&keyHandle2, KEY_READ, &objectAttributes);
        if(!NT_SUCCESS(status))
        {
            goto error;
        }

        ResultLength = 0;
        status = NtQueryKey(keyHandle2, KeyFullInformation, &keyFullInfo2, sizeof(KEY_FULL_INFORMATION), &ResultLength);
        if(!NT_SUCCESS(status))
        {
            goto error;
        }

        for(j = 0; j < keyFullInfo2.Values; j++)
        {
            if(dns_server_count > DNS_SERVERS_MAX_COUNT - 1)
            {
                break;
            }

            ResultLength = 0;
            memset(pKeyValueFullInfo, 0, sizeof(char) * 1024);
            status = NtEnumerateValueKey(keyHandle2, j, KeyValueFullInformation, pKeyValueFullInfo, 2048, &ResultLength);
            if(!NT_SUCCESS(status))
            {
                break;
            }

            wcharToChar((wchar_t *)pKeyValueFullInfo->Name, (char *)buffer, 1024);

            ptr = buffer + nameServerLen;
            if(strncmp(buffer, "NameServer", nameServerLen) == 0 && *(char *)(ptr + 1) != '\0')
            {
                strcpy(dns_servers[dns_server_count++], ptr);
            }

            ptr = buffer + dhcpNameServerLen;
            if(strncmp(buffer, "DhcpNameServer", dhcpNameServerLen) == 0 && *(char *)(ptr + 1) != '\0')
            {
                strcpy(dns_servers[dns_server_count++], ptr);
            }
        }

        NtClose(keyHandle2);
    }

    if(dns_server_count == 0)
    {
        printf("[-] nameserver cannot find in HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\n");

        goto error;
    }else
    {
#ifdef _DEBUG
        printf("[+] nameserver found in HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces: %s\n", dns_servers[0]);
#endif
    }

    free(buffer);
    free(path);
    free(pathWide);
    free(pKeyNodeInfo);
    free(pKeyValueFullInfo);

    if(keyHandle2 != NULL)
    {
        NtClose(keyHandle2);
    }

    if(keyHandle1 != NULL)
    {
        NtClose(keyHandle1);
    }

    if(rootKeyHandle != NULL)
    {
        NtClose(rootKeyHandle);
    }

    return dns_servers[0];

error:
    free(buffer);
    free(path);
    free(pathWide);
    free(pKeyNodeInfo);
    free(pKeyValueFullInfo);

    if(keyHandle2 != NULL)
    {
        NtClose(keyHandle2);
    }

    if(keyHandle1 != NULL)
    {
        NtClose(keyHandle1);
    }

    if(rootKeyHandle != NULL)
    {
        NtClose(rootKeyHandle);
    }

    return NULL;
}

