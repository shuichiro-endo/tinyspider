/*
 * Title:  dns.h
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
 * https://www.binarytides.com/dns-query-code-in-c-with-winsock/
 * https://www.ietf.org/rfc/rfc1035.txt
 * https://en.wikipedia.org/wiki/Domain_Name_System
 */

#pragma once

#ifndef DNS_H_
#define DNS_H_

#include "stdfunc.h"

/*
    3.2.2. TYPE values

    TYPE fields are used in resource records.  Note that these types are a
    subset of QTYPEs.

    TYPE            value and meaning

    A               1 a host address

    NS              2 an authoritative name server

    MD              3 a mail destination (Obsolete - use MX)

    MF              4 a mail forwarder (Obsolete - use MX)

    CNAME           5 the canonical name for an alias

    SOA             6 marks the start of a zone of authority

    MB              7 a mailbox domain name (EXPERIMENTAL)

    MG              8 a mail group member (EXPERIMENTAL)

    MR              9 a mail rename domain name (EXPERIMENTAL)

    NULL            10 a null RR (EXPERIMENTAL)

    WKS             11 a well known service description

    PTR             12 a domain name pointer

    HINFO           13 host information

    MINFO           14 mailbox or mail list information

    MX              15 mail exchange

    TXT             16 text strings
*/
#define TYPE_A      1
#define TYPE_NS     2
#define TYPE_MD     3
#define TYPE_MF     4
#define TYPE_CNAME  5
#define TYPE_SOA    6
#define TYPE_MB     7
#define TYPE_MG     8
#define TYPE_MR     9
#define TYPE_NULL   10
#define TYPE_WKS    11
#define TYPE_PTR    12
#define TYPE_HINFO  13
#define TYPE_MINFO  14
#define TYPE_MX     15
#define TYPE_TXT    16
#define TYPE_AAAA   28  // ipv6

#pragma pack(push, 1)
/*
    4.1.1. Header section format

    The header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    ID              A 16 bit identifier assigned by the program that
                    generates any kind of query.  This identifier is copied
                    the corresponding reply and can be used by the requester
                    to match up replies to outstanding queries.

    QR              A one bit field that specifies whether this message is a
                    query (0), or a response (1).

    OPCODE          A four bit field that specifies kind of query in this
                    message.  This value is set by the originator of a query
                    and copied into the response.  The values are:

                    0               a standard query (QUERY)

                    1               an inverse query (IQUERY)

                    2               a server status request (STATUS)

                    3-15            reserved for future use

    AA              Authoritative Answer - this bit is valid in responses,
                    and specifies that the responding name server is an
                    authority for the domain name in question section.

                    Note that the contents of the answer section may have
                    multiple owner names because of aliases.  The AA bit
                    corresponds to the name which matches the query name, or
                    the first owner name in the answer section.

    TC              TrunCation - specifies that this message was truncated
                    due to length greater than that permitted on the
                    transmission channel.

    RD              Recursion Desired - this bit may be set in a query and
                    is copied into the response.  If RD is set, it directs
                    the name server to pursue the query recursively.
                    Recursive query support is optional.

    RA              Recursion Available - this be is set or cleared in a
                    response, and denotes whether recursive query support is
                    available in the name server.

    Z               Reserved for future use.  Must be zero in all queries
                    and responses.

    RCODE           Response code - this 4 bit field is set as part of
                    responses.  The values have the following
                    interpretation:

                    0               No error condition

                    1               Format error - The name server was
                                    unable to interpret the query.

                    2               Server failure - The name server was
                                    unable to process this query due to a
                                    problem with the name server.

                    3               Name Error - Meaningful only for
                                    responses from an authoritative name
                                    server, this code signifies that the
                                    domain name referenced in the query does
                                    not exist.

                    4               Not Implemented - The name server does
                                    not support the requested kind of query.

                    5               Refused - The name server refuses to
                                    perform the specified operation for
                                    policy reasons.  For example, a name
                                    server may not wish to provide the
                                    information to the particular requester,
                                    or a name server may not wish to perform
                                    a particular operation (e.g., zone
                                    transfer) for particular data.

                    6-15            Reserved for future use.

    QDCOUNT         an unsigned 16 bit integer specifying the number of
                    entries in the question section.

    ANCOUNT         an unsigned 16 bit integer specifying the number of
                    resource records in the answer section.

    NSCOUNT         an unsigned 16 bit integer specifying the nuname
                    server resource records in the authority records
                    section.

    ARCOUNT         an unsigned 16 bit integer specifying the number of
                    resource records in the additional records section.
*/
typedef struct dns_header
{
    unsigned short id;

    unsigned char rd     :1;
    unsigned char tc     :1;
    unsigned char aa     :1;
    unsigned char opcode :4;
    unsigned char qr     :1;

    unsigned char rcode  :4;
    unsigned char cd     :1;
    unsigned char ad     :1;
    unsigned char z      :1;
    unsigned char ra     :1;

    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} dns_header;


/*
    4.1.2. Question section format

    The question section is used to carry the "question" in most queries,
    i.e., the parameters that define what is being asked.  The section
    contains QDCOUNT (usually 1) entries, each of the following format:

                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    QNAME           a domain name represented as a sequence of labels, where
                    each label consists of a length octet followed by that
                    number of octets.  The domain name terminates with the
                    zero length octet for the null label of the root.  Note
                    that this field may be an odd number of octets; no
                    padding is used.

    QTYPE           a two octet code which specifies the type of the query.
                    The values for this field include all codes valid for a
                    TYPE field, together with some more general codes which
                    can match more than one type of RR.

    QCLASS          a two octet code that specifies the class of the query.
                    For example, the QCLASS field is IN for the Internet.
*/
typedef struct question
{
    unsigned short qtype;
    unsigned short qclass;
} question;

typedef struct query
{
    unsigned char *name;
    struct question *question;
} query;


/*
     4 .1.3. Resource record format                                     *

     The answer, authority, and additional sections all share the same
     format: a variable number of resource records, where the number of
     records is specified in the corresponding count field in the header.
     Each resource record has the following format:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |                                               |
     /                                               /
     /                      NAME                     /
     |                                               |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |                      TYPE                     |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |                     CLASS                     |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |                      TTL                      |
     |                                               |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |                   RDLENGTH                    |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
     /                     RDATA                     /
     /                                               /
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

     where:

     NAME            a domain name to which this resource record pertains.

     TYPE            two octets containing one of the RR type codes.  This
                     field specifies the meaning of the data in the RDATA
                     field.

     CLASS           two octets which specify the class of the data in the
                     RDATA field.

     TTL             a 32 bit unsigned integer that specifies the time
                     interval (in seconds) that the resource record may be
                     cached before it should be discarded.  Zero values are
                     interpreted to mean that the RR can only be used for the
                     transaction in progress, and should not be cached.

     RDLENGTH        an unsigned 16 bit integer that specifies the length in
                     octets of the RDATA field.

     RDATA           a variable length string of octets that describes the
                     resource.  The format of this information varies
                     according to the TYPE and CLASS of the resource record.
                     For example, the if the TYPE is A and the CLASS is IN,
                     the RDATA field is a 4 octet ARPA Internet address.
*/
typedef struct r_record
{
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
} r_record;

typedef struct resource_record
{
    unsigned char *name;
    struct r_record *resource;
    unsigned char *rdata;
} resource_record;
#pragma pack(pop)

#define DNS_SERVERS_MAX_COUNT       10
#define DNS_SERVERS_MAX_SIZE        256
#define FILE_BUFFER_SIZE            1024
#define DNS_BUFFER_SIZE             65536
#define DNS_TIMEOUT_MILLISECOND     10000

char *get_dns_name_servers();
unsigned char *read_name(unsigned char *reader, unsigned char *buffer, int *count);
void change_to_dns_name_format(unsigned char *dns_name, unsigned char *host);
int get_host_by_name(char *host, int query_type, void *host_addr, int host_addr_size);

#endif /* DNS_H_ */

