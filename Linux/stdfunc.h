/*
 * Title:  stdfunc.h
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://gitlab.com/nowrep/tinylibc
 * https://nullprogram.com/blog/2023/03/23/
 * https://github.com/skeeto/scratch/blob/master/misc/stack_head.c
 */

#pragma once

#ifndef STDFUNC_H_
#define STDFUNC_H_

#include <stdarg.h>

#define SYS_read                    0
#define SYS_write                   1
#define SYS_open                    2
#define SYS_close                   3
#define SYS_mmap                    9
#define SYS_mprotect                10
#define SYS_munmap                  11
#define SYS_rt_sigaction            13
#define SYS_select                  23
#define SYS_dup2                    33
#define SYS_nanosleep               35
#define SYS_getpid                  39
#define SYS_socket                  41
#define SYS_connect                 42
#define SYS_accept                  43
#define SYS_sendto                  44
#define SYS_recvfrom                45
#define SYS_shutdown                48
#define SYS_bind                    49
#define SYS_listen                  50
#define SYS_setsockopt              54
#define SYS_getsockopt              55
#define SYS_clone                   56
#define SYS_fork                    57
#define SYS_exit                    60
#define SYS_fcntl                   72
#define SYS_gettimeofday            96
#define SYS_setsid                  112
#define SYS_gettid                  186
#define SYS_futex                   202
#define SYS_exit_group              231
#define SYS_getrandom               318

#define NULL                        ((void*)0)
#define UINT8_MAX                   255
#define MAX_STR_LEN                 256
#define MAX_PRINT_STR_LEN           1024
#define PAGE_SIZE                   4096
#define INET6_ADDR_STRING_LENGTH    46

#define STDIN_FILENO                0
#define STDOUT_FILENO               1
#define STDERR_FILENO               2

#define PROT_NONE                   0x0
#define PROT_READ                   0x1
#define PROT_WRITE                  0x2
#define PROT_EXEC                   0x4
#define MAP_SHARED                  0x1
#define MAP_PRIVATE                 0x2
#define MAP_ANONYMOUS               0x20
#define MAP_FAILED                  ((void *)-1)

#define F_GETFL                     3
#define F_SETFL                     4

#define O_RDONLY                    0
#define O_WRONLY                    1
#define O_RDWR                      2
#define O_CREAT                     64
#define O_EXCL                      128
#define O_TRUNC                     512
#define O_APPEND                    1024
#define O_NONBLOCK                  2048

#define AF_INET                     2
#define AF_INET6                    10

#define SOCK_STREAM                 1
#define SOCK_DGRAM                  2

#define IPPROTO_TCP                 6
#define IPPROTO_UDP                 17

#define SOL_SOCKET                  1

#define SO_REUSEADDR                2
#define SO_RCVTIMEO                 20

#define SIGHUP                      1
#define SIGINT                      2
#define SIGQUIT                     3
#define SIGILL                      4
#define SIGABRT                     6
#define SIGFPE                      8
#define SIGKILL                     9
#define SIGSEGV                     11
#define SIGPIPE                     13
#define SIGTERM                     15
#define SIGUSR1                     10
#define SIGUSR2                     12
#define SIGALRM                     14
#define SIGCHLD                     17
#define SIGCONT                     18
#define SIGSTOP                     19
#define SIGTSTP                     20
#define SIGTTIN                     21
#define SIGTTOU                     22

#define SIG_DFL                     0
#define SIG_IGN                     1

#define SA_RESTORER                 0x04000000

#define FD_SETSIZE                  1024

#define EINTR                       4
#define EAGAIN                      11

#define FUTEX_WAIT                  0
#define FUTEX_WAKE                  1

#define STACK_SIZE                  65536

typedef unsigned char       byte;
//typedef char               int8_t;
typedef unsigned char       uint8_t;
typedef short               int16_t;
typedef unsigned short      uint16_t;
typedef int                 int32_t;
typedef unsigned int        uint32_t;
typedef long                int64_t;
typedef unsigned long       uint64_t;
typedef unsigned long       size_t;
typedef long                ssize_t;

typedef int                 pid_t;
typedef int                 tid_t;

typedef unsigned int        uid_t;

typedef long                clock_t;

typedef long                time_t;

typedef enum { false, true } bool;

typedef union
{
    int sival_int;
    void *sival_ptr;
} sigval;

typedef struct sigset_t
{
    unsigned long sig[32];
} sigset_t;

typedef struct siginfo_t
{
    int si_signo;
    int si_errno;
    int si_code;
    int si_trapno;
    pid_t si_pid;
    uid_t si_uid;
    int si_status;
    clock_t si_utime;
    clock_t si_stime;
    sigval si_value;
    int si_int;
    void *si_ptr;
    int si_overrun;
    int si_timerid;
    void *si_addr;
    long si_band;
    int si_fd;
    short si_addr_lsb;
    void *si_lower;
    void *si_upper;
    int si_pkey;
    void *si_call_addr;
    int si_syscall;
    unsigned int si_arch;
} siginfo_t;

typedef struct sigaction_ign
{
    long sa_handler;
    void (*sa_sigaction)(int, struct siginfo_t *, void *);
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
} sigaction_ign;

typedef struct sigaction
{
    void (*sa_handler)(int);
    void (*sa_sigaction)(int, struct siginfo_t *, void *);
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
} sigaction;

typedef struct kernel_sigaction
{
    void (*k_sa_handler)(int);
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
} kernel_sigaction;

typedef struct fd_set
{
    unsigned long fds_bits[FD_SETSIZE / (8 * sizeof(unsigned long))];
} fd_set;

typedef struct tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
} tm;

typedef struct timeval
{
    long tv_sec;
    long tv_usec;
} timeval;

typedef struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
} timezone;

typedef unsigned short      sa_family_t;
typedef unsigned int        in_addr_t;
typedef unsigned short      in_port_t;
typedef int                 socklen_t;

typedef struct sockaddr
{
    sa_family_t sa_family;
    char        sa_data[];
} sockaddr;

typedef struct in_addr
{
    in_addr_t s_addr;
} in_addr;

typedef struct in6_addr
{
    uint8_t s6_addr[16];
} in6_addr;

typedef struct sockaddr_in
{
    sa_family_t    sin_family;
    in_port_t      sin_port;
    struct in_addr sin_addr;
} sockaddr_in;

typedef struct sockaddr_in6
{
    sa_family_t     sin6_family;
    in_port_t       sin6_port;
    uint32_t        sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t        sin6_scope_id;
} sockaddr_in6;

typedef struct __attribute__((aligned(16))) stack_head
{
    void (*entry)(struct stack_head *);
    void *args;
    tid_t thread_id;
    int join_futex;
} stack_head;

long syscall0(long n);
long syscall1(long n, long a);
long syscall2(long n, long a, long b);
long syscall3(long n, long a, long b, long c);
long syscall4(long n, long a, long b, long c, long d);
long syscall5(long n, long a, long b, long c, long d, long e);
long syscall6(long n, long a, long b, long c, long d, long e, long f);

ssize_t read(int fd, void *buffer, size_t count);
ssize_t write(int fd, void *buffer, size_t length);
int open(const char *pathname, int flags);
int close(int fd);
int mprotect(void *addr, size_t len, int prot);
void signal_trampoline(void) __attribute__((naked));
int rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact, size_t sigsetsize);
int select(int nfds, struct fd_set *readfds, struct fd_set *writefds, struct fd_set *exceptfds, struct timeval *timeout);
int dup2(int oldfd, int newfd);
pid_t getpid(void);
int socket(int domain, int type, int protocol);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int shutdown(int sockfd, int how);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
pid_t fork(void);
void exit(int status) __attribute__((noreturn));
pid_t setsid(void);
pid_t gettid(void);
void exit_group(int status) __attribute__((noreturn));
int fcntl(int fd, int cmd, int arg);
int gettimeofday(struct timeval *tv, struct timezone *tz);
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);

void futex_wait(__volatile__ int *addr, int value);
void futex_wake(__volatile__ int *addr, int value);

void FD_ZERO(fd_set *set);
void FD_SET(int fd, fd_set *set);
int FD_ISSET(int fd, fd_set *set);

void millisleep(int ms);
void sleep(int s);

long new_thread(stack_head *stack) __attribute__((naked));

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void free(void *ptr);
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *s, uint8_t c, size_t n);
void *memmove(void *dst, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strdup(const char *s);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strcat(char *dst, const char *src);
char *strncat(char *dst, const char *src, size_t n);
char *strstr(const char *haystack, const char *needle);
char *strchr(const char *s, int c);
char *strtok(char *str, const char *delim, char **saved_ptr);
long strtol(const char *str, int base);
int atoi(const char *nptr);
long atol(const char *nptr);

static void putstring(char *str);
static int putchar(char *str, char c);
static int putint(char *str, char fill, int width, int value);
static int putdouble(char *str, int width, double value);
static int putunsignedint(char *str, char fill, int width, unsigned int value);
static int putunsignedlong(char *str, char fill, int width, unsigned long value);
static int puthex(char *str, char fill, int width, unsigned char cap, unsigned long value);
static int putstr(char *str, char fill, int width, const char *src);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
int sprintf(char *str, const char *format, ...);
void printf(const char *format, ...);

char *fgets(char *s, int size, int fd);
int scanf(const char *format, ...);

uint16_t htons(uint16_t hostshort);
uint32_t htonl(uint32_t hostlong);
uint64_t htonll(uint64_t hostlonglong);
uint16_t ntohs(uint16_t netshort);
uint32_t ntohl(uint32_t netlong);
uint64_t ntohll(uint64_t netlonglong);
in_addr_t inet_addr(const char *cp);
char *inet_ntoa(in_addr in);
int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

static int is_leap_year(int year);
static int days_in_month(int month, int year);
char *ctime(const time_t *timep);


// spider function
char hex_char_to_int(char c);
void hex_string_to_array(const char *hex_string, int32_t hex_string_length, unsigned char *buffer, int32_t buffer_size);
void print_bytes(char *buffer, int buffer_length);
uint32_t generate_random_id();
int32_t recv_data(int32_t sock, char *buffer, int32_t buffer_size, long tv_sec, long tv_usec);
int32_t send_data(int32_t sock, char *buffer, int32_t buffer_length, long tv_sec, long tv_usec);

#endif /* STDFUNC_H_ */
