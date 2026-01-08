/*
 * Title:  stdfunc.c
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://gitlab.com/nowrep/tinylibc
 * https://nullprogram.com/blog/2023/03/23/
 * https://github.com/skeeto/scratch/blob/master/misc/stack_head.c
 */

#include "stdfunc.h"

long syscall0(long n)
{
    register long ret;

    __asm__ __volatile__
    (
        "syscall"
        : "=a"(ret)
        : "a"(n)
        : "rcx", "r11", "memory"
    );

    return ret;
}

long syscall1(long n, long a)
{
    register long ret;

    __asm__ __volatile__
    (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a)
        : "rcx", "r11", "memory"
    );

    return ret;
}

long syscall2(long n, long a, long b)
{
    register long ret;

    __asm__ __volatile__
    (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a), "S"(b)
        : "rcx", "r11", "memory"
    );

    return ret;
}

long syscall3(long n, long a, long b, long c)
{
    register long ret;

    __asm__ __volatile__
    (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory"
    );

    return ret;
}

long syscall4(long n, long a, long b, long c, long d)
{
    register long ret;
    register long r10 __asm__("r10") = d;

    __asm__ __volatile__
    (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx", "r11", "memory"
    );

    return ret;
}

long syscall5(long n, long a, long b, long c, long d, long e)
{
    register long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;

    __asm__ __volatile__
    (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );

    return ret;
}

long syscall6(long n, long a, long b, long c, long d, long e, long f)
{
    register long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;

    __asm__ __volatile__
    (
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );

    return ret;
}

ssize_t read(int fd, void *buffer, size_t count)
{
    ssize_t ret = 0;

    ret = syscall3(SYS_read, fd, (long)buffer, count);
    if(ret < 0)
    {
        return ret;
    }

    return ret;
}

ssize_t write(int fd, void *buffer, size_t length)
{
    size_t offset = 0;
    ssize_t ret = 0;

    while(offset < length)
    {
        ret = syscall3(SYS_write, fd, (long)((char *)buffer + offset), length - offset);
        if(ret < 0)
        {
            return ret;
        }
        offset += ret;
    }

    return length;
}

int open(const char *pathname, int flags)
{
    int fd = 0;

    fd = syscall2(SYS_open, (long)pathname, flags);

    return fd;
}

int close(int fd)
{
    int ret = 0;

    ret = syscall1(SYS_close, fd);

    return ret;
}

int mprotect(void *addr, size_t len, int prot)
{
    int ret = 0;

    ret = syscall3(SYS_mprotect, (long)addr, len, prot);

    return ret;
}

int rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact, size_t sigsetsize)
{
    int ret = 0;

    ret = syscall4(SYS_rt_sigaction, signum, (long)act, (long)oldact, sigsetsize);

    return ret;
}

int select(int nfds, struct fd_set *readfds, struct fd_set *writefds, struct fd_set *exceptfds, struct timeval *timeout)
{
    int ret = 0;

    ret = syscall5(SYS_select, nfds, (long)readfds, (long)writefds, (long)exceptfds, (long)timeout);

    return ret;
}

int dup2(int oldfd, int newfd)
{
    int ret = 0;

    ret = syscall2(SYS_dup2, oldfd, newfd);

    return ret;
}

pid_t getpid(void)
{
    pid_t ret = 0;

    ret = syscall0(SYS_getpid);

    return ret;
}

int socket(int domain, int type, int protocol)
{
    int ret = 0;

    ret = syscall3(SYS_socket, domain, type, protocol);

    return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret = 0;

    ret = syscall3(SYS_connect, sockfd, (long)addr, addrlen);

    return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int ret = 0;

    ret = syscall3(SYS_accept, sockfd, (long)addr, (long)addrlen);

    return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ssize_t ret = 0;

    ret = syscall6(SYS_sendto, sockfd, (long)buf, len, flags, (long)dest_addr, addrlen);

    return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t ret = 0;

    ret = syscall6(SYS_recvfrom, sockfd, (long)buf, len, flags, (long)src_addr, (long)addrlen);

    return ret;
}

int shutdown(int sockfd, int how)
{
    int ret = 0;

    ret = syscall2(SYS_shutdown, sockfd, how);

    return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret = 0;

    ret = syscall3(SYS_bind, sockfd, (long)addr, addrlen);

    return ret;
}

int listen(int sockfd, int backlog)
{
    int ret = 0;

    ret = syscall2(SYS_listen, sockfd, backlog);

    return ret;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    int ret = 0;

    ret = syscall5(SYS_setsockopt, sockfd, level, optname, (long)optval, optlen);

    return ret;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    int ret = 0;

    ret = syscall5(SYS_getsockopt, sockfd, level, optname, (long)optval, (long)optlen);

    return ret;
}

pid_t fork(void)
{
    pid_t ret = 0;

    ret = syscall0(SYS_fork);

    return ret;
}

void exit(int status)
{
    syscall1(SYS_exit, status);

    __builtin_unreachable();
}

int gettimeofday(timeval *tv, timezone *tz)
{
    int ret = 0;

    ret = syscall2(SYS_gettimeofday, (long)tv, (long)tz);

    return ret;
}

pid_t setsid(void)
{
    pid_t ret = 0;

    ret = syscall0(SYS_setsid);

    return ret;
}

pid_t gettid(void)
{
    pid_t ret = 0;

    ret = syscall0(SYS_gettid);

    return 0;
}

void exit_group(int status)
{
    syscall1(SYS_exit_group, status);

    __builtin_unreachable();
}

int fcntl(int fd, int cmd, int arg)
{
    int ret = 0;

    ret = syscall3(SYS_fcntl, fd, cmd, arg);

    return ret;
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    ssize_t ret = 0;

    ret = syscall3(SYS_getrandom, (long)buf, buflen, flags);

    return ret;
}

void futex_wait(__volatile__ int *addr, int value)
{
    syscall6(SYS_futex, (long)addr, FUTEX_WAIT, value, (long)NULL, (long)NULL, 0);
}

void futex_wake(__volatile__ int *addr, int value)
{
    syscall6(SYS_futex, (long)addr, FUTEX_WAKE, value, (long)NULL, (long)NULL, 0);
}

void FD_ZERO(fd_set *set)
{
    int i = 0;

    for(i = 0; i < FD_SETSIZE / (8 * sizeof(unsigned long)); i++)
    {
        set->fds_bits[i] = 0;
    }
}

void FD_SET(int fd, fd_set *set)
{
    if(fd < 0 || fd >= FD_SETSIZE)
    {
        return;
    }

    set->fds_bits[fd / (8 * sizeof(unsigned long))] |= (1UL << (fd % (8 * sizeof(unsigned long))));
}

int FD_ISSET(int fd, fd_set *set)
{
    if (fd < 0 || fd >= FD_SETSIZE)
    {
        return 0;
    }

    return (set->fds_bits[fd / (8 * sizeof(unsigned long))] & (1UL << (fd % (8 * sizeof(unsigned long))))) != 0;
}

void millisleep(int ms)
{
    long ts[] = { (ms / 1000), (ms % 1000) * 1000000L };

    syscall2(SYS_nanosleep, (long)ts, (long)ts);
}

void sleep(int s)
{
    long ts[] = { s, 0L };

    syscall2(SYS_nanosleep, (long)ts, (long)ts);
}

long new_thread(struct stack_head *stack)
{
    __asm__ __volatile__
    (
        "mov %%rdi, %%rsi\n"
        "mov $0x50f00, %%edi\n"
        "mov $56, %%eax\n"
        "syscall\n"
        "mov %%rsp, %%rdi\n"
        "ret"
        :
        :
        : "rax", "rcx", "rsi", "rdi", "r11", "memory"
    );
}

void *malloc(size_t size)
{
    void *ptr = NULL;
    size_t page_size = PAGE_SIZE;
    size_t total_size = 0;

    if(size <= 0)
    {
        return NULL;
    }

    total_size = (size + sizeof(size_t) + (page_size - 1)) & ~(page_size - 1);

    ptr = (void *)syscall6(SYS_mmap, 0, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(ptr == MAP_FAILED)
    {
        return NULL;
    }

    *(size_t *)ptr = total_size;

    return (char *)ptr + sizeof(size_t);
}

void *calloc(size_t nmemb, size_t size)
{
    void *ptr = NULL;
    size_t total_size = 0;
    size_t i = 0;

    if(nmemb <= 0 || size <= 0)
    {
        return NULL;
    }

    total_size = nmemb * size;

    ptr = malloc(total_size);
    if(ptr)
    {
        for(i = 0; i < total_size; i++)
        {
            ((char *)ptr)[i] = 0;
        }
    }

    return ptr;
}

void free(void *ptr)
{
    size_t block_size = 0;
    ssize_t ret = 0;

    if(ptr == NULL)
    {
        return;
    }

    block_size = *(size_t *)((char *)ptr - sizeof(size_t));

    ret = syscall2(SYS_munmap, (long)((char *)ptr - sizeof(size_t)), block_size);
}

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *dst_addr = (uint8_t *)dst;
    uint8_t *src_addr = (uint8_t *)src;
    size_t i = 0;

    for(i = 0; i < n; i++)
    {
        *dst_addr++ = *src_addr++;
    }

    return dst;
}

void *memset(void *s, uint8_t c, size_t n)
{
    uint8_t *s_addr = (uint8_t *)s;
    size_t i = 0;

    for(i = 0; i < n; i++)
    {
        *s_addr++ = c;
    }

    return s;
}

void *memmove(void *dst, const void *src, size_t n)
{
    uint8_t *dst_addr = (uint8_t *)dst;
    uint8_t *src_addr = (uint8_t *)src;
    size_t i = 0;

    for(i = 0; i < n; i++)
    {
        *dst_addr++ = *src_addr++;
    }

    return dst;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    uint8_t *s1_addr = (uint8_t *)s1;
    uint8_t *s2_addr = (uint8_t *)s2;

    while(n-- > 0)
    {
        if(*s1_addr++ != *s2_addr++)
        {
            return s1_addr[-1] < s2_addr[-1] ? -1 : 1;
        }
    }

    return 0;
}

size_t strlen(const char *s)
{
    size_t pos = 0;

    while(s[pos])
    {
        pos++;
    }

    return pos;
}

char *strcpy(char *dst, const char *src)
{
    char *ptr = dst;
    size_t i = 0;

    for(i = 0; src[i] != '\0'; i++, ptr++)
    {
        *ptr = *(src + i);
    }

    *ptr = '\0';

    return dst;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    char *ptr = dst;
    size_t i = 0;

    for(i = 0; src[i] != '\0' && i < n; i++, ptr++)
    {
        *ptr = *(src + i);
    }

    for(; i < n; i++, ptr++)
    {
        *ptr = '\0';
    }

    return dst;
}

char *strdup(const char *s)
{
    size_t length = 0;
    char *dup = NULL;

    if(s == NULL)
    {
        return NULL;
    }

    length = strlen(s);
    dup = (char *)calloc(1, length + 1);
    if(dup == NULL)
    {
        return NULL;
    }

    strncpy(dup, s, length);

    return dup;
}

int strcmp(const char *s1, const char *s2)
{
    return strncmp(s1, s2, strlen(s2));
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    while(*s1 && *s2 && n)
    {
        if(*s1 > *s2)
        {
            return 1;
        }

        if(*s1 < *s2)
        {
            return -1;
        }

        s1++;
        s2++;
        n--;
    }

    if(n < 1)
    {
        return 0;
    }

    if(*s1)
    {
        return 1;
    }

    if(*s2)
    {
        return -1;
    }

    return 0;
}

char *strcat(char *dst, const char *src)
{
    char *ptr = dst;

    while(*ptr != '\0')
    {
        ptr++;
    }

    while(*src != '\0')
    {
        *ptr++ = *src++;
    }

    *ptr = '\0';

    return dst;
}

char *strncat(char *dst, const char *src, size_t n)
{
    char *ptr = dst;

    while(*ptr != '\0')
    {
        ptr++;
    }

    while(n > 0 && *src != '\0')
    {
        *ptr++ = *src++;
        n--;
    }

    *ptr = '\0';

    return dst;
}

char *strstr(const char *haystack, const char *needle)
{
    if(*needle == '\0')
    {
        return (char *)haystack;
    }

    while(*haystack)
    {
        const char *h = haystack;
        const char *n = needle;

        while(*h && *n && (*h == *n))
        {
            h++;
            n++;
        }

        if(*n == '\0')
        {
            return (char *)haystack;
        }

        haystack++;
    }

    return NULL;
}

char *strchr(const char *s, int c)
{
    while(*s)
    {
        if(*s == (char)c)
        {
            return (char *)s;
        }
        s++;
    }

    return NULL;
}

char *strtok(char *str, const char *delim, char **saved_ptr)
{
    char *start = NULL;

    if(str == NULL && *saved_ptr != NULL)
    {
        str = *saved_ptr;
    }else if(str == NULL && *saved_ptr == NULL)
    {
        *saved_ptr = NULL;
        return NULL;
    }

    while(*str != '\0' && strchr(delim, *str))
    {
        str++;
    }

    if(*str == '\0')
    {
        *saved_ptr = NULL;
        return NULL;
    }

    start = str;

    while(*str && !strchr(delim, *str))
    {
        str++;
    }

    if(*str)
    {
        *str = '\0';
        *saved_ptr = str + 1;
    }else
    {
        *saved_ptr = NULL;
    }

    return start;
}

long strtol(const char *str, int base)
{
    size_t i = 0;
    long val = 0;

    switch(base)
    {
        case 16:
            while(str[i] && i < MAX_STR_LEN)
            {
                char c = str[i++];

                if(c >= '0' && c <= '9')
                {
                    val *= 16;
                    val += c - '0';
                }else if(c >= 'A' && c <= 'F')
                {
                    val *= 16;
                    val += c - 'A' + 10;
                }else if(c >= 'a' && c <= 'f')
                {
                    val *= 16;
                    val += c - 'a' + 10;
                }else if(val)
                {
                    break;
                }
            }
            break;

        case 10:
            while(str[i] && i < MAX_STR_LEN)
            {
                char c = str[i++];

                if(c >= '0' && c <= '9')
                {
                    val *= 10;
                    val += c - '0';
                }else if(val)
                {
                    break;
                }
            }
            break;

        default:
            break;
    }

    return val;
}

int atoi(const char *nptr)
{
    int sign = 1;
    int val = 0;
    const char *pos = nptr;

    while(*pos == ' ')
    {
        pos++;
    }

    if(*pos == '-')
    {
        sign = -1;
        pos++;
    }else if(*pos == '+')
    {
        pos++;
    }

    while(*pos >= '0' && *pos <= '9')
    {
        val *= 10;
        val += *pos - '0';
        pos++;
    }

    return sign * val;
}

long atol(const char *nptr)
{
    long sign = 1;
    long val = 0;
    const char *pos = nptr;

    while(*pos == ' ')
    {
        pos++;
    }

    if(*pos == '-')
    {
        sign = -1;
        pos++;
    }else if(*pos == '+')
    {
        pos++;
    }

    while(*pos >= '0' && *pos <= '9')
    {
        val *= 10;
        val += *pos - '0';
        pos++;
    }

    return sign * val;
}

static void putstring(char *str)
{
    size_t length = strlen(str);
    ssize_t ret = 0;

    ret = write(1, str, length);
}

static int putchar(char *str, char c)
{
    *str = c;

    return 1;
}

static int putint(char *str, char fill, int width, int value)
{
    int num = 0;
    unsigned int absolute;

    if(value < 0)
    {
        absolute = -value;
    }else
    {
        absolute = value;
    }

    width--;

    if((absolute / 10) > 0)
    {
        if(value < 0)
        {
            num = putint(str, fill, width, -(absolute / 10));
        }else
        {
            num = putint(str, fill, width, (absolute / 10));
        }
        str += num;
    }else
    {
        if(value < 0)
        {
            width--;
        }

        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }

        if(value < 0)
        {
            num += putchar(str, '-');
            str++;
        }
    }

    num += putchar(str, (absolute % 10) + '0');

    return num;
}

static int putdouble(char *str, int width, double value)
{
    int num = 0;
    int i = 0;
    int e = 0;

    if(width < 1)
    {
        width = 11;
    }

    if(value < 0.0)
    {
        value = -value;
        num += putchar(str, '-');
        str++;
    }

    while(value < 1.0 && e > -310)
    {
        value *= 10;
        e--;
    }

    while(value > 10.0 && e < 310)
    {
        value /= 10;
        e++;
    }

    if(e >= 310 || e <= -310)
    {
        num += putchar(str, 'i');
        str++;
        num += putchar(str, 'n');
        str++;
        num += putchar(str, 'f');
        str++;

        return num;
    }

    if((int)value > 9)
    {
        num += putchar(str, 'n');
        str++;
        num += putchar(str, 'a');
        str++;
        num += putchar(str, 'n');
        str++;

        return num;
    }

    num += putchar(str, (int)value + '0');
    str++;
    num += putchar(str, '.');
    str++;

    for(i = 0; i < width; i++)
    {
        value -= (int)value;
        value *= 10;
        num += putchar(str, (int)value + '0');
        str++;
    }

    num += putchar(str, 'e');
    str++;
    num += putint(str, ' ', 0, e);

    return num;
}

static int putunsignedint(char *str, char fill, int width, unsigned int value)
{
    int num = 0;

    width--;

    if((value / 10) > 0)
    {
        num = putunsignedint(str, fill, width, (value / 10));
        str += num;
    }else
    {
        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }
    }

    num += putchar(str, (value % 10) + '0');

    return num;
}

static int putunsignedlong(char *str, char fill, int width, unsigned long value)
{
    int num = 0;

    width--;

    if((value / 10) > 0)
    {
        num = putunsignedlong(str, fill, width, (value / 10));
        str += num;
    }else
    {
        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }
    }

    num += putchar(str, (value % 10) + '0');

    return num;
}

static int puthex(char *str, char fill, int width, unsigned char cap, unsigned long value)
{
    int num = 0;

    width--;

    if((value >> 4) > 0)
    {
        num += puthex(str, fill, width, cap, (value >> 4));
        str += num;
    }else
    {
        while(width > 0)
        {
            putchar(str, fill);
            str++;
            num++;
            width--;
        }
    }

    if((value & 0xf) < 10)
    {
        putchar(str, (value & 0xf) + '0');
    }else if(cap)
    {
        putchar(str, (value & 0xf) - 10 + 'A');
    }else
    {
        putchar(str, (value & 0xf) - 10 + 'a');
    }

    num++;

    return num;
}

static int putstr(char *str, char fill, int width, const char *src)
{
    int num = 0;

    while(*src != 0)
    {
        *str++ = *src++;
        num++;
    }

    width -= num;

    while(width > 0)
    {
        *str++ = fill;
        num++;
        width--;
    }

    return num;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    char fill = 0;
    size_t width = 0;
    size_t num = 0;
    size_t length = 0;

    if(str)
    {
        *str = '\0';
    }

    while(*format != 0 && length < size)
    {
        if(*format != '%')
        {
            *str++ = *format++;
            length++;
        }else if(*(format + 1) == '%')
        {
            *str++ = '%';
            format += 2;
            length++;
        }else{
            fill = ' ';
            width = 0;
            format++;

            if(*format == '0')
            {
                fill = '0';
                format++;
            }

            if(*format == '-')
            {
                format++;
            }

            while(*format >= '0' && *format <= '9')
            {
                width = width * 10 + *format - '0';
                format++;
            }

            if(length + width > size)
            {
                width = size - length;
            }

            switch(*format)
            {
                case 'd':
                case 'i':
                    num = putint(str, fill, width, va_arg(ap, int));
                    break;

                case 'f':
                    num = putdouble(str, width, va_arg(ap, double));
                    break;

                case 'p':
                    num = puthex(str, '0', 2 * sizeof(unsigned long), 0, va_arg(ap, unsigned long));
                    break;

                case 'u':
                    num = putunsignedint(str, fill, width, va_arg(ap, unsigned int));
                    break;

                case 'l':
                    num = putunsignedlong(str, fill, width, va_arg(ap, unsigned long));
                    break;

                case 'x':
                    num = puthex(str, fill, width, 0, va_arg(ap, unsigned long));
                    break;

                case 'X':
                    num = puthex(str, fill, width, 1, va_arg(ap, unsigned long));
                    break;

                case 's':
                    num = putstr(str, fill, width, va_arg(ap, char *));
                    break;

                case 'c':
                    num = putchar(str, va_arg(ap, int));
                    break;

                default:
                    return -1;
            }

            format++;
            str += num;
            length += num;
        }
    }

    if(length < size)
    {
        *str = '\0';
    }else
    {
        *(--str) = '\0';
        length--;
    }

    return length;
}

int sprintf(char *str, const char *format, ...)
{
    va_list ap;
    size_t result = 0;

    va_start(ap, format);
    result = vsnprintf(str, MAX_PRINT_STR_LEN, format, ap);
    va_end(ap);

    return result;
}

void printf(const char *format, ...)
{
    char buffer[MAX_PRINT_STR_LEN] = {0};
    va_list ap;
    size_t result = 0;

    va_start(ap, format);
    result = vsnprintf(buffer, MAX_PRINT_STR_LEN, format, ap);
    va_end(ap);

    putstring(buffer);
}

char *fgets(char *s, int size, int fd)
{
    int count = 0;
    char ch;

    while(count < size -1)
    {
        ssize_t bytes_read = read(fd, &ch, 1);

        if(bytes_read < 0)
        {
            return NULL;
        }

        if(bytes_read == 0 || ch == '\n')
        {
            break;
        }

        s[count++] = ch;
    }

    s[count] = '\0';

    return (count > 0) ? s : NULL;
}


uint16_t htons(uint16_t hostshort)
{
    return (hostshort << 8) | (hostshort >> 8);
}

uint32_t htonl(uint32_t hostlong)
{
    return (hostlong << 24) | ((hostlong & 0x00FF0000) >> 8) | ((hostlong & 0x0000FF00) << 8) | (hostlong >> 24);
}

uint64_t htonll(uint64_t hostlonglong)
{
    return ((1 == htonl(1)) ? (hostlonglong) : (((uint64_t)htonl((hostlonglong) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((hostlonglong) >> 32)));
}

uint16_t ntohs(uint16_t netshort)
{
    return htons(netshort);
}

uint32_t ntohl(uint32_t netlong)
{
    return htonl(netlong);
}

uint64_t ntohll(uint64_t netlonglong)
{
    return ((1 == ntohl(1)) ? (netlonglong) : (((uint64_t)ntohl((netlonglong) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((netlonglong) >> 32)));
}

in_addr_t inet_addr(const char *cp)
{
    in_addr addr;
    unsigned int bytes[4];
    int byte_count = 0;

    while(*cp)
    {
        if(*cp >= '0' && *cp <= '9')
        {
            int value = 0;

            while(*cp >= '0' && *cp <= '9')
            {
                value = value * 10 + (*cp - '0');
                cp++;
            }

            if(value > 255)
            {
                goto error;
            }

            bytes[byte_count++] = value;

            if(*cp == '.')
            {
                cp++;
            }
        }else
        {
            goto error;
        }

        if(byte_count > 4)
        {
            goto error;
        }
    }

    addr.s_addr = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];

    return addr.s_addr;

error:
    addr.s_addr = 0;

    return addr.s_addr;
}

char *inet_ntoa(in_addr in)
{
    char *buffer = (char *)calloc(16, sizeof(char));

    sprintf(buffer, "%u.%u.%u.%u", (in.s_addr & 0x000000FF), (in.s_addr & 0x0000FF00) >> 8, (in.s_addr & 0x00FF0000) >> 16, (in.s_addr & 0xFF000000) >> 24);

    return buffer;
}

int inet_pton(int af, const char *src, void *dst)
{
    unsigned int bytes[4];
    int byte_count = 0;
    unsigned int segments[8];
    int segment_count = 0;
    const char *pos = NULL;
    int double_colon_start_segment_index = -1;
    int double_colon_end_segment_index = -1;
    int value = 0;
    char ch;
    int i = 0;

    if(af == AF_INET)
    {
        while(*src != '\0')
        {
            ch = *src;

            if(ch >= '0' && ch <= '9')
            {
                value = value * 10 + ch - '0';
            }else if(ch == '.')
            {
                if(byte_count >= 3 || value > 255)
                {
                    return 0;
                }

                bytes[byte_count++] = value;
                value = 0;
            }else
            {
                return 0;
            }

            src++;
        }

        if(byte_count == 3 && value <= 255)
        {
            bytes[byte_count++] = value;
        }

        if(byte_count != 4)
        {
            return 0;
        }

        ((in_addr *)dst)->s_addr = (bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0];
    }else if(af == AF_INET6)
    {
        pos = src;

        if(*pos == ':') // ::1
        {
            double_colon_start_segment_index = 0;
        }

        while(*pos != '\0')
        {
            ch = *pos;

            if((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
            {
                pos++;
            }else if(ch == ':')
            {
                if(segment_count >= 8)
                {
                    return 0;
                }

                segment_count++;
                pos++;

                if(*pos == ':')  // ::
                {
                    if(double_colon_start_segment_index > 0)
                    {
                        return 0;
                    }else if(double_colon_start_segment_index == -1)
                    {
                        double_colon_start_segment_index = segment_count;
                        segment_count = 0;
                    }

                    pos++;
                }
            }else
            {
                return 0;
            }
        }

        if(double_colon_start_segment_index == 0)   // ::1
        {
            double_colon_end_segment_index = 7 - segment_count;
        }else if(double_colon_start_segment_index != -1)
        {
            double_colon_end_segment_index = 7 - segment_count - 1;
        }

        pos = src;
        segment_count = 0;

        if(double_colon_start_segment_index == 0)   // ::1
        {
            while(segment_count <= double_colon_end_segment_index)
            {
                segments[segment_count++] = 0;
            }

            pos++;  // :
            pos++;  // :

            while(*pos != '\0')
            {
                ch = *pos;

                if((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
                {
                    if(value > 0xFFFF)
                    {
                        return 0;
                    }

                    value = value * 16 + ((ch >= '0' && ch <= '9') ? (ch - '0') : (ch >= 'a' ? (ch - 'a' + 10) : (ch - 'A' + 10)));
                }else if(ch == ':')
                {
                    if(segment_count >= 8)
                    {
                        return 0;
                    }

                    segments[segment_count++] = value;
                    value = 0;
                }else
                {
                    return 0;
                }

                pos++;
            }

            if(segment_count < 8)
            {
                segments[segment_count] = value;
            }
        }else
        {
            while(*pos != '\0')
            {
                ch = *pos;

                if((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
                {
                    if(value > 0xFFFF)
                    {
                        return 0;
                    }

                    value = value * 16 + ((ch >= '0' && ch <= '9') ? (ch - '0') : (ch >= 'a' ? (ch - 'a' + 10) : (ch - 'A' + 10)));
                }else if(ch == ':')
                {
                    if(segment_count >= 8)
                    {
                        return 0;
                    }

                    segments[segment_count++] = value;
                    value = 0;

                    if(*(pos + 1) == ':')
                    {
                        if(segment_count == double_colon_start_segment_index)
                        {
                            while(segment_count <= double_colon_end_segment_index)
                            {
                                segments[segment_count++] = 0;
                            }
                        }

                        pos++;
                    }
                }else
                {
                    return 0;
                }

                pos++;
            }
        }

        if(segment_count < 8)
        {
            segments[segment_count] = value;
        }

        for(i = 0; i < 8; i++)
        {
            ((in6_addr *)dst)->s6_addr[i * 2] = (segments[i] >> 8) & 0xFF;
            ((in6_addr *)dst)->s6_addr[i * 2 + 1] = segments[i] & 0xFF;
        }
    }else
    {
        return 0;
    }

    return 1;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    in_addr_t s_addr = *(long *)src;
    const uint16_t *addr = (const uint16_t *)src;
    int longest_zero_idx = -1;
    int longest_zero_len = 0;
    int current_zero_len = 0;
    int i = 0;
    int seq_length = 0;
    char *ptr = dst;
    int skip = 0;

    if(af == AF_INET && size >= 16)
    {
        sprintf(dst, "%u.%u.%u.%u", (s_addr & 0x000000FF), (s_addr & 0x0000FF00) >> 8, (s_addr & 0x00FF0000) >> 16, (s_addr & 0xFF000000) >> 24);
    }else if(af == AF_INET6 && size >= INET6_ADDR_STRING_LENGTH)
    {
        if(addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0)
        {
            return 0;
        }

        for(i = 0; i < 8; i++)
        {
            if(addr[i] == 0)
            {
                if(current_zero_len == 0)
                {
                    current_zero_len = 1;
                    longest_zero_idx = i;
                }else
                {
                    current_zero_len++;
                }
            }else
            {
                if(current_zero_len > longest_zero_len)
                {
                    longest_zero_len = current_zero_len;
                }

                current_zero_len = 0;
            }
        }

        if(current_zero_len > longest_zero_len)
        {
            longest_zero_len = current_zero_len;
            longest_zero_idx = 8 - current_zero_len;
        }

        for(i = 0; i < 8; i++)
        {
            if(i == longest_zero_idx)
            {
                *ptr++ = ':';

                if(longest_zero_len > 1)
                {
                    i += longest_zero_len -1;

                    continue;
                }else
                {
                    skip = 1;
                }
            }

            ptr += sprintf(ptr, "%x", ntohs(addr[i]));

            if(i < 7)
            {
                *ptr++ = ':';
            }
        }

        *ptr = '\0';
    }else
    {
        return NULL;
    }

    return dst;
}

static int is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static int days_in_month(int month, int year)
{
    const int days_in_months[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    if(month == 1 && is_leap_year(year))
    {
        return 29;
    }

    return days_in_months[month];
}

char *ctime(const time_t *timep)
{
    static char buffer[MAX_PRINT_STR_LEN] = {0};
    struct tm time_info;
    const char* week_days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const char* month_names[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    time_info.tm_sec = *timep % 60;
    int total_minutes = *timep / 60;
    time_info.tm_min = total_minutes % 60;
    int total_hours = total_minutes / 60;
    time_info.tm_hour = total_hours % 24;

    long total_days = total_hours / 24;
    time_info.tm_year = 1970;

    while(total_days >= 365)
    {
        total_days -= (is_leap_year(time_info.tm_year) ? 366 : 365);
        time_info.tm_year++;
    }

    time_info.tm_yday = total_days;

    int month = 0;
    while(total_days >= days_in_month(month, time_info.tm_year))
    {
        total_days -= days_in_month(month, time_info.tm_year);
        month++;
    }

    time_info.tm_mon = month;
    time_info.tm_mday = total_days + 1;
    time_info.tm_wday = (total_days + 4) % 7;

    sprintf(buffer, "%s %s %d %02d:%02d:%02d %d", week_days[time_info.tm_wday], month_names[time_info.tm_mon], time_info.tm_mday, time_info.tm_hour, time_info.tm_min, time_info.tm_sec, time_info.tm_year);

    return buffer;
}


// spider function
char hex_char_to_int(char c)
{
    if((c >= '0') && (c <= '9'))
    {
        c = c - '0';
    }else if((c >= 'a') && (c <= 'f'))
    {
        c = c + 10 - 'a';
    }else if((c >= 'A') && (c <= 'F'))
    {
        c = c + 10 - 'A';
    }else
    {
        c = 0;
    }
    return c;
}

void hex_string_to_array(const char *hex_string, int32_t hex_string_length, unsigned char *buffer, int32_t buffer_size)
{
    char tmp1 = 0;
    char tmp2 = 0;
    int32_t length = 0;
    int32_t i = 0;

    for(i = 0; i < hex_string_length && length < buffer_size; i += 2)
    {
        tmp1 = hex_char_to_int(hex_string[i]);
        tmp2 = hex_char_to_int(hex_string[i + 1]);

        tmp1 = tmp1 << 4;
        buffer[length] = (unsigned char)(tmp1 + tmp2);
        length++;
    }
}

void print_bytes(char *buffer, int buffer_length)
{
    for(int i = 0; i < buffer_length; i++){
        if(i != 0 && i % 16 == 0){
            printf("\n");
        }else if(i % 16 == 8){
            printf(" ");
        }
        printf("%02x ", buffer[i] & 0xff);
    }
    printf("\n");

    return;
}

uint32_t generate_random_id()
{
    uint32_t id = 0;
    ssize_t ret = 0;

    do{
        ret = getrandom(&id, sizeof(uint32_t), 0);
    }while(id == 0);

    return id;
}

int32_t recv_data(int32_t sock, char *buffer, int32_t buffer_size, long tv_sec, long tv_usec)
{
    int ret = 0;
    int32_t rec = 0;
    struct fd_set readfds;
    int nfds = -1;
    struct timeval tv;

    memset((char *)buffer, 0, buffer_size);

    while(1)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        nfds = sock + 1;
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(nfds, &readfds, NULL, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[-] recv_data select timeout\n");
#endif

            return -1;
        }

        ret = FD_ISSET(sock, &readfds);
        if(ret > 0)
        {
            rec = read(sock, buffer, buffer_size);
            if(rec <= 0)
            {
                if(rec == EINTR)
                {
                    continue;
                }else if(rec == EAGAIN)
                {
                    millisleep(5);

                    continue;
                }else
                {
#ifdef _DEBUG
                    printf("[-] recv_data read error: %d\n", rec);
#endif

                    return -1;
                }
            }else
            {
                break;
            }
        }
    }

    return rec;
}

int32_t send_data(int32_t sock, char *buffer, int32_t buffer_length, long tv_sec, long tv_usec)
{
    int ret = 0;
    int32_t sen = 0;
    int32_t send_length = 0;
    int32_t len = 0;
    struct fd_set writefds;
    int nfds = -1;
    struct timeval tv;

    len = buffer_length;

    while(len > 0)
    {
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        nfds = sock + 1;
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;

        ret = select(nfds, NULL, &writefds, NULL, &tv);
        if(ret == 0)
        {
#ifdef _DEBUG
            printf("[-] send_data select timeout\n");
#endif

            return -1;
        }

        ret = FD_ISSET(sock, &writefds);
        if(ret > 0)
        {
            sen = write(sock, buffer + send_length, len);
            if(sen <= 0)
            {
                if(sen == EINTR)
                {
                    continue;
                }else if(sen == EAGAIN)
                {
                    millisleep(5);

                    continue;
                }else
                {
#ifdef _DEBUG
                    printf("[-] send_data write error: %d\n", sen);
#endif

                    return -1;
                }
            }

            send_length += sen;
            len -= sen;
        }
    }

    return buffer_length;
}

