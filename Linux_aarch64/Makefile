CC       = gcc
CFLAGS   = -std=c99 -fno-stack-protector -fno-builtin -Os -static -nostdlib -nostartfiles -Wl,--entry="_start"
LDFLAGS  =
OPTS     =

SRCS1    += syscall.s
SRCS1    += signal_trampoline.s
SRCS1    += new_thread.s
SRCS1    += start.s
SRCS2    += stdfunc.c
SRCS2    += spiderip.c
SRCS2    += semaphore.c
SRCS2    += queue.c
SRCS2    += rbtree.c
SRCS2    += thread.c
SRCS2    += dns.c
SRCS2    += xor.c
SRCS2    += aes.c
SRCS2    += route.c
SRCS2    += message.c
SRCS2    += pipe.c
SRCS2    += client.c
SRCS2    += server.c
SRCS2    += spidercommand.c
SRCS2    += tinyspider.c

OBJS1    = $(SRCS1:.s=.o)
OBJS2    = $(SRCS2:.c=.o)
TARGET   = tinyspider

INCDIR   =
LIBDIR   =
LIBS     =



all:       clean $(OBJS1) $(OBJS2) $(TARGET)

debug:     CFLAGS += -D_DEBUG
debug:     all

$(TARGET): $(OBJS1) $(OBJS2)
	$(CC) $(CFLAGS) $(OPTS) -o $@ $^ $(LIBDIR) $(LIBS) $(LDFLAGS)

$(OBJS1):  $(SRCS1)
	$(CC) $(CFLAGS) $(INCDIR) -c $(SRCS1)

$(OBJS2):  $(SRCS2)
	$(CC) $(CFLAGS) $(INCDIR) -c $(SRCS2)

clean:
	rm -f $(OBJS1) $(OBJS2) $(TARGET)

