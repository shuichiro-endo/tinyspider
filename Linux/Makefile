CC       = gcc
CFLAGS   = -std=c99 -fno-stack-protector -fno-builtin
LDFLAGS  =

SRCS    += stdfunc.c
SRCS    += spiderip.c
SRCS    += semaphore.c
SRCS    += queue.c
SRCS    += rbtree.c
SRCS    += thread.c
SRCS    += dns.c
SRCS    += xor.c
SRCS    += aes.c
SRCS    += route.c
SRCS	+= message.c
SRCS	+= pipe.c
SRCS    += client.c
SRCS    += server.c
SRCS    += spidercommand.c
SRCS    += tinyspider.c

OBJS     = $(SRCS:.c=.o)
TARGET   = tinyspider

INCDIR   =
LIBDIR   =
LIBS     =
OPTS     = -static -nostdlib -nostartfiles


all:       clean $(OBJS) $(TARGET)

debug:     CFLAGS += -D_DEBUG
debug:     all

$(TARGET): $(OBJS)
	$(CC) $(OPTS) -o $@ $^ $(LIBDIR) $(LIBS) $(LDFLAGS)

$(OBJS):   $(SRCS)
	$(CC) $(OPTS) $(CFLAGS) $(INCDIR) -c $(SRCS)
clean:
	rm -f $(OBJS) $(TARGET)

