CC       = x86_64-w64-mingw32-gcc
CFLAGS   = -std=c99 -fno-stack-protector -fno-builtin -Os -static -nostdlib -nostartfiles -ffreestanding -mconsole --entry="_start"
LDFLAGS  =
OPTS     =

SRCS    += stdfunc.c
SRCS    += spiderip.c
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
TARGET   = tinyspider.exe

INCDIR   =
LIBDIR   =
LIBS     =



all:       clean $(OBJS) $(TARGET)

debug:     CFLAGS += -D_DEBUG
debug:     all

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OPTS) -o $@ $^ $(LIBDIR) $(LIBS) $(LDFLAGS)

$(OBJS):   $(SRCS)
	$(CC) $(CFLAGS) $(INCDIR) -c $(SRCS)
clean:
	rm -f $(OBJS) $(TARGET)

