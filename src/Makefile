
all: umip.elf

TARGET := umip.elf

INCLUDES := utap.h mac.h common.h arp.h ip.h tcp.h icmp.h
LIBOBJS := main.o common.o utap.o mac.o arp.o ip.o tcp.o icmp.o
LIBTARGET := umac.a

CFLAGS += -fms-extensions -O0

$(TARGET): $(LIBTARGET)
	$(CC) $(LDFLAGS) -ggdb -o $(TARGET) $(LIBTARGET)
	cp $(TARGET) ..

$(LIBTARGET): $(LIBOBJS)
	ar cru $(LIBTARGET) $(LIBOBJS)

%.o: %.c Makefile $(INCLUDES)
	$(CC) $(CFLAGS) -c -ggdb $<

clean:
	rm -f $(LIBOBJS) $(TARGET) $(LIBTARGET)

