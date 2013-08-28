
all: umip.elf

TARGET := umip.elf

INCLUDES := utap.h mac.h common.h arp.h ip.h
LIBOBJS := main.o common.o utap.o mac.o arp.o ip.o

CFLAGS += -fms-extensions

$(TARGET): $(LIBOBJS)
	$(CC) $(LDFLAGS) -ggdb -o $(TARGET) $(LIBOBJS)
	cp $(TARGET) ..

%.o: %.c Makefile $(INCLUDES)
	$(CC) $(CFLAGS) -c -ggdb $<

clean:
	rm -f $(LIBOBJS) $(TARGET)

