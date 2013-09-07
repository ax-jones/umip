
#CC=arm-none-eabi-gcc
#AR=arm-none-eabi-ar

INCLUDES := utap.h mac.h common.h arp.h ip.h tcp.h icmp.h
LIBOBJS := common.o mac.o arp.o ip.o tcp.o icmp.o
TAPOBJS := utap.o main.o
LIBTARGET := umac.a

TARGET := umip.elf

all: $(TARGET)

CFLAGS += -fms-extensions -O0 -ggdb

$(TARGET): $(LIBTARGET) $(TAPOBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(TAPOBJS) $(LIBTARGET)
	cp $(TARGET) ..
	strip -o ../$(TARGET).stripped $(TARGET)

$(LIBTARGET): $(LIBOBJS)
	$(AR) cru $(LIBTARGET) $(LIBOBJS)

%.o: %.c Makefile $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(LIBOBJS) $(TARGET) $(LIBTARGET) $(TAPOBJS)

