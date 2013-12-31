
#CC=arm-none-eabi-gcc
#AR=arm-none-eabi-ar
CC=mipsisa64-octeon-elf-gcc
AR=mipsisa64-octeon-elf-ar

CDEFINES += -I. -march=octeon
#CFLAGS += -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
#CDEFINES += -DLINUX -DLITTLE_ENDIAN

INCLUDES := ../include/utap.h ../include/mac.h ../include/common.h ../include/arp.h ../include/ip.h ../include/tcp.h ../include/icmp.h
LIBOBJS := common.o mac.o arp.o ip.o tcp.o icmp.o
TAPOBJS := utap.o main.o
LIBTARGET := umac.a

TARGET := umip.elf

all: $(LIBTARGET)

CFLAGS += -fms-extensions -O0 -ggdb -I../include -msoft-float $(CDEFINES)

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

