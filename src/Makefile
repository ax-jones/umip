
all: umip.elf

TARGET := umip.elf

LIBOBJS := main.o utap.o

$(TARGET): $(LIBOBJS)
	$(CC) $(LDFLAGS) -ggdb -o $(TARGET) $(LIBOBJS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c -ggdb $<

clean:
	rm -f $(LIBOBJS) $(TARGET)

