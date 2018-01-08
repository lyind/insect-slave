
ifeq ($(OS),Windows_NT)
CFLAGS=-mno-ms-bitfields
LIBS=-lws2_32
all: insect-slave
else
all: insect-slave allocate-port
endif

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
