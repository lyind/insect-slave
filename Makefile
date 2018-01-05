all: insect-slave

ifeq ($(OS),Windows_NT)
CFLAGS=-mno-ms-bitfields
LIBS=-lws2_32
endif

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
