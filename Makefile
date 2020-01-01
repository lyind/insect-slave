
ifeq ($(OS),Windows_NT)
CFLAGS+=-mno-ms-bitfields -Wall
LIBS=-lws2_32
all: insect-slave
else
CFLAGS+=-Wall
all: insect-slave allocate-port
endif

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
