/*
 * Copyright (C) 2018  Jonas Zeiger <jonas.zeiger@talpidae.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * insect-slave.c - Simple insect slave implementation
 * 
 * USAGE:
 * 
 *   insect-slave [OPTIONS] COMMAND
 * 
 * COMMANDS:
 * 
 *   keep-alive        Send periodic mapping messages, shutdown on demand
 *   lookup            Lookup dependency
 * 
 * OPTIONS:
 * 
 *   -h                  Show this help
 * 
 *   -d DEPENDENCY_ROUTE Slave dependency route (up to 16 allowed)
 *   -p SLAVE_PORT       Slave port
 *   -P QUEEN_PORT       Remote queen port
 *   -q QUEEN_HOST       Remote queen hostname or address
 *   -r ROUTE            Slave route
 *   -s SLAVE_HOST       Slave host address or name
 *
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

// platform specific
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>


#define BUFFER_SIZE 4096

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))


// TODO Make this configurable.
#define KEEP_ALIVE_INTERVAL_MICROS  1000000    // 1s


/** Mapping message */
typedef struct insect_mapping_s
{
    // all numeric fields are big-endian
    uint8_t type;             // message type (1: mapping)
    uint8_t flags;            // 0x0
    uint8_t hostLength;       // length of bindAddress
    uint8_t routeLength;      // length of route
    int64_t ts;               // client System.nanoTime()
    uint16_t port;            // client port
    uint8_t nameLength;       // length of unique service name
    uint8_t dependencyLength; // length of dependency
    char[] data;              // UTF-8 encoded data fields:
    // 1. client IPv4 address/hostname as non-terminated UTF-8 string
    // 2. route (exported path, non-terminated UTF-8 string)
    // 3. unique service name (non-terminated UTF-8 string)
    // 4. as single dependency to be subscribed (non-terminated UTF-8 string)
}
insect_mapping_t;


/** Shutdown command message */
typedef struct insect_shutdown_s
{
    uint8_t type;             // message type (2: shutdown)
    uint8_t magic;            // 0x86
}
insect_shutdown_t;


typedef union message_buffer_u
{
    char buffer[BUFFER_SIZE];
    insect_mapping_t mapping;
    insect_mapping_t shutdown;
}
message_buffer_t;


static message_buffer_t out = { 0 };
static message_buffer_t in = { 0 };


typedef enum insect_command_e
{
	COMMAND_NONE,
    COMMAND_HELP,
    COMMAND_KEEP_ALIVE,
    COMMAND_LOOKUP
}
insect_command_t;


static insect_command_t command = COMMAND_NONE;

static const char slave_host[256] = { '\0' };
static const char slave_route[256] = { '\0' };
static const char dependency_route[16][256] = { 0 };
static const char queen_host[256] = { '\0' };

static uint16_t slave_port = 0;  // big-endian
static uint16_t queen_port = 0;  // big-endian


/**
 * Print help and exit.
 */
static void commandHelp()
{
    (void) fputs("\n\
 insect-slave.c - Simple insect slave implementation\n\
\n\
USAGE:\n\
\n\
   insect-slave [OPTIONS] COMMAND\n\
\n\
COMMANDS:\n\
\n\
   keep-alive        Send periodic mapping messages\n\
   lookup            Lookup dependency\n\
\n\
OPTIONS:\n\
\n\
   -h                  Show this help\n\
\n\
   -d DEPENDENCY_ROUTE Slave dependency route (up to 16 allowed)\n\
   -p SLAVE_PORT       Slave port\n\
   -P QUEEN_PORT       Remote queen port\n\
   -q QUEEN_HOST       Remote queen hostname or address\n\
   -r ROUTE            Slave route\n\
   -s SLAVE_HOST       Slave host address or name\n", stderr);
}


/** Parse command line arguments. */
static void parse_args(int argc, char *argv[])
{
	errno = 0;
    opterr = 0;
    
    int c;
    while ((c = getopt(argc, argv, "hd:p:P:q:r:s:")) != -1)
    {
        switch (c)
        {
            case 'h':
                command = COMMAND_HELP;
				return 0;
            
            case 'd':
            {
                const unsigned max_length = sizeof(dependency_route[0]) - 1;
                int i = 0;
                for (; i < COUNT_OF(dependency_route); ++i)
                {
                    if (dependency_route[i][0] == '\0')
                    {
                        (void) strncpy(dependency_route[i], argv[optarg], max_length);
                        break;
                    }
                }
                
                if (i >= COUNT_OF(dependency_route))
                {
                    (void) fputs("error: Too many dependencies specified (maximum: 16)\n", stderr);
                    return -1;
                }

                break;
            }

            case 'p':
            {
                int port;
                if (sscanf(argv[optarg], "%" SCNo16, &port) != 1)
                {
                    (void) fputs("error: invalid slave port specified (outside 0-65535)\n", stderr);
                    return -1;
                }
                
                slave_port = htons(port);
                
                break;
            }
            
            case 'P':
            {
				int port;
                if (sscanf(argv[optarg], "%" SCNo16, &port) != 1)
                {
                    (void) fputs("error: invalid queen port specified (outside 0-65535)\n", stderr);
                    return -1;
                }
                
                queen_port = htons(port);
                
                break;
            }
            
            case 'q':
            {
                const unsigned max_length = sizeof(queen_host) - 1;
                (void) strncpy(queen_host, argv[optarg], max_length);
                break;
            }
            
            case 'r':
            {
                const unsigned max_length = sizeof(slave_route) - 1;
                (void) strncpy(slave_route, argv[optarg], max_length);
                break;
            }
            
            case 's':
            {
                const unsigned max_length = sizeof(slave_host) - 1;
                (void) strncpy(slave_host, argv[optarg], max_length);
                break;
            }
            
            case '?':
            {
                if (optopt == 'd' || optopt == 'd' || optopt == 'p' || optopt == 'P' || optopt == 'q' || optopt == 'r' || optopt == 's')
                {
                    (void) fprintf(stderr, "error: option '-%c' requires an argument\n", optopt);
                }
                else if (isprint(optopt))
                {
                    (void) fprintf(stderr, "error: unknown option `-%c'\n", optopt);
                }
                else
                {
                    (void) fprintf(stderr, "error: unknown option character `\\x%x'\n", optopt);
                }
                    
                return -1;
            }
            
            default:
            {
                (void) fputs("error: failed to parse arguments\n", stderr);
                return -1;
            }
        }
    }

	if (command == COMMAND_NONE)
	{
		if (optind >= argc)
		{
			(void) fputs("error: no command specified\n", stderr);
			
			command = COMMAND_HELP;
			
			return -1;
		}
		
		if (strncmp(argv[optind], "keep-alive", strlen("keep-alive")) == 0)
		{
			command = COMMAND_KEEP_ALIVE;
		}
		else if (strncmp(argv[optind], "lookup", strlen("lookup")) == 0)
		{
			command = COMMAND_LOOKUP;
		}
		else
		{
			(void) fprintf(stderr, "error: unknown command specified: %s\n", argv[optind]);
			
			command = COMMAND_HELP;
			
			return -1;
		}
	}
	
	return 0;
}


static int resolve_host_port(struct sockaddr_in *address, const char *host, uint_fast16_t port)
{
	errno = 0;
    struct hostent *host_entity = gethostbyname(host);
    if (host_entity == NULL)
    {
        perror(host);
		return -1;
    }

	memset(address, 0, sizeof(struct sockaddr_in));
	
    address->sin_family = AF_INET;
    memcpy((char *)&address.sin_addr.s_addr, (char *)host_entity->h_addr, host_entity->h_length);
    address->sin_port = htons(port);
	
	return 0;
}


//#ifndef _WIN32

/** Get microseconds since EPOCH on any POXIX compliant system. */
static int64_t timeMicros()
{
       struct timeval tp;
       struct timezone tz;

       tz.tz_minuteswest = 0;

       (void) gettimeofday(&tp, &tz);

       return (1000000 * (int64_t)tp.tv_sec) + (int64_t)tp.tv_usec;
}


static int socketNonBlockUdp4()
{
	errno = 0;
    const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) 
    {
		perror("failed to open socket");
        return sock;
    }
	
	if (fcntl(sock, F_SETFL, O_NONBLOCK))
	{
		perror("enabling non-blocking operation");
		return -1;
	}
	
	return sock;
}

#if 0
	
// must be some ghastly Windoze, maybe even NT4!
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define poll(fdarray, nfds, timeout) WSAPoll(fdarray, nfds, timeout)

/** Hopefully get microseconds since EPOCH on Win32. */
static int64_t timeMicros()
{
	static LARGE_INTEGER frequency = { 0 };
    if(frequency.QuadPart == 0)
    {
        QueryPerformanceFrequency(&frequency);
        frequency.QuadPart /= 1000000;
    }
	
    LARGE_INTEGER timestamp = { 0 };
    QueryPerformanceCounter(&timestamp);

    return timestamp.QuadPart / frequency.QuadPart;
}

#endif


static int tryRecv()
{
	struct sockaddr_in remote_address;
	size_t remote_address_length = sizeof(remote_address);
	memcpy(&remote_address, &queen_address, remote_address_length);
	
	errno = 0;
    const int n = recvfrom(sock, in.buffer, sizeof(in.buffer), MSG_DONTWAIT, &remote_address, &remote_address_length);
    if (n < 0)
	{
		if (errno != EGAIN && errno != EWOULDBLOCK)
		{
			perror("recvfrom()");
			return n;
		}
		
		return 0;
	}
	
	return n;
}


static int trySendKeepAlive()
{
    static const size_t queen_address_length = sizeof(queen_address);
	
	// TODO Assemble keep-alive message in out.mapping
	int out_size = 42;
	
	errno = 0;
    const int n = sendto(sock, out.buffer, out_size, MSG_DONTWAIT, &queen_address, queen_address_length);
    if (n != out_size)
	{
		if (errno != EGAIN && errno != EWOULDBLOCK)
		{
			perror("sendto()");
			return -1;			
		}

		return 0;
	}
	
	return n;
}


static int commandKeepAlive(struct sockaddr_in queen_address, int sock)
{
	int64_t nextKeepalive = timeMicros();
	do
	{
		const int64_t now = timeMicros();
		const int64_t timeout = nextKeepalive - now;
		const int timeout_ms = timeout / 1000;
		
		struct pollfd pfd;		
		pfd.fd = sock;
		pfd.events = POLLERR | POLLIN | ((timeout_ms <= 0) ? POLLOUT : 0);
		pfd.revents = 0;
		
		errno = 0;
		int status = poll(&pfd, 1, timeout_ms);
		if (status < 0 || (pfd.revents & (POLLERR | POLLHUP)))
		{
			perror("poll()");
			return -1;
		}
		
		if (status == 0 || (pfd.revents & POLLOUT))
		{
			// timeout, try to send keep-alive immediately
			int n = trySendKeepAlive();
			if (n > 0)
			{
				nextKeepalive = now + KEEP_ALIVE_INTERVAL_MICROS;
			}
			else if (n < 0)
			{
				return -1;
			}
		}
		
		if (status > 0 && (pfd.revents & POLLIN))
		{
			int size = tryRecv();
			if (size > 0)
			{
				// TODO Handle incoming message
			}
			else if (size < 0)
			{
				return -1;
			}
		}
	}
	while(true);  // TODO handle Ctrl-C / SIGTERM
	
	return 0;
}


int main(int argc, char **argv)
{
	int code = parse_args(argc, argv);
	if (command == COMMAND_HELP)
	{
		commandHelp();
	}
	else if (!code)
	{
		// arguments parsed ok and some regular command requiring network access
		struct sockaddr_in queen_address;
		if (resolve_host_port(&queen_address, queen_host, queen_port))
			return 1;

		const int sock = socketNonBlockUdp4();
		if (sock < 0)
			return 1;
		
		switch(command)
		{
			case COMMAND_KEEP_ALIVE:
			{
				code = commandKeepAlive(&queen_address, sock) ? 1 : 0;
				break;
			}
			
			default:
			{
				(void) fputs("error: command not implemented, yet", stderr);
				code = 1;
			}
		}
		
		close(sock);
	}

    return code;
}
