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
 *   lookup            Lookup dependencies and output:
 *                     ROUTE NAME HOST PORT TIMESTAMP
 * 
 * OPTIONS:
 * 
 *   -h                    Show this help
 * 
 *   -d DEPENDENCY_ROUTE   Slave dependency route (up to 16 allowed)
 *   -n UNIQUE_SLAVE_NAME  Slave route
 *   -p SLAVE_PORT         Slave port
 *   -P QUEEN_PORT         Remote queen port
 *   -q QUEEN_HOST         Remote queen hostname or address
 *   -r ROUTE              Slave route
 *   -s SLAVE_HOST         Slave host address or name
 *
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>


#ifndef _WIN32

/* UNIX platform stuff */
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>

#else

/* this must be some ghastly Windoze, maybe even NT4! */

/* we support everything from vista onwards */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#ifndef POLLERR
#define POLLERR 0
#endif
#define poll(fdarray, nfds, timeout) WSAPoll(fdarray, nfds, timeout)

#endif


#define BUFFER_SIZE 1500

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

// TODO Make this configurable.
#define KEEP_ALIVE_INTERVAL_MICROS  1000000    // 1s


typedef enum insect_message_type_e
{
    INSECT_MESSAGE_NONE = 0,
    INSECT_MESSAGE_MAPPING = 1,
    INSECT_MESSAGE_SHUTDOWN = 2,
    INSECT_MESSAGE_INVALIDATE = 3
}
insect_message_type_t;


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
    char data[];             // UTF-8 encoded data fields:
    // 1. client IPv4 address/hostname as non-terminated UTF-8 string
    // 2. route (exported path, non-terminated UTF-8 string)
    // 3. unique service name (non-terminated UTF-8 string)
    // 4. as single dependency to be subscribed (non-terminated UTF-8 string)
}
__attribute__((packed))
insect_mapping_t;


/** Shutdown command message */
typedef struct insect_shutdown_s
{
    uint8_t type;             // message type (2: shutdown)
    uint8_t magic;            // 0x86
}
__attribute__((packed))
insect_shutdown_t;


/** Invalidate command message */
typedef struct insect_invalidate_s
{
    uint8_t type;             // message type (3: shutdown)
    uint8_t magic;            // 0x73
}
__attribute__((packed))
insect_invalidate_t;


typedef union message_buffer_u
{
    char buffer[BUFFER_SIZE];
    insect_mapping_t mapping;
    insect_shutdown_t shutdown;
    insect_invalidate_t invalidate;
}
__attribute__((packed))
message_buffer_t;


static message_buffer_t out = { 0 };
static message_buffer_t in = { 0 };


typedef struct dependency_state_s
{
	char route[256];
	message_buffer_t state[16];  // TODO allocate this on demand or use a database
}
dependency_state_t;


typedef enum insect_command_e
{
	COMMAND_NONE,
    COMMAND_HELP,
    COMMAND_KEEP_ALIVE,
    COMMAND_LOOKUP
}
insect_command_t;



/** Callback that may handle received messages.
 * 
 * Messages are checked for validity at the point the callback is executed.
 * 
 * @param size The validated message size.
 * @param type The message type.
 * 
 * @return 0 if successful -1 if an error occured, 1 if the operation finished.
 */
typedef int (incoming_message_cb)(const message_buffer_t *message, int size, uint_fast8_t type);


static insect_command_t command = COMMAND_NONE;

static char slave_host[256] = { '\0' };
static char slave_route[256] = { '\0' };
static char slave_name[256] = { '\0' };
static char queen_host[256] = { '\0' };
static dependency_state_t dependencies[16] = { 0 };

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
   keep-alive       Send periodic mapping messages\n\
   lookup           Lookup dependencies and output (TAB separated):\n\
                    ROUTE  NAME  HOST  PORT  TIMESTAMP\n\
\n\
OPTIONS:\n\
\n\
   -h                    Show this help\n\
\n\
   -d DEPENDENCY_ROUTE   Slave dependency route (up to 16 allowed)\n\
   -n UNIQUE_SLAVE_NAME  Slave route\n\
   -p SLAVE_PORT         Slave port\n\
   -P QUEEN_PORT         Remote queen port\n\
   -q QUEEN_HOST         Remote queen hostname or address\n\
   -r ROUTE              Slave route\n\
   -s SLAVE_HOST         Slave host address or name\n", stderr);
}


/** Convert 64-bit integer from host order to big-endian, if necessary. */
static inline uint64_t htonll(uint64_t n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

/** Convert 64-bit integer from big-endian to host order, if necessary. */
static inline uint64_t ntohll(uint64_t n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)ntohl(n)) << 32) + ntohl(n >> 32);
#endif
}


/** Parse command line arguments. */
static int parse_args(int argc, char *argv[])
{
	errno = 0;
    opterr = 0;
    
    int c;
    while ((c = getopt(argc, argv, "hd:n:p:P:q:r:s:")) != -1)
    {
        switch (c)
        {
            case 'h':
            {
                command = COMMAND_HELP;
				return 0;
			}
            
            case 'd':
            {
                unsigned i = 0;
                for (; i < COUNT_OF(dependencies); ++i)
                {
                    if (dependencies[i].route[0] == '\0')
                    {
                        (void) strncpy(dependencies[i].route, optarg, sizeof(dependencies[0].route) - 1);
                        break;
                    }
                }
                
                if (i >= COUNT_OF(dependencies))
                {
                    (void) fputs("error: Too many dependencies specified (maximum: 16)\n", stderr);
                    return -1;
                }

                break;
            }

            case 'n':
            {
                const unsigned max_length = sizeof(slave_name) - 1;
                (void) strncpy(slave_name, optarg, max_length);
                break;
            }

            case 'p':
            {
                uint16_t port;
                if (sscanf(optarg, "%hu", &port) != 1)
                {
                    (void) fputs("error: invalid slave port specified (outside 0-65535)\n", stderr);
                    return -1;
                }
                
                slave_port = port;
                
                break;
            }
            
            case 'P':
            {
				uint16_t port;
                if (sscanf(optarg, "%hu", &port) != 1)
                {
                    (void) fputs("error: invalid queen port specified (outside 0-65535)\n", stderr);
                    return -1;
                }
                
                queen_port = port;
                
                break;
            }
            
            case 'q':
            {
                const unsigned max_length = sizeof(queen_host) - 1;
                (void) strncpy(queen_host, optarg, max_length);
                break;
            }
            
            case 'r':
            {
                const unsigned max_length = sizeof(slave_route) - 1;
                (void) strncpy(slave_route, optarg, max_length);
                break;
            }
            
            case 's':
            {
                const unsigned max_length = sizeof(slave_host) - 1;
                (void) strncpy(slave_host, optarg, max_length);
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
		#ifndef _WIN32
        perror(host);
		#else
		(void) fprintf(stderr, "error: resolving %s: error %d\n", host, WSAGetLastError());
		#endif
		return -1;
    }

	memset(address, 0, sizeof(struct sockaddr_in));
	
    address->sin_family = AF_INET;
    memcpy((char *)&address->sin_addr.s_addr, (char *)host_entity->h_addr, host_entity->h_length);
    address->sin_port = htons(port);
	
	return 0;
}


#ifndef _WIN32

/** Get microseconds since EPOCH on any POXIX compliant system. */
static int64_t timeMicros()
{
       struct timeval tp;
       struct timezone tz;

       tz.tz_minuteswest = 0;

       (void) gettimeofday(&tp, &tz);

       return (1000000 * (int64_t)tp.tv_sec) + (int64_t)tp.tv_usec;
}

#else

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


static int createNonBlockingUDPSocket(struct sockaddr_in *bind_address, const char *bind_host, uint16_t bind_port)
{
	#ifdef _WIN32
	// Initialize Winsock2
	WSADATA wsaData;
	int status = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (status != 0)
	{
		(void) fprintf(stderr, "error: initializing Winsock2: error %ld", status);
		return -1;
	}
    #endif
	
	errno = 0;
    const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) 
    {
		#ifndef _WIN32
		perror("failed to open socket");
		#else
		(void) fprintf(stderr, "error: socket(): error %ld", WSAGetLastError());
		#endif
        return -1;
    }
	
	#ifndef _WIN32
	errno = 0;
	if (fcntl(sock, F_SETFL, O_NONBLOCK))
	{
		perror("enabling non-blocking operation");
		return -1;
	}
	#else
	unsigned long iMode = 1;
	status = ioctlsocket(sock, FIONBIO, &iMode);
	if (status != NO_ERROR)
	{
		(void) fprintf(stderr, "error: enabling non-blocking operation: error %ld", status);
		return -1;
	}
	#endif
	
	struct sockaddr_in queen_address;
	errno = 0;
	if (resolve_host_port(bind_address, bind_host, bind_port))
		return -1;
	
	errno = 0;
	if (bind(sock, (const struct sockaddr *)bind_address, sizeof(*bind_address)))
	{
		#ifndef _WIN32
		perror("bind()");
		#else
		(void) fprintf(stderr, "error: socket(): error %ld", WSAGetLastError());
		#endif
		return -1;
	}
	
	return sock;
}


static int tryRecv(int sock, const struct sockaddr_in *source_remote_address)
{
	struct sockaddr remote_address;
	socklen_t remote_address_length = sizeof(remote_address);
	memcpy(&remote_address, source_remote_address, remote_address_length);
	
	errno = 0;
    const int n = recvfrom(sock,
						   in.buffer,
						   sizeof(in.buffer),
						   0,
						   &remote_address,
						   &remote_address_length);
    if (n < 0)
	{
		#ifndef _WIN32
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			perror("recvfrom()");
			return n;
		}
		#else
		int error = WSAGetLastError();
		if (error != EAGAIN && error != EWOULDBLOCK)
		{
			(void) fprintf(stderr, "error: recvfrom(): error %ld", error);
			return n;
		}
		#endif
		
		return 0;
	}
	
	return n;
}


static int assembleMappingMessage(const char *dependency)
{
	const uint8_t host_length = strlen(slave_host);
	if (!host_length)
	{
		(void) fputs("error: slave host or address not specified\n", stderr);
		return -1;
	}
	
	const uint8_t route_length = strlen(slave_route);
	if (!route_length)
	{
		(void) fputs("error: slave route not specified\n", stderr);
		return -1;
	}
	
	const uint8_t name_length = strlen(slave_name);
	if (!name_length)
	{
		(void) fputs("error: unique slave name not specified\n", stderr);
		return -1;
	}
	
	const uint8_t dependency_length = dependency ? strlen(dependency) : 0;
	
	out.mapping.type = INSECT_MESSAGE_MAPPING; // message type (1: mapping)
	out.mapping.flags = 0x0; // 0x0
	out.mapping.hostLength = host_length; // length of bindAddress
	out.mapping.routeLength = route_length; // length of route
	out.mapping.ts = htonll(timeMicros() * 1000); // client System.nanoTime()
	out.mapping.port = htons(slave_port); // client port
	out.mapping.nameLength = name_length; // length of unique service name
	out.mapping.dependencyLength = dependency_length; // length of dependency
	
	char *data = out.mapping.data; // UTF-8 encoded data fields (see below)
	
	// 1. client IPv4 address/hostname as non-terminated UTF-8 string
	memcpy(data, slave_host, host_length);
	data += host_length;
	
	// 2. route (exported path, non-terminated UTF-8 string)
	memcpy(data, slave_route, route_length);
	data += route_length;
    
	// 3. unique service name (non-terminated UTF-8 string)
	memcpy(data, slave_name, name_length);
	data += name_length;
	
	// 4. as single dependency to be subscribed (non-terminated UTF-8 string)
	memcpy(data, dependency, dependency_length);
	data += dependency_length;
	
	return (int)((uintptr_t)data - (uintptr_t)out.buffer);
}


static dependency_state_t *findDependencyByRoute(const char *route)
{
	// TODO Skip timed out entries
    const int routeLength = route ? strlen(route) : 0;
    
	for (unsigned i = 0; i < COUNT_OF(dependencies) && dependencies[i].route[0] != '\0'; ++i)
	{
		if (strlen(dependencies[i].route) == routeLength
            && strncmp(dependencies[i].route, route, routeLength) == 0)
		{
			return dependencies + i;
		}
	}
	
	return NULL;
}


static const dependency_state_t *findFirstUnresolved()
{
	// TODO Skip timed out entries
	unsigned i = 0;
	for (; i < COUNT_OF(dependencies) && dependencies[i].route[0]; ++i)
	{
		if (!dependencies[i].state[0].mapping.type)
		{
			return dependencies + i;
		}
	}
	
	return NULL;
}


static unsigned countUnresolvedDependencies()
{
    // TODO Skip timed out entries
	int count = 0;
	for (unsigned i = 0; i < COUNT_OF(dependencies) && dependencies[i].route[0]; ++i)
	{
        // have no candidate yet? count.
		if (dependencies[i].state[0].mapping.type != INSECT_MESSAGE_MAPPING)
		{
			++count;
		}
	}
    
    return count;
}


static int printResolvedDependencies()
{
    // TODO Skip timed out entries
	for (unsigned i = 0; i < COUNT_OF(dependencies) && dependencies[i].route[0]; ++i)
	{
        for (unsigned j = 0; j < COUNT_OF(dependencies[0].state); ++j)
        {
            const insect_mapping_t *mapping = &dependencies[i].state[j].mapping;
            
            if (mapping->type == INSECT_MESSAGE_MAPPING)
            {
                // find field offsets
                const char *host = mapping->data;
                const char *route = mapping->data + mapping->hostLength;
                const char *name = mapping->data + mapping->hostLength + mapping->routeLength;
                
                const int bytesWritten = fprintf(stdout, "%.*s\t%.*s\t%.*s\t%hu\t%" PRId64 "\n",
                    mapping->routeLength,
                    route,
                    mapping->nameLength,
                    name,
                    mapping->hostLength,
                    host,
                    ntohs(mapping->port),
                    ntohll(mapping->ts));

                if (bytesWritten <= 0)
                {
                    perror("writing lookup results");
                    return -1;
                }
            }
            else
            {
                // next dependency
                break;
            }
        }
	}
    
    return 0;
}


static int parseMessageMapping(int size)
{
    const uint8_t type = in.mapping.type;        
    if (type != INSECT_MESSAGE_MAPPING)
        return -1;
    
    if (size < 16)
    {
        (void) fprintf(stderr, "warn: received truncated mapping of %d bytes size\n", size);
        return -1;
    }
    
    const uint8_t host_length = in.mapping.hostLength; // length of host
    const uint8_t route_length = in.mapping.routeLength; // length of route
	const uint8_t name_length = in.mapping.nameLength; // length of unique service name
	const uint8_t dependency_length = in.mapping.dependencyLength; // length of dependency
    
    const int total = 16 + host_length + route_length + name_length + dependency_length;
    if (size < total)
    {
        (void) fprintf(stderr, "warn: received corrupted mapping of %d bytes size\n", size);
        return -1;
    }
    else if (size > total)
    {
        (void) fprintf(stderr, "warn: received invalid mapping of %d bytes size with superfluous data\n", size);
        return -1;
    }

    return 0;
}


static int parseMessageShutdown(int size)
{
    const uint8_t type = in.shutdown.type;
    if (type != INSECT_MESSAGE_SHUTDOWN)
        return -1;
    
    if (size != 2)
    {
        (void) fprintf(stderr, "warn: received shutdown message with unexpected size of %d bytes\n", size);
        return -1;
    }
    
    if (in.shutdown.magic != 0x86)
    {
        (void) fputs("warn: received shutdown message with unexpected magic\n", stderr);
        return -1;
    }
    
    return 0;
}


static int parseMessageInvalidate(int size)
{
    const uint8_t type = in.invalidate.type;
    if (type != INSECT_MESSAGE_INVALIDATE)
        return -1;
    
    if (size != 2)
    {
        (void) fprintf(stderr, "warn: received invalidate message with unexpected size of %d bytes\n", size);
        return -1;
    }
    
    if (in.invalidate.magic != 0x73)
    {
        (void) fputs("warn: received invalidate message with unexpected magic\n", stderr);
        return -1;
    }
    
    return 0;
}


static int handleIncomingMessage(incoming_message_cb message_callback, int size)
{
    if (size > 1 && size <= sizeof(in.buffer))
    {
        const uint_fast8_t type = in.mapping.type;
        
        if (!parseMessageMapping(size)
            || !parseMessageShutdown(size)
            || !parseMessageInvalidate(size))
        {
            return message_callback(&in, size, type);
        }
        else
        {
            (void) fprintf(stderr, "warn: received message of unknown type %d and %d bytes size\n", type, size);
        }
    }
    else
    {
        (void) fprintf(stderr, "warn: received invalid message of %d bytes size\n", size);
    }
    
    return -1;
}


static int trySendKeepAlive(int sock, const struct sockaddr_in *destination_remote_address)
{
	// TODO Assemble keep-alive message in out.mapping
	// find first unresolved dependency and attach to mapping
	const dependency_state_t *unresolvedDependency = findFirstUnresolved();
	if (unresolvedDependency)
    {
        (void) fprintf(stderr, "info: resolving dependency: %s\n", unresolvedDependency->route);
    }
    
	const int messageSize = assembleMappingMessage(unresolvedDependency ? unresolvedDependency->route : NULL);
	
	errno = 0;
    const int n = sendto(sock,
						 out.buffer,
						 messageSize,
						 0,
						 (const struct sockaddr *)destination_remote_address,
						 sizeof(*destination_remote_address));
    if (n != messageSize)
	{
		#ifndef _WIN32
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			perror("sendto()");
			return -1;
		}
		#else
		int error = WSAGetLastError();
		if (error != EAGAIN && error != EWOULDBLOCK)
		{
			(void) fprintf(stderr, "error: sendto(): error %ld", error);
			return -1;
		}
		#endif

		return 0;
	}
	
	return n;
}


static int exchangeMessages(incoming_message_cb callback, struct sockaddr_in *queen_address, int sock)
{
	int64_t now = timeMicros();
	int64_t nextKeepalive = now;
	do
	{
		const int64_t timeout = nextKeepalive - now;
		const int timeout_ms = timeout / 1000;
		
		struct pollfd pfd;
		pfd.fd = sock;
		#ifndef _WIN32
		pfd.events = POLLERR | POLLIN | ((timeout_ms <= 0) ? POLLOUT : 0);
		#else
		pfd.events = POLLRDNORM | ((timeout_ms <= 0) ? POLLWRNORM : 0);
		#endif
		pfd.revents = 0;
		
		errno = 0;
		int status = poll(&pfd, 1, timeout_ms);
		if (status < 0 || (pfd.revents & (POLLERR | POLLHUP)))
		{
			#ifndef _WIN32
			perror("poll()");
			#else
			(void) fprintf(stderr, "error: poll(): error %ld", WSAGetLastError());
			#endif

			return -1;
		}
		
		int sentKeepAliveSize = 0;
		#ifndef _WIN32
		if (status == 0 || (pfd.revents & POLLOUT))
		#else
		if (status == 0 || (pfd.revents & POLLWRNORM))
		#endif
		{
			// timeout, try to send keep-alive immediately
			sentKeepAliveSize = trySendKeepAlive(sock, queen_address);
			//fprintf(stderr, "trySendKeepAlive(): %d\n", sentKeepAliveSize);
			if (sentKeepAliveSize < 0)
			{
				return -1;
			}
		}
		
		#ifndef _WIN32
		if (status > 0 && (pfd.revents & POLLIN))
		#else
		if (status > 0 && (pfd.revents & POLLRDNORM))
		#endif
		{
			int receivedSize = tryRecv(sock, queen_address);
            //fprintf(stderr, "tryRecv(): %d\n", receivedSize);
			if (receivedSize > 0)
			{
				int result = handleIncomingMessage(callback, receivedSize);
                if (result < 0)
                {
                    return -1;
                }
                else if (result > 0)
                {
                    return 0;
                }
			}
			else if (receivedSize < 0)
			{
				return -1;
			}
		}
		
		now = timeMicros(); // sample timestamp for next run
		
		// time for next keep-alive?
		if (sentKeepAliveSize > 0)
		{
			nextKeepalive = now + KEEP_ALIVE_INTERVAL_MICROS;
		}
	}
	while(1);  // TODO handle Ctrl-C / SIGTERM
	
	return 0;
}


/** Handle an incoming mapping.
 * 
 * @return Pointer to the updated dependency or NULL.
 */
static const dependency_state_t *handleMapping(const insect_mapping_t *mapping, int size)
{
    // parse route
    char route[256] = {0};
    (void) strncpy(route, mapping->data + mapping->hostLength, mapping->routeLength);
    
    // find dependency and update its state
    dependency_state_t *dependency_state = findDependencyByRoute(route);
    if (dependency_state == NULL)
    {
        (void) fprintf(stderr, "info: ignoring mapping for unneeded route %s\n", route);
        return NULL;
    }
    
    // parse host
    char host[256] = {0};
    (void) strncpy(route, mapping->data, mapping->hostLength);
    
    // find first record matching address or first free record and overwrite
    for (message_buffer_t *state = dependency_state->state;
        state < dependency_state->state + COUNT_OF(dependency_state->state);
        ++state)
    {
        if (state->mapping.type != INSECT_MESSAGE_MAPPING
            || (state->mapping.port == mapping->port
                && mapping->hostLength == state->mapping.hostLength
                && strncmp(state->mapping.data, host, mapping->hostLength) == 0))
        {
            // found slot, copy
            memcpy(state->buffer, mapping, size);
            return dependency_state;
        }
    }
    
    return NULL;
}


static void handleInvalidate()
{
    (void) fprintf(stderr, "info: invalidating all resolved dependencies\n");
    
    // remove all information about slaves
    for (unsigned i = 0; i < COUNT_OF(dependencies); ++i)
    {
        memset(&dependencies[i].state, 0, sizeof(dependencies[0].state));
    }
}


static int commandKeepAliveMessageHandler(const message_buffer_t *message, int size, uint_fast8_t type)
{
    switch(type)
    {
        case INSECT_MESSAGE_MAPPING:
        {
            (void) handleMapping(&message->mapping, size);
            break;
        }
        
        case INSECT_MESSAGE_SHUTDOWN:
        {
            (void) fprintf(stderr, "info: planned remote shutdown\n");
            return 1;
        }
        
        case INSECT_MESSAGE_INVALIDATE:
        {
            handleInvalidate();
            break;
        }
        
        default:
            break;
    }
    
    return 0;
}


static int commandLookupMessageHandler(const message_buffer_t *message, int size, uint_fast8_t type)
{
    switch(type)
    {
        case INSECT_MESSAGE_MAPPING:
        {
            const dependency_state_t *dependency_state = handleMapping(&message->mapping, size);
            if (dependency_state != NULL)
            {
                // check if all requested dependencies have been resolved
                int unresolvedCount = countUnresolvedDependencies();
                if (unresolvedCount == 0)
                {
                    // dump all results
                    return printResolvedDependencies() ? -1 : 1;
                }
            }
            
            break;
        }
        
        case INSECT_MESSAGE_SHUTDOWN:
        {
            (void) fprintf(stderr, "info: planned remote shutdown\n");
            return 1;
        }
        
        case INSECT_MESSAGE_INVALIDATE:
        {
            handleInvalidate();
            break;
        }
        
        default:
            break;
    }
    
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
		struct sockaddr_in slave_address;
		const int sock = createNonBlockingUDPSocket(&slave_address, slave_host, slave_port);
		if (sock < 0)
			return 1;
	
		// arguments parsed ok and some regular command requiring network access
		struct sockaddr_in queen_address;
		if (resolve_host_port(&queen_address, queen_host, queen_port))
			return 1;
		
		switch(command)
		{
			case COMMAND_KEEP_ALIVE:
			{
				code = exchangeMessages(commandKeepAliveMessageHandler, &queen_address, sock) ? 1 : 0;
				break;
			}
            
            case COMMAND_LOOKUP:
            {
                code = exchangeMessages(commandLookupMessageHandler, &queen_address, sock) ? 1 : 0;
                break;
            }
			
			default:
			{
				(void) fputs("error: command not implemented, yet", stderr);
				code = 1;
			}
		}
		
		close(sock);
		
		#ifdef _WIN32
		WSACleanup();
		#endif
	}

    return code;
}
