#ifndef _INSECT_TYPES_H_
#define _INSECT_TYPES_H_
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


#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#ifndef _WIN32

#include <netdb.h>

#else

/* this must be some ghastly Windoze, maybe even NT4! */

/* we support everything from vista onwards */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#endif

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))


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


#define BUFFER_SIZE 1500

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


typedef struct dependency_state_s
{
	char route[256];
	message_buffer_t state[16];
}
__attribute__((packed))
dependency_state_t;

#endif /* _INSECT_TYPES_H_ */

