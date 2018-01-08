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
 * allocate-port.c - Simple dynamic port allocation helper
 *
 * Lets the kernel allocate a dynamic TCP listen port, outputs it and exits.
 * 
 * USAGE:
 * 
 *   allocate-port ADDRESS
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


/* UNIX platform stuff */
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>


static int resolve_host_port(struct sockaddr_in *address, const char *host, uint_fast16_t port)
{
    struct hostent *host_entity = gethostbyname(host);
    h_errno = 0;
    if (host_entity == NULL)
    {
        (void) fprintf(stderr, "Error: gethostbyname(): %s\n", hstrerror(h_errno));
		return -1;
    }

	memset(address, 0, sizeof(struct sockaddr_in));
	
    address->sin_family = AF_INET;
    memcpy((char *)&address->sin_addr.s_addr, (char *)host_entity->h_addr, host_entity->h_length);
    address->sin_port = htons(port);
	
	return 0;
}


/** Allocate a dynamic listen TCP (IPv4) port and immediately close the socket.
 *
 * @return Allocated TCP port, -1 on any error.
 */
static int allocate_port(const char *bind_host, uint16_t bind_port)
{
	errno = 0;
    const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) 
    {
		perror("socket()");
        return -1;
    }

	errno = 0;
    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)))
    {
		perror("setsockopt()");
        return -1;
    }
	
	errno = 0;
    struct sockaddr_in bind_address;
	if (resolve_host_port(&bind_address, bind_host, bind_port))
    {
		return -1;
    }
	
	errno = 0;
	if (bind(sock, (const struct sockaddr *)&bind_address, sizeof(bind_address)))
	{
		perror("bind()");
		return -1;
	}

    errno = 0;
    struct sockaddr_in bound_address = { 0 };
    socklen_t bound_address_len = sizeof(bound_address);
    if (getsockname(sock, (struct sockaddr *) &bound_address, &bound_address_len))
    {
		perror("getsockname()");
		return -1;
    }

    errno = 0;
    if (close(sock))
    {
		perror("close()");
		return -1;
    }
	
    return ntohs(bound_address.sin_port);
}


int main(int argc, char **argv)
{
    if (argc != 2)
    {
        (void) fprintf(stderr, "error: no bind address specified\n");
        return 1;
    }

    int port = allocate_port(argv[1], 0);
    if (port < 0)
    {
        (void) fprintf(stderr, "error: failed to allocate port\n");
        return 1;
    }

    (void) printf("%hu", port);

    return 0;
}

