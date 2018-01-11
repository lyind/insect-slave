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
#include <ifaddrs.h>


/* UNIX platform stuff */
#include <arpa/inet.h>
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


/*
static int resolve_primary_address(struct sockaddr *primary_address, int primary_address_size)
{
    struct ifaddrs *if_addresses;

    if (getifaddrs(&if_addresses))
    {
        perror("getifaddrs()");
        return -1;
    }

    for (struct ifaddr *ifa = if_addresses; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL)
            continue;  

        int family, s;

        if((strcmp(ifa->ifa_name,"wlan0")==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
            printf("getnameinfo() failed: %s\n", gai_strerror(s));
            exit(EXIT_FAILURE);
            }
            printf("\tInterface : <%s>\n",ifa->ifa_name );
            printf("\t  Address : <%s>\n", host); 
        }
    }

    freeifaddrs(ifaddr);

    return 0;
}
*/

/**
 * Create an outgoing UDP socket (to a test address) and return its local IP.
 */
static int resolve_primary_address(const char *reachable_ipv4, struct sockaddr_in *primary_address, int primary_address_size)
{
    errno = 0;
    const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        perror("resolve_primary_address: socket()");
        return -1;
    }

    /* use TEST-NET-1 IP (reserved by IANA for documentation purposes) as a fallback */
    const char* test_ip = "192.0.2.1";
    if (reachable_ipv4 != NULL && strlen(reachable_ipv4) > 0)
    {
        test_ip = reachable_ipv4;
    }

    const uint16_t dns_port = 53;  /* whatever */

    struct sockaddr_in test_address;
    memset(&test_address, 0, sizeof(test_address));
    test_address.sin_family = AF_INET;
    test_address.sin_port = htons(dns_port);

    if (!inet_aton(test_ip, &test_address.sin_addr))
    {
        (void) fprintf(stderr, "error: invalid IPv4 address: %s\n", test_ip);
        return -1;
    }

    errno = 0;
    if (connect(sock, (const struct sockaddr*) &test_address, sizeof(test_address)))
    {
        perror("resolve_primary_address: connect()");
        return -1;
    }

    errno = 0;
    if (getsockname(sock, (struct sockaddr*) primary_address, &primary_address_size))
    {
        perror("resolve_primary_address: getsockname()");
        return -1;
    }

    errno = 0;
    if (close(sock))
    {
        perror("resolve_primary_address: close()");
        return -1;
    }

    return 0;
}


/** Allocate a dynamic listen TCP (IPv4) port and immediately close the socket.
 *
 * @return 0 if bound_address has been filled with the outgoing address and an allocated TCP port
 *         or -1 if any error occured
 */
static int allocate_port(const char *bind_host, uint16_t bind_port, struct sockaddr_in *bound_address, const char *reachable_ipv4)
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

    socklen_t bound_address_size = sizeof(*bound_address);
    memset(bound_address, 0, bound_address_size);
    errno = 0;
    if (getsockname(sock, (struct sockaddr *) bound_address, &bound_address_size))
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

    /** INADDR_ANY (0.0.0.0) ? */
    if (bound_address->sin_addr.s_addr == 0)
    {
        const uint16_t port = bound_address->sin_port;

        if (resolve_primary_address(reachable_ipv4, bound_address, bound_address_size))
        {
            (void) fprintf(stderr, "error: failed to resolve primary address\n");
            return -1;
        }

        bound_address->sin_port = port;
    }

    return 0;
}


int main(int argc, char **argv)
{
    if (argc < 2)
    {
        (void) fprintf(stderr, "error: no bind address specified\n");
        return 1;
    }
    else if (argc > 3)
    {
        (void) fprintf(stderr, "error: superfluous arguments specified\n");
        return 1;
    }

    struct sockaddr_in bound_address = { 0 };
    if (allocate_port(argv[1], 0, &bound_address, (argc == 3) ? argv[2] : NULL))
    {
        (void) fprintf(stderr, "error: failed to allocate port\n");
        return 1;
    }

    (void) printf("%s\t%hu\n", inet_ntoa(bound_address.sin_addr), ntohs(bound_address.sin_port));

    return 0;
}

