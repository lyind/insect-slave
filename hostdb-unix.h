#ifndef _HOSTDB_H_
#define _HOSTDB_H_
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


#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "insect-types.h"

// TODO Make this dynamic
#define DB_ENTRY_SIZE sizeof(dependency_state_t)

#define DB_FILE_NAME "insect-slave"


typedef struct db_s
{
    dependency_state_t *record;
    int       fd;
    size_t    size;
}
db_t;


static inline void exit_log(const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    (void) vfprintf(stderr, fmt, ap);
    va_end (ap);

    exit(1);
}


static inline void exit_syslog(const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    vsyslog(LOG_ERR, fmt, ap);
    va_end (ap);

    exit(1);
}


static inline unsigned db_entry_count(db_t *db)
{
    if (db->fd <= 0)
        return 0;

    return db->size / DB_ENTRY_SIZE;
}


static inline dependency_state_t *db_insert_dependency_route(db_t *db, const char *route)
{
	// TODO Skip timed out entries
    int route_length = route ? strlen(route) : 0;
    if (route_length >= sizeof(db->record[0].route))
    {
        --route_length;
    }
    
    for (unsigned i = 0; i < db_entry_count(db); ++i)
    {
        if (strncmp(db->record[i].route, route, route_length) == 0)
        {
            return db->record + i;
        }
        else if (db->record[i].route[0] == '\0')
        {
            (void) strncpy(db->record[i].route, route, route_length);
            return db->record + i;
        }
    }

	return NULL;
}


static inline dependency_state_t *db_find_dependency_by_route(db_t *db, const char *route)
{
	// TODO Skip timed out entries
    const int routeLength = route ? strlen(route) : 0;
    
	for (unsigned i = 0; i < db_entry_count(db); ++i)
	{
		if (strncmp(db->record[i].route, route, routeLength) == 0)
		{
			return db->record + i;
		}
	}
	
	return NULL;
}


static inline dependency_state_t *db_update_dependency_state_for_host(db_t *db, const char *route, const char *host, uint16_t port, const insect_mapping_t *mapping, int size)
{
    const int host_length = (host) ? strlen(host) : 0;

    // find dependency and update its state
    dependency_state_t *dependency_state = db_find_dependency_by_route(db, route);
    if (dependency_state == NULL)
    {
        return NULL;
    }
    
    // find first record matching address or first free record and overwrite
    for (message_buffer_t *state = dependency_state->state;
        state < dependency_state->state + COUNT_OF(dependency_state->state);
        ++state)
    {
        if (state->mapping.type != INSECT_MESSAGE_MAPPING
            || (state->mapping.port == port
                && host_length == state->mapping.hostLength
                && strncmp(state->mapping.data, host, host_length) == 0))
        {
            // found slot, copy
            memcpy(state->buffer, mapping, size);
            return dependency_state;
        }
    }

    return NULL;
}


static inline const dependency_state_t *db_find_dependency_unresolved(db_t *db)
{
	// TODO Skip timed out entries
	for (unsigned i = 0; i < db_entry_count(db) && db->record[i].route[0]; ++i)
	{
		if (!db->record[i].state[0].mapping.type)
		{
			return db->record + i;
		}
	}
	
	return NULL;
}


static inline unsigned db_count_dependencies_unresolved(db_t *db)
{
    // TODO Skip timed out entries
	unsigned count = 0;
	for (unsigned i = 0; i < db_entry_count(db) && db->record[i].route[0]; ++i)
	{
        // have no candidate yet? count.
		if (db->record[i].state[0].mapping.type != INSECT_MESSAGE_MAPPING)
		{
			++count;
		}
	}
    
    return count;
}


static inline void db_delete_dependency_state(db_t *db)
{
    for (unsigned i = 0; i < db_entry_count(db); ++i)
    {
        memset(&db->record[i].state, 0, sizeof(db->record[0].state));
    }
}


static int db_print_dependencies_resolved(db_t *db)
{
    // TODO Skip timed out entries
	for (unsigned i = 0; i < db_entry_count(db) && db->record[i].route[0]; ++i)
	{
        for (unsigned j = 0; j < COUNT_OF(db->record[0].state); ++j)
        {
            const insect_mapping_t *mapping = &db->record[i].state[j].mapping;
            
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


static inline int db_alloc(const db_t *db, size_t size)
{
    errno = 0;
    int status = ftruncate(db->fd, size);
    if (status)
    {
        perror("db_alloc(): ftruncate()");
        syslog(LOG_ERR, "db_alloc(): ftruncate() failed: %m\n");
    }

    return status;
}


static inline int db_open_readwrite(db_t *db)
{
    errno = 0;
    db->fd = open("/tmp/" DB_FILE_NAME ".db", O_RDWR | O_CREAT, 0644);
    if (db->fd < 0)
    {
        perror("db_open_readwrite(): open(\"/tmp/" DB_FILE_NAME ".db\")");
        syslog(LOG_ERR, "db_open_readwrite(): open(\"/tmp/" DB_FILE_NAME ".db\") failed: %m\n");
        return -1;
    }

    if (db_alloc(db, db->size))
    {
        return -1;
    }

    errno = 0;
    db->record = mmap(NULL, db->size, PROT_READ | PROT_WRITE, MAP_SHARED, db->fd, 0);
    if (db->record == MAP_FAILED)
    {
        perror("db_open_readwrite(): mmap()");
        syslog(LOG_ERR, "db_open_readwrite(): mmap() failed: %m\n");
        return -1;
    }

    return 0;
}


static inline int db_open_readonly(db_t *db)
{
    struct stat s;

    errno = 0;
    db->fd = open("/tmp/" DB_FILE_NAME ".db", O_RDONLY, 0644);
    if (db->fd < 0)
    {
        perror("db_open_readonly(): open(\"/tmp/" DB_FILE_NAME ".db\")");
        syslog(LOG_ERR, "db_open_readonly(): open(\"/tmp/" DB_FILE_NAME ".db\"): %m\n");
        return -1;
    }

    errno = 0;
    if (fstat(db->fd, &s))
    {
        perror("db_open_readonly(): fstat()");
        syslog(LOG_ERR, "open_db(): fstat(): %m\n");
        (void) close(db->fd);
        return -1;
    }

    db->size = s.st_size;

    errno = 0;
    db->record = mmap(NULL, db->size, PROT_READ, MAP_SHARED, db->fd, 0);
    if (db->record == MAP_FAILED)
    {
        perror("db_open_readonly(): mmap()");
        syslog(LOG_ERR, "open_db(): mmap(): %m\n");
        (void) close(db->fd);
        return -1;
    }

    return 0;
}

static inline void db_close(db_t *db)
{
    (void) munmap(db->record, db->size);
    (void) close(db->fd);
}


#endif   /* _HOSTDB_H_ */

