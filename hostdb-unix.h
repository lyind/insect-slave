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
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/file.h>

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


static inline bool db_lock(db_t *db, bool writable)
{
    struct flock lock;
    lock.l_type = writable ? F_WRLCK : F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    return fcntl(db->fd, F_SETLKW, &lock) == 0;
}


static inline bool db_unlock(db_t *db)
{
    struct flock lock;
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    return fcntl(db->fd, F_SETLK, &lock) == 0;
}


static inline unsigned db_entry_count(db_t *db)
{
    if (db->fd <= 0)
        return 0;

    return db->size / DB_ENTRY_SIZE;
}


static inline dependency_state_t *db_insert_dependency_route(db_t *db, const char *route)
{
    if (!db_lock(db, true))
    {
        return NULL;
    }

	// TODO Skip timed out entries
    int route_length = route ? strlen(route) : 0;
    if (route_length >= sizeof(db->record[0].route))
    {
        --route_length;
    }
    
    dependency_state_t *dependency = NULL;
    for (unsigned i = 0; i < db_entry_count(db); ++i)
    {
        if (strncmp(db->record[i].route, route, route_length) == 0)
        {
            dependency = db->record + i;
            break;
        }
        else if (db->record[i].route[0] == '\0')
        {
            // initialize
            (void) strncpy(db->record[i].route, route, route_length);
            dependency = db->record + i;
            break;
        }
    }

    if (!db_unlock(db))
    {
        return NULL;
    }

	return dependency;
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


static inline int db_compare_state_by_timestamp(const void *a, const void *b)
{
    const insect_mapping_t *m1 = &((const message_buffer_t*)a)->mapping;
    const insect_mapping_t *m2 = &((const message_buffer_t*)b)->mapping;

    const int64_t ts1 = (m1->type == INSECT_MESSAGE_MAPPING) ? ntohll(m1->ts) : INT64_MIN;
    const int64_t ts2 = (m2->type == INSECT_MESSAGE_MAPPING) ? ntohll(m2->ts) : INT64_MIN;

    if (ts1 < ts2)
    {
        return 1;
    }
    else if (ts1 > ts2)
    {
        return -1;
    }

    return 0;
}


static inline dependency_state_t *db_update_dependency_state_for_host(db_t *db, const char *route, const char *host, uint16_t port, const insect_mapping_t *mapping, int size)
{
    if (!db_lock(db, true))
    {
        return NULL;
    }

    // find dependency and update its state
    dependency_state_t *dependency = db_find_dependency_by_route(db, route);
    if (dependency != NULL)
    {
        // find first record matching address or first free record and overwrite
        const int host_length = (host) ? strlen(host) : 0;
        message_buffer_t *state = dependency->state;
        for (; state < dependency->state + COUNT_OF(dependency->state); ++state)
        {
            if (state->mapping.type != INSECT_MESSAGE_MAPPING
                || (state->mapping.port == port
                    && host_length == state->mapping.hostLength
                    && strncmp(state->mapping.data, host, host_length) == 0))
            {
                // found slot, copy
                memcpy(state->buffer, mapping, size);
                break;
            }
        }

        if (state >= dependency->state + COUNT_OF(dependency->state))
        {
            // found no free or mergable slot, replace oldest entry
            memset(dependency->state + COUNT_OF(dependency->state) - 1, 0, sizeof(*dependency->state));
            memcpy((dependency->state + COUNT_OF(dependency->state) - 1)->buffer, mapping, size);
        }

        // sort by timestamp
        qsort(dependency->state, COUNT_OF(dependency->state), sizeof(*dependency->state), db_compare_state_by_timestamp);
    }

    if (!db_unlock(db))
    {
        return NULL;
    }

    return dependency;
}


static inline const dependency_state_t *db_find_dependency_unresolved(db_t *db)
{
    if (!db_lock(db, false))
    {
        return NULL;
    }

	// TODO Skip timed out entries
    dependency_state_t *dependency = NULL;
	for (unsigned i = 0; i < db_entry_count(db) && db->record[i].route[0]; ++i)
	{
		if (!db->record[i].state[0].mapping.type)
		{
			dependency = db->record + i;
            break;
		}
	}
	
    if (!db_unlock(db))
    {
        return NULL;
    }

	return dependency;
}


static inline unsigned db_count_dependencies_unresolved(db_t *db)
{
    if (!db_lock(db, false))
    {
        return UINT_MAX;
    }

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
    
    if (!db_unlock(db))
    {
        return UINT_MAX;
    }

    return count;
}


static inline void db_delete_dependency_state(db_t *db)
{
    db_lock(db, true);

    for (unsigned i = 0; i < db_entry_count(db); ++i)
    {
        memset(db->record[i].state, 0, sizeof(db->record[0].state));
    }

    db_unlock(db);
}


static bool db_print_dependencies_resolved(db_t *db)
{
    if (!db_lock(db, false))
    {
        return false;
    }

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
                    db_unlock(db);
                    return false;
                }
            }
            else
            {
                // next dependency
                break;
            }
        }
	}

    return db_unlock(db);
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

