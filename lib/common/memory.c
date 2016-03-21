/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h> 
#include <stdio.h>
#include <stdint.h>
#include <string.h>

//winbase.h creates of issues if windows.h is not included before it.
#ifdef  _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <Winbase.h> 
#else
#include <stdlib.h>
#include <unistd.h>
#endif

#include "C:\Users\Rathi\Desktop\Repository\one-four-2016\http2-repo1\mmanlibrary_ExternalPosixReplacements\mman.h"  : memory.c
#include "h2o/memory.h"
#include "io.h"


#ifdef _WIN32
//Open file with random name generated using temp, with read and write permission, and O_CLOEXEC FLAG. 
int mkstemp(char* temp) {
	char *fnTemplate = "fnXXXXXX"; //Last six characters should be like this
	int sizeInChars;
	sizeInChars = strnlen(temp, 9) + 1;
	FILE *fp;
	errno_t err = _mktemp_s(temp, sizeInChars); //creates a file name...
	if (err != 0)
		return -1;
	else //File name successfully created
	{
		if (fp = fopen(temp, "ab+")) // create the file with read/write permission.
			return _fileno(fp);	//Successful return file descriptor.					 
		else
			return -1;
		fclose(fp);
	}
}

//getpagesize for windows
long getpagesize(void) {
	static long g_pagesize = 0;
	if (!g_pagesize) {
		SYSTEM_INFO system_info;
		GetSystemInfo(&system_info);
		g_pagesize = system_info.dwPageSize;
	}
	return g_pagesize;
}
#endif //Win32

struct st_h2o_mem_recycle_chunk_t {
    struct st_h2o_mem_recycle_chunk_t *next;
};

struct st_h2o_mem_pool_chunk_t {
    struct st_h2o_mem_pool_chunk_t *next;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[4096 - sizeof(void *) * 2];
};

struct st_h2o_mem_pool_direct_t {
    struct st_h2o_mem_pool_direct_t *next;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[1];
};

struct st_h2o_mem_pool_shared_ref_t {
    struct st_h2o_mem_pool_shared_ref_t *next;
    struct st_h2o_mem_pool_shared_entry_t *entry;
};

#ifdef _WIN32
static h2o_mem_recycle_t mempool_allocator = { 16 };
#else
static __thread h2o_mem_recycle_t mempool_allocator = { 16 };
#endif

void h2o_fatal(const char *msg)
{
    fprintf(stderr, "fatal:%s\n", msg);
    abort();
}

void *h2o_mem_alloc_recycle(h2o_mem_recycle_t *allocator, size_t sz)
{
    struct st_h2o_mem_recycle_chunk_t *chunk;
    if (allocator->cnt == 0)
        return h2o_mem_alloc(sz);
    /* detach and return the pooled pointer */
    chunk = allocator->_link;
    assert(chunk != NULL);
    allocator->_link = chunk->next;
    --allocator->cnt;
    return chunk;
}

void h2o_mem_free_recycle(h2o_mem_recycle_t *allocator, void *p)
{
    struct st_h2o_mem_recycle_chunk_t *chunk;
    if (allocator->cnt == allocator->max) {
        free(p);
        return;
    }
    /* register the pointer to the pool */
    chunk = p;
    chunk->next = allocator->_link;
    allocator->_link = chunk;
    ++allocator->cnt;
}

void h2o_mem_init_pool(h2o_mem_pool_t *pool)
{
    pool->chunks = NULL;
    pool->chunk_offset = sizeof(pool->chunks->bytes);
    pool->directs = NULL;
    pool->shared_refs = NULL;
}

void h2o_mem_clear_pool(h2o_mem_pool_t *pool)
{
    /* release the refcounted chunks */
    if (pool->shared_refs != NULL) {
        struct st_h2o_mem_pool_shared_ref_t *ref = pool->shared_refs;
        do {
            h2o_mem_release_shared(ref->entry->bytes);
        } while ((ref = ref->next) != NULL);
        pool->shared_refs = NULL;
    }
    /* release the direct chunks */
    if (pool->directs != NULL) {
        struct st_h2o_mem_pool_direct_t *direct = pool->directs, *next;
        do {
            next = direct->next;
            free(direct);
        } while ((direct = next) != NULL);
        pool->directs = NULL;
    }
    /* free chunks, and reset the first chunk */
    while (pool->chunks != NULL) {
        struct st_h2o_mem_pool_chunk_t *next = pool->chunks->next;
        h2o_mem_free_recycle(&mempool_allocator, pool->chunks);
        pool->chunks = next;
    }
    pool->chunk_offset = sizeof(pool->chunks->bytes);
}

void *h2o_mem_alloc_pool(h2o_mem_pool_t *pool, size_t sz)
{
    void *ret;

    if (sz >= sizeof(pool->chunks->bytes) / 4) {
        /* allocate large requests directly */
        struct st_h2o_mem_pool_direct_t *newp = h2o_mem_alloc(offsetof(struct st_h2o_mem_pool_direct_t, bytes) + sz);
        newp->next = pool->directs;
        pool->directs = newp;
        return newp->bytes;
    }

    /* 16-bytes rounding */
    sz = (sz + 15) & ~15;
    if (sizeof(pool->chunks->bytes) - pool->chunk_offset < sz) {
        /* allocate new chunk */
        struct st_h2o_mem_pool_chunk_t *newp = h2o_mem_alloc_recycle(&mempool_allocator, sizeof(*newp));
        newp->next = pool->chunks;
        pool->chunks = newp;
        pool->chunk_offset = 0;
    }

    ret = pool->chunks->bytes + pool->chunk_offset;
    pool->chunk_offset += sz;
    return ret;
}

static void link_shared(h2o_mem_pool_t *pool, struct st_h2o_mem_pool_shared_entry_t *entry)
{
    struct st_h2o_mem_pool_shared_ref_t *ref = h2o_mem_alloc_pool(pool, sizeof(struct st_h2o_mem_pool_shared_ref_t));
    ref->entry = entry;
    ref->next = pool->shared_refs;
    pool->shared_refs = ref;
}

void *h2o_mem_alloc_shared(h2o_mem_pool_t *pool, size_t sz, void (*dispose)(void *))
{
    struct st_h2o_mem_pool_shared_entry_t *entry = h2o_mem_alloc(offsetof(struct st_h2o_mem_pool_shared_entry_t, bytes) + sz);
    entry->refcnt = 1;
    entry->dispose = dispose;
    if (pool != NULL)
        link_shared(pool, entry);
    return entry->bytes;
}

void h2o_mem_link_shared(h2o_mem_pool_t *pool, void *p)
{
    h2o_mem_addref_shared(p);
    link_shared(pool, H2O_STRUCT_FROM_MEMBER(struct st_h2o_mem_pool_shared_entry_t, bytes, p));
}

static size_t topagesize(size_t capacity)
{
    size_t pagesize = getpagesize(); 
    return (offsetof(h2o_buffer_t, _buf) + capacity + pagesize - 1) / pagesize * pagesize;
}

void h2o_buffer__do_free(h2o_buffer_t *buffer)
{
    /* caller should assert that the buffer is not part of the prototype */
    if (buffer->capacity == buffer->_prototype->_initial_buf.capacity) {
        h2o_mem_free_recycle(&buffer->_prototype->allocator, buffer);
    } else if (buffer->_fd != -1) {
#ifdef _WIN32
		_close(buffer->_fd);
#else
		close(buffer->_fd);
#endif
		munmap(buffer, topagesize(buffer->capacity)); 
    } else {
        free(buffer);
    }
}

h2o_iovec_t  h2o_buffer_reserve(h2o_buffer_t **_inbuf, size_t min_guarantee)
{
    h2o_buffer_t *inbuf = *_inbuf;
    h2o_iovec_t  ret;

    if (inbuf->bytes == NULL) {
        h2o_buffer_prototype_t *prototype = H2O_STRUCT_FROM_MEMBER(h2o_buffer_prototype_t, _initial_buf, inbuf);
        if (min_guarantee <= prototype->_initial_buf.capacity) {
            min_guarantee = prototype->_initial_buf.capacity;
            inbuf = h2o_mem_alloc_recycle(&prototype->allocator, offsetof(h2o_buffer_t, _buf) + min_guarantee);
        } else {
            inbuf = h2o_mem_alloc(offsetof(h2o_buffer_t, _buf) + min_guarantee);
        }
        *_inbuf = inbuf;
        inbuf->size = 0;
        inbuf->bytes = inbuf->_buf;
        inbuf->capacity = min_guarantee;
        inbuf->_prototype = prototype;
        inbuf->_fd = -1;
    } else {
        if (min_guarantee <= inbuf->capacity - inbuf->size - (inbuf->bytes - inbuf->_buf)) {
            /* ok */
        } else if ((inbuf->size + min_guarantee) * 2 <= inbuf->capacity) {
            /* the capacity should be less than or equal to 2 times of: size + guarantee */
            memmove(inbuf->_buf, inbuf->bytes, inbuf->size);
            inbuf->bytes = inbuf->_buf;
        } else {
            size_t new_capacity = inbuf->capacity;
            do {
                new_capacity *= 2;
            } while (new_capacity - inbuf->size < min_guarantee);
            if (inbuf->_prototype->mmap_settings != NULL && inbuf->_prototype->mmap_settings->threshold <= new_capacity) {
                size_t new_allocsize = topagesize(new_capacity);
                int fd;
                h2o_buffer_t *newp;
                if (inbuf->_fd == -1) {
                    char *tmpfn = _alloca(strlen(inbuf->_prototype->mmap_settings->fn_template) + 1);
                    strcpy_s(tmpfn,sizeof(inbuf->_prototype->mmap_settings->fn_template) ,inbuf->_prototype->mmap_settings->fn_template);
                    //defined in #include <stdlib.h> : mkstemp()
					
					/*
					More about: mkstemp() 
					The mkstemp() function generates a unique temporary filename from
					template, creates and opens the file, and returns an open file
					descriptor for the file.

					The last six characters of template must be "XXXXXX" and these are
					replaced with a string that makes the filename unique.  Since it will
					be modified, template must not be a string constant, but should be
					declared as a character array.

					The file is created with permissions 0600, that is, read plus write
					for owner only.  The returned file descriptor provides both read and
					write access to the file.  The file is opened with the open(2) O_EXCL
					flag, guaranteeing that the caller is the process that creates the
					file.
					*/

					//_mktemp_s of windows returns a file name only doesn't opens it. So if I am to use that function I have to take 
					//care of opening it with above permissions.
					//A detailed example of doing this : https://msdn.microsoft.com/en-us/library/t8ex5e91.aspx

					if ((fd = mkstemp(tmpfn)) == -1) {
                        fprintf(stderr, "failed to create temporary file:%s:%s\n", tmpfn, strerror(errno));
                        goto MapError;
                    }
                    _unlink(tmpfn);
                } else {
                    fd = inbuf->_fd;
                }
                //we don't have ftruncate in windows, but _chsize, the difference revolves around the size (2nd) argument only. Both
				//Return 0 on successful return.
#ifdef _WIN32
				if (_chsize(fd, new_allocsize) != 0) {
#else
				if (ftruncate(fd, new_allocsize) != 0) {
#endif //WIN32
					perror("failed to resize temporary file");
                    goto MapError;
                }
                if ((newp = mmap(NULL, new_allocsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
                    perror("mmap failed");
                    goto MapError;
                }
                if (inbuf->_fd == -1) {
                    /* copy data (moving from malloc to mmap) */
                    newp->size = inbuf->size;
                    newp->bytes = newp->_buf;
                    newp->capacity = new_capacity;
                    newp->_prototype = inbuf->_prototype;
                    newp->_fd = fd;
                    memcpy(newp->_buf, inbuf->bytes, inbuf->size);
                    h2o_buffer__do_free(inbuf);
                    *_inbuf = inbuf = newp;
                } else {
                    /* munmap */
                    size_t offset = inbuf->bytes - inbuf->_buf;
                    munmap(inbuf, topagesize(inbuf->capacity));
                    *_inbuf = inbuf = newp;
                    inbuf->capacity = new_capacity;
                    inbuf->bytes = newp->_buf + offset;
                }
            } else {
                h2o_buffer_t *newp = h2o_mem_alloc(offsetof(h2o_buffer_t, _buf) + new_capacity);
                newp->size = inbuf->size;
                newp->bytes = newp->_buf;
                newp->capacity = new_capacity;
                newp->_prototype = inbuf->_prototype;
                newp->_fd = -1;
                memcpy(newp->_buf, inbuf->bytes, inbuf->size);
                h2o_buffer__do_free(inbuf);
                *_inbuf = inbuf = newp;
            }
        }
    }

    ret.base = inbuf->bytes + inbuf->size;
    ret.len = inbuf->_buf + inbuf->capacity - ret.base;

    return ret;

MapError:
    ret.base = NULL;
    ret.len = 0;
    return ret;
}

void h2o_buffer_consume(h2o_buffer_t **_inbuf, size_t delta)
{
    h2o_buffer_t *inbuf = *_inbuf;

    if (delta != 0) {
        assert(inbuf->bytes != NULL);
        if (inbuf->size == delta) {
            *_inbuf = &inbuf->_prototype->_initial_buf;
            h2o_buffer__do_free(inbuf);
        } else {
            inbuf->size -= delta;
            inbuf->bytes += delta;
        }
    }
}

//This function was missing, copied it from current repo.
void h2o_buffer__dispose_linked(void *p) 
{ 
	h2o_buffer_t **buf = p; 
	h2o_buffer_dispose(buf); 
}


void h2o_vector__expand(h2o_mem_pool_t *pool, h2o_vector_t *vector, size_t element_size, size_t new_capacity)
{
    void *new_entries;
    assert(vector->capacity < new_capacity);
    if (vector->capacity == 0)
        vector->capacity = 4;
    while (vector->capacity < new_capacity)
        vector->capacity *= 2;
    if (pool != NULL) {
        new_entries = h2o_mem_alloc_pool(pool, element_size * vector->capacity);
        memcpy(new_entries, vector->entries, element_size * vector->size);
    } else {
        new_entries = h2o_mem_realloc(vector->entries, element_size * vector->capacity);
    }
    vector->entries = new_entries;
}

void h2o_dump_memory(FILE *fp, const char *buf, size_t len)
{
    size_t i, j;

    for (i = 0; i < len; i += 16) {
        fprintf(fp, "%08zx", i);
        for (j = 0; j != 16; ++j) {
            if (i + j < len)
                fprintf(fp, " %02x", (int)(unsigned char)buf[i + j]);
            else
                fprintf(fp, "   ");
        }
        fprintf(fp, " ");
        for (j = 0; j != 16 && i + j < len; ++j) {
            int ch = buf[i + j];
            fputc(' ' <= ch && ch < 0x7f ? ch : '.', fp);
        }
        fprintf(fp, "\n");
    }
}

void h2o_append_to_null_terminated_list(void ***list, void *element)
{
    size_t cnt;

    for (cnt = 0; (*list)[cnt] != NULL; ++cnt)
        ;
    *list = h2o_mem_realloc(*list, (cnt + 2) * sizeof(void *));
    (*list)[cnt++] = element;
    (*list)[cnt] = NULL;
}
