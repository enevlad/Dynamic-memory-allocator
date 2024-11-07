// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8

#define ALIGN_SIZE(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#define HEAP_SIZE (128 * 1024)

struct block_meta *head;

static int is_heap_init;

struct block_meta *find_block(size_t size)
{
	struct block_meta *current = head;
	struct block_meta *best = NULL;

	while (current) {
		if (current->status == STATUS_FREE && current->size >= size) {
			if (!best || current->size < best->size)
				best = current;
		}
		current = current->next;
	}
	return best;
}

void init_heap(void)
{
	if (!is_heap_init) {
		head = (struct block_meta *)sbrk(HEAP_SIZE);
		DIE(head == (void *) -1, "sbrk failed");
		head->size = HEAP_SIZE - sizeof(struct block_meta);
		head->status = STATUS_FREE;
		head->next = NULL;
		head->prev = NULL;
		is_heap_init = 1;
	}
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	struct block_meta *block;

	if (size == 0)
		return NULL;

	size = ALIGN_SIZE(size);

	if (is_heap_init == 0 && size < HEAP_SIZE)
		init_heap();

	if (size >= HEAP_SIZE) {
		block = mmap(NULL, size + sizeof(struct block_meta),
					 PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | 0x20, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed");
		block->size = size;
		block->status = STATUS_MAPPED;
		block->next = NULL;
		block->prev = NULL;

		return (void *)(block + 1);
	}

	// find best fit
	block = find_block(size);
	if (block) {
		//split block
		if (block->size >= size + sizeof(struct block_meta) + ALIGNMENT) {
			struct block_meta *new = (struct block_meta *)((char *)block + sizeof(struct block_meta) + size);

			new->size = block->size - size - sizeof(struct block_meta);
			new->status = STATUS_FREE;
			new->next = NULL;
			new->prev = block;

			if (block->next)
				block->next->prev = new;
			block->size = size;
			block->next = new;
		}
		block->status = STATUS_ALLOC;
		return (void *)(block + 1);
	}

	return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)(ptr - sizeof(struct block_meta));

	if (block->status == STATUS_MAPPED) {
		munmap(block, block->size + sizeof(struct block_meta));
	} else {
		block->status = STATUS_FREE;
		//coalesce
		if (block->next && block->next->status == STATUS_FREE) {
			block->size += block->next->size + sizeof(struct block_meta);
			block->next = block->next->next;
			if (block->next)
				block->next->prev = block;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
