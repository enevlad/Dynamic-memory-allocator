// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8

#define ALIGN_SIZE(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

#define HEAP_SIZE (128 * 1024)

struct block_meta *head;
struct block_meta *last;

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
		DIE(head == MAP_FAILED, "sbrk failed");
		head->size = HEAP_SIZE - sizeof(struct block_meta);
		head->status = STATUS_ALLOC;
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
	struct block_meta *block = get_addr_block(ptr);

	if (block && block->status == STATUS_MAPPED) {
		int eval = munmap(block, block->size + sizeof(struct block_meta));

		DIE(eval == -1, "munmap failed");
	} else if (block && block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		//coalesce
		if (block->prev && block->prev->status == STATUS_FREE)
			block = coalesce_blocks(block->prev);
		if (block->next)
			block = coalesce_blocks(block);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if (nmemb == 0 || size == 0)
		return NULL;
	size_t total_size = nmemb * size;
	size_t page_size = getpagesize();
	void *ptr;

	total_size = ALIGN_SIZE(total_size);

	if (total_size + sizeof(struct block_meta) < page_size) {
		ptr = os_malloc(total_size);
		if (ptr)
			memset(ptr, 0, total_size);
	} else {
		struct block_meta *block = mmap(NULL, total_size + sizeof(struct block_meta),
										PROT_WRITE | PROT_READ,
										MAP_PRIVATE | 0x20, -1, 0);

		DIE(block == MAP_FAILED, "mmap failed");
		block->status = STATUS_MAPPED;
		block->size = total_size;
		block->prev = NULL;
		block->next = NULL;
		ptr = (void *)(block + 1);
		memset(ptr, 0, total_size);
	}
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = get_addr_block(ptr);
	size_t copy_of_size = block->size;

	if (block == NULL || block->status == STATUS_FREE)
		return NULL;
	size = ALIGN_SIZE(size);

	// truncate the block if size given is smaller than the block size
	if (block->status == STATUS_ALLOC && size < block->size) {
		split_block(block, size);
		return ptr;
	}
	// try to extend if it is the last block in the list
	if (last == block && last->size < size) {
		void *request = sbrk(size - last->size);

		DIE(request == MAP_FAILED, "sbrk failed");
		last->size = size;
		return (void *)(last + 1);
	}

	// coalesce block with free blocks after it
	// if it is not space leave it as it is
	size_t coalesce_size = block->size;

	while (block->next && block->next->status == STATUS_FREE) {
		coalesce_size += block->next->size + sizeof(struct block_meta);
		block = coalesce_blocks(block);
		if (block->size >= size + sizeof(struct block_meta) + ALIGNMENT) {
			split_block(block, size);
			return ptr;
		} else if (coalesce_size > size) {
			return ptr;
		}
	}
	if (coalesce_size == size)
		return ptr;

	// if all else fails call os_malloc and copy to the new pointer
	void *new = os_malloc(size);

	if (new) {
		if (size < copy_of_size)
			copy_of_size = size;
		memcpy(new, ptr, copy_of_size);
		os_free(ptr);
	}
	return new;
}
