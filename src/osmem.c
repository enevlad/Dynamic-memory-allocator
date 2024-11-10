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

static int is_heap_init;

struct block_meta *give_me_space(struct block_meta *last, size_t size)
{
	struct block_meta *old_block, *new_block;

	old_block = sbrk(0);
	new_block = sbrk(size + sizeof(struct block_meta));
	DIE(new_block == MAP_FAILED, "sbrk failed");
	old_block->size = size;
	old_block->status = STATUS_ALLOC;
	old_block->next = NULL;
	old_block->prev = last;
	if (last)
		last->next = old_block;
	return old_block;
}

struct block_meta *find_block(size_t size)
{
	struct block_meta *block = head;

	while (block && block->next) {
		if (block->status == STATUS_FREE && block->size >= size)
			return block;
		block = block->next;
	}
	return block;
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

struct block_meta *get_addr_block(void *ptr)
{
	char *aux = ptr;

	aux = aux - sizeof(struct block_meta);
	ptr = aux;
	return ptr;
}

void split_block(struct block_meta *block, size_t size)
{
	if (block->size >= size + sizeof(struct block_meta) + ALIGNMENT) {
		struct block_meta *new = (struct block_meta *)((char *)block + sizeof(struct block_meta) + size);

		new->size = ALIGN_SIZE(block->size - size - sizeof(struct block_meta));
		new->status = STATUS_FREE;
		new->prev = block;
		if (block->next) {
			block->next->prev = new;
			new->next = block->next;
		} else {
			new->next = NULL;
		}
		block->size = size;
		block->next = new;
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

	if (head) {
		// find best fit
		block = find_block(size);
		// if block is free and at the end of the list extend it and allocate
		if (block && block->next == NULL && block->status == STATUS_FREE && size > block->size) {
			void *request = sbrk(size - block->size);

			DIE(request == MAP_FAILED, "sbrk failed");
			block->size = size;
			block->status == STATUS_ALLOC;
			return (void *)(block + 1);
		}
		if (block && block->status == STATUS_FREE) {
			//split block
			
			split_block(block, size);
			block->status = STATUS_ALLOC;
			return (void *)(block + 1);
		}
		block = give_me_space(block, size);
		if (!block)
			return NULL;
	} else {
		init_heap();
		block = head;
	}
	return (void *)(block + 1);
}

struct block_meta *coalesce_blocks(struct block_meta *block)
{
	if (block->next && block->next->status == STATUS_FREE) {
		block->size += block->next->size + sizeof(struct block_meta);
		block->next = block->next->next;
	}
	if (block->next)
		block->next->prev = block;
	return block;
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
	if (block == NULL || block->status == STATUS_FREE)
		return NULL;
	size = ALIGN_SIZE(size);
	
	if(block->status == STATUS_ALLOC && size < block->size) {
		split_block(block, size);
		return ptr;
	} else if (block->next && block->next->status == STATUS_FREE) {
		size_t coalesce_size = block->size;

		while (block->next && block->next->status == STATUS_FREE) {
			coalesce_size += block->next->size + sizeof(struct block_meta);
			block = coalesce_blocks(block);
			if (block->size >= size + sizeof(struct block_meta) + ALIGNMENT) {
				split_block(block, size);
				return ptr;
			}
		}

		if (block->next == NULL && size >= coalesce_size) {
			void *request = sbrk(size - block->size);
			
			DIE(request == MAP_FAILED, "sbrk failed");
			block->size = size;
			return ptr;
		}
	} else {
		void *new = os_malloc(size);
		if (new) {
			memcpy(new, ptr, size);
			os_free(ptr);
		}
		return new;
	}
	return ptr;
}
