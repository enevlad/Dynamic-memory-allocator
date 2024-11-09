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

struct block_meta *give_me_space(struct block_meta *last, size_t size)
{
	struct block_meta *old_block, *new_block;

	old_block = sbrk(0);
	new_block = sbrk(size + sizeof(struct block_meta));
	DIE(new_block == (void *) -1, "sbrk failed");
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
		DIE(head == (void *) -1, "sbrk failed");
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
		if (block && block->status == STATUS_FREE) {
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
			} else if (size > block->size) {
				void *request = sbrk(size - block->size);

				block->size = size;
			}
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
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
