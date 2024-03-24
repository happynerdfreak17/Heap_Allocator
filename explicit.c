#include "./allocator.h"
#include "./debug_break.h"
#include <string.h>
#include <stdio.h>

#define BYTES_PER_LINE 32
#define MIN_TOTALSIZE 24

// doubly linked list containing the free blocks in the heap
typedef struct freeList {
    size_t header;
    struct freeList *next;
    struct freeList *prev;
} freeList;

static void *segment_start;
static size_t segment_size;
static size_t nused;
freeList *freeListStart = NULL;
void coalesce(freeList *curBlock, void *ptr);

/* Function: myinit
 * -----------------
 * This function initializes our global variables given the heap_size and heap_start parameters. It also initializes the list of free blocks in the heap. 
 */ 
bool myinit(void *heap_start, size_t heap_size) {
    segment_start = heap_start;
    segment_size = heap_size;
    nused = ALIGNMENT;  // including the length of the first header

    freeListStart = (freeList *)(segment_start);
    freeListStart->header = heap_size - ALIGNMENT;  // last bit of 0 indicates that the next block is free
    freeListStart->next = NULL;
    freeListStart->prev = NULL;

    if (segment_size == 0) {
        return (false);
    }
    return true;
}

/* Function: roundup
 * -----------------
 * This function rounds up the given number to the given multiple, which has to be a power of 2, and returns the result.
 */ 
size_t roundup(size_t sz, size_t mult) {
    return (sz + mult - 1) & ~(mult - 1);
}

/* Function: mymalloc
 * -----------------
 * This function returns a pointer to the first available free block in the list of free blocks with enough space for the allocation request. The size is given by the requested_size parameter. It iterates through the list of free blocks and if a free block can fit the indicated size, we update headers and freeList. If no compatible free block can be found, we return NULL
 */ 
void *mymalloc(size_t requested_size) {
    if (requested_size == 0) {
        return (NULL);
    }
    size_t totalSize = roundup(requested_size, ALIGNMENT) + ALIGNMENT;
    if (totalSize < MIN_TOTALSIZE) {
        totalSize = MIN_TOTALSIZE;
    }
    freeList *curBlock = freeListStart;  // current header we are on in the list
    while (curBlock != NULL) {
        // checking if the prev/next pointers can be stored            
        if (curBlock->header >= MIN_TOTALSIZE && curBlock->header >= totalSize + 2 * ALIGNMENT) {
            freeList *newBlock = (freeList *)((size_t *)curBlock + totalSize/ALIGNMENT);
            newBlock->header = (unsigned int) (curBlock->header - totalSize);
            newBlock->prev = curBlock->prev;
            newBlock->next = curBlock->next;
            if (curBlock->next != NULL) {  // changing headers of blocks 
                ((freeList *) (curBlock->next))->prev = newBlock;
            }
            if (curBlock->prev != NULL) {
                ((freeList *) (curBlock->prev))->next = newBlock;
            }
            if (((char *)curBlock + totalSize - (char *)segment_start) > nused) {
                // checking if we should increment nused
                nused += totalSize;
            }
            curBlock->header = totalSize | 1;
            curBlock->header -= ALIGNMENT;

            if (curBlock-> prev == NULL) {  // resetting head of the freeList
                freeListStart = newBlock;
            }

            return ((size_t *) curBlock + 1);
        }
        curBlock = (freeList *)(curBlock->next);  // iterating to the next block in the list 
    }
    return (NULL);
}

/* Function: myfree
 * -----------------
 * This function marks the block pointed to by the given pointer as free by setting the last bit of the header to 0, which we defined to indicate a free block. This function also calls the coalesce function to combine this newly freed block with blocks to the right of this block on the heap which are also free. We also update headers and the free block list accordingly.
 */ 
void myfree(void *ptr) {
    freeList *curBlock = (freeList *)((char *)ptr - ALIGNMENT);  // current block of the given pointer
    if ((size_t *) ptr) {
        bool is_used = (curBlock->header & 1);
        curBlock->header &= (~0UL << 1);  // mark as free
        if (is_used) {
            curBlock->prev = NULL;
            curBlock->next = freeListStart;  // set freeListStart as second element of the list now
            freeListStart->prev = curBlock; 
            freeListStart = curBlock;  // add this free block to the front of the list
        }
        
        // coalescing to the right:
        coalesce(curBlock, ptr);
    }
}

/* Function: coalesce
 * -----------------
 * This function is given parameters of a block that is free. The function checks if blocks to the right of the given block are also free. If so, the function combines the free blocks and updates headers and the free block list accordingly.
 */ 
void coalesce(freeList *curBlock, void *ptr) {
    // this loop checks if we can coalesce blocks to the right
    while ((char *)curBlock - (char *)segment_start + curBlock->header + ALIGNMENT < segment_size) { 
        freeList *nextBlock = (freeList *)((char *)ptr + curBlock->header);
        if ((nextBlock->header & 1) == 0) {  // if we can coalesce
            curBlock->header += nextBlock->header + ALIGNMENT;  // increasing indicated freespace
            if (nextBlock->next != NULL) {
                (nextBlock->next)->prev = nextBlock->prev;  // delete right block from the linked list
            }
            if (nextBlock->prev != NULL) {
                (nextBlock->prev)->next = nextBlock->next;
            }
        } else {  // once we can't coalesce, we break out of the loop
            break;
        }    
    }
}

/* Function: myrealloc
 * -----------------
 * This function returns a pointer to the first available free block with enough space for the reallocation request. It first checks if reallocation in place is possible. It is able to do this by freeing the current block and adding that block to the front of the list of free blocks. Then, we coalesce to combine this newly freed block with blocks to the right.
 */ 
void *myrealloc(void *old_ptr, size_t new_size) {
    if (old_ptr == NULL) {
        size_t *mallocPointer = mymalloc(new_size);
        return (mallocPointer);
    }
    if (new_size == 0) {
        return (NULL);
    }

    size_t totalSize = roundup(new_size, ALIGNMENT) + ALIGNMENT;
    if (totalSize < MIN_TOTALSIZE) {
        totalSize = MIN_TOTALSIZE;
    }

    // First, check if we can realloc in place:
    freeList *curBlock = (freeList *)((char *)old_ptr - ALIGNMENT);
    curBlock->header &= (~0UL << 1);  // marking as free
    size_t temp = (size_t) *((size_t *)old_ptr);  // value to copy over after freeing
    size_t copyLen = curBlock->header;
    curBlock->next = freeListStart;
    curBlock->prev = NULL;
    freeListStart->prev = curBlock;
    freeListStart = curBlock;
    
    coalesce(curBlock, old_ptr);

    // Now that we have freed the  we use malloc:
    size_t *new_ptr = mymalloc(totalSize - ALIGNMENT);  // requesting rounded up size
    // freeList *newBlock = (freeList *)((char *)new_ptr - ALIGNMENT);
    if (totalSize - ALIGNMENT < copyLen) {
        copyLen = totalSize - ALIGNMENT;
    }
    if (new_ptr != old_ptr) {
        memcpy(new_ptr, old_ptr, copyLen);
        myfree(old_ptr);  // we know that we did not realloc in place
    }
    *((size_t *)new_ptr) = temp;
    *((size_t *)new_ptr + 1) = temp;
    return (new_ptr);
}

/* Function: validate_heap
 * -----------------
 * This function checks for errors in the heap data structure. It goes through the blocks in the heap and ensures that the blocks have nonzero size. If there is an error, the function returns false and returns true otherwise. It also checks if the heap is greater than the available space.
 */ 
bool validate_heap() {
    if (nused > segment_size) {
        printf("Heap is greater than available space!\n");
        breakpoint();
        return (false);
    }
    size_t *curPtr = (size_t *)segment_start;

    while (curPtr < (size_t *)segment_start + segment_size/ALIGNMENT) {
        size_t curSize = *curPtr;
        if (curSize == 0 || curSize == 1) {
            // checking if block size is 0
            printf("Blocksize is 0!\n");
            breakpoint();
            return(false);
        }
        curPtr += curSize/ALIGNMENT + 1;
    }

    return (true);
}

/* Function: dump_heap
 * -------------------
 * This function prints out the the block contents of the heap.  It is not
 * called anywhere, but is a useful helper function to call from gdb when
 * tracing through programs.  It prints out the total range of the heap, and
 * information about each block within it.
 */
void dump_heap() {
    printf("Heap segment starts at address %p, ends at %p. %lu bytes currently used.",
            segment_start, (char *)segment_start + segment_size, nused);
    for (int i = 0; i < nused; i++) {
        unsigned char *cur = (unsigned char *)segment_start + i;
        if (i % BYTES_PER_LINE == 0) {
            printf("\n%p: ", cur);
        }
        printf("%02x ", *cur);
    }
    printf("\n");

    freeList *curBlock = freeListStart;
    while (curBlock != NULL) {
        printf ("Free block headers: 0x%zx",curBlock->header);
        printf(" -- Free block Address: 0x%p\n", curBlock);
        curBlock = (freeList *)curBlock->next;
    }
}
