#include "./allocator.h"
#include "./debug_break.h"
#include <string.h>
#include <stdio.h>

#define BYTES_PER_LINE 32

static void *segment_start;
static size_t segment_size;
static size_t nused;

/*Function: myinit
 * -----------------
 * This funcion initializes our global variables given the heap_size and heap_start parameters.
 */
bool myinit(void *heap_start, size_t heap_size) {
    segment_start = heap_start;
    segment_size = heap_size;
    nused = ALIGNMENT;  // length of first header
    // We let the last bit of a header being 0 indicate that the block is free
    // We let the last bit of a header being 1 indicate that the block is not free
    *((size_t *) segment_start) = (size_t) segment_size - ALIGNMENT; 
    if (segment_size == 0) { 
        return false;
    }
    return true;
}

/* Function: roundup
 * ------------------
 * This function rounds up the given number to the given multiple, which has to be a power of 2, and returns the result.
 */
size_t roundup(size_t sz, size_t mult) {
    return (sz + mult - 1) & ~(mult - 1);
}

/* Function: mymalloc
 * ------------------
 * This function returns a pointer to the first available free block with enough space for the allocation request. This size is indicated by the parameter requested_size. If no such free block can be found, this function returns NULL.
 */
void *mymalloc(size_t requested_size) {
    if (requested_size == 0) {
        return (NULL);
    }
    size_t curInd = 0;
    // totalSize represents the size of a block, the length of the payload plus the length of the header
    size_t totalSize = roundup(requested_size, ALIGNMENT) + ALIGNMENT;
    while (curInd < segment_size) {
        size_t *header = (size_t *) segment_start + curInd/ALIGNMENT;
        if ((*header & 1) == 0 && totalSize < *header) {  // if the memory can be stored at this address
            if (*header - totalSize + ALIGNMENT > 0) {  // if there is remaining space in the block, make another header
                *(header + totalSize/ALIGNMENT) = (unsigned int) (*header - totalSize);
            }
            if (curInd + totalSize > nused) {
                nused += totalSize;
            }
            *header = totalSize | 1;  // mark as used
            *header -= ALIGNMENT;
            return ((size_t *)segment_start + curInd/ALIGNMENT + 1);
        }
        curInd += (*header + ALIGNMENT) & (~0UL << 1);
    }
    return (NULL);
}

/* Function: myfree
 * ------------------
 * This function marks the block pointed to by the given pointer as free. It does this by setting the last bit of the header to 0, which we defined to indicate a free block.
 */
void myfree(void *ptr) {
    if ((size_t *) ptr) {
        *((size_t *) ((char *) ptr - ALIGNMENT)) &= (~0UL << 1);  // marking space after the header as free
    }
}

/* Function: myrealloc
 * ------------------
 * This function returns a pointer to the first available free block with enough space for the reallocation request. It does this by calling mymalloc to find a block with enough space to fit the new_size payload size. Then, it copies the existing contents of the old block to the new one. Finally, it calls myfree on the old pointer to mark the old block as free if the new block pointer is different from the old block pointer.
 */
void *myrealloc(void *old_ptr, size_t new_size) {
    if (old_ptr == NULL) { 
        size_t *mallocPointer = mymalloc(new_size);
        return (mallocPointer);
    }
    if (new_size == 0) {
        return (NULL);
    }
    size_t *oldHeader = (size_t *) old_ptr - 1;
    size_t roundedSize = roundup(new_size, ALIGNMENT); 
    // call mymalloc to find a block with enough space for the payload
    size_t *new_ptr = mymalloc(roundedSize);
    *((size_t *) old_ptr - 1) = *oldHeader - 1;
    size_t copyLen = *oldHeader;
    if (roundedSize < copyLen) {
        copyLen = roundedSize;  // copy length is minimum of existing contents and new_size
    }
    memcpy(new_ptr, old_ptr, copyLen);
    // free the old block if the new block pointer is different from the old block pointer.
    if (new_ptr != old_ptr) {
        myfree(old_ptr);
    }
    return (new_ptr);
}

/* Function: validate_heap
 * ------------------
 * This function checks for errors in the heap data structure. It goes through the blocks in the heap and ensures that the blocks have valid size. If there is an error, the fucntion returns false and returns true otherwise. It also checks if the heap is greater than the available space.
 */
bool validate_heap() {
    if (nused > segment_size) {
        printf("Heap is greater than available space!\n");
        breakpoint();
        return (false);
    }
    size_t *curPtr = (size_t *)segment_start;

    // make sure blocks in the heap are in proper format
    while (curPtr < (size_t *)segment_start + segment_size/ALIGNMENT) {
        size_t curSize = *curPtr;
        if (curSize == 0 || curSize == 1) {
            // checking if block size is 0
            printf("Blocksize is 0!\n");
            breakpoint();
            return (false);
        }
        if (!(curSize % ALIGNMENT == 0 || curSize % ALIGNMENT == 1) || curSize > segment_size) {
            // checking for invalid blocksize
            printf("Invalid blocksize!\n");
            breakpoint();
            return (false);
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

    size_t *curPtr = (size_t *)segment_start;
    while (curPtr < (size_t *)segment_start + segment_size/ALIGNMENT) {
        size_t curSize = *curPtr;
        printf("Block headers: 0x%zx", *(curPtr));
        printf(" -- Block address: 0x%p\n", curPtr);
        curPtr += curSize/ALIGNMENT + 1;
    }
}

