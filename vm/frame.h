#ifndef VM_FRAME
#define VM_FRAME

#include <stdlib.h>
#include <inttypes.h>
#include "kernel/hash.h"
#include "kernel/list.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/page.h"

/* frame descriptor */
struct frame{
  void* addr;                 /* Frame address */
  struct page* page;          /* Pointer to Page descriptor */
  struct hash_elem hash_elem; /* for frame_table */
};

void frame_init(void);
void* frame_create(enum palloc_flags flags, struct page* page);
void frame_free(void* addr);

#endif // VM_FRAME
