#ifndef VM_PAGE
#define VM_PAGE

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "kernel/hash.h"
#include "kernel/list.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/frame.h"

struct page{
  void* vaddr;
  void* paddr;

  struct hash_elem hash_elem;
};

void page_init(void);
void* page_get(enum palloc_flags flags);
void page_free(void* addr);

#endif // VM_PAGE
