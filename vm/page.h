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

  struct hash_elem hash_elem;
};

void page_init(void);
void* page_allocate(enum palloc_flags flags);
struct page* page_get(void* addr);
void page_free(void* addr);

struct hash* get_page_table(tid_t pid);
struct hash* create_page_table(tid_t pid);
struct hash* remove_page_table(tid_t pid);

#endif // VM_PAGE
