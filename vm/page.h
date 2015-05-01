#ifndef VM_PAGE
#define VM_PAGE

#include <stdlib.h>
#include <inttypes.h>
#include "kernel/hash.h"
#include "kernel/list.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "kernel/bitmap.h"

#define MAX_STACK (8 * (1 << 20)) /* 8MB */

enum page_type{
  PAGE_SWAP,
  PAGE_FILE
};

struct page{
  enum page_type type;

  void* vaddr;            /* page,  user,   address */
  void* paddr;            /* frame, kernel, address */

  bool writable;          /* user allowed to write */
  bool loaded;            /* ready for read/write */
  bool pinned;            /* must not be evicted */

  struct frame* frame;    /* corresponding frame */
  struct thread* thread;  /* for frame viction */ 
  size_t swap_id;         /* id of page in swap disk */
 
  /* PAGE_FILE */
  struct file* file;
  size_t read_bytes;
  size_t zero_bytes;
  off_t ofs;

  struct hash_elem hash_elem;
};

struct page_table{
  struct thread* thread;
  struct hash table;
};

void page_init(void);

void page_construct(void);
void page_destruct(void);

struct page* page_get(void* addr);
bool page_insert_file(struct file* file, void* vaddr, 
                      size_t page_read_bytes, size_t page_zero_bytes,
                      bool writable, off_t ofs);

bool load_page(struct page* page);
bool grow_stack(void* vaddr);

#endif // VM_PAGE
