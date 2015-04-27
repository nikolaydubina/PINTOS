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

#define MAX_STACK (8 * (1 << 20)) /* 4MB */

enum page_type{
  PAGE_FILE,
  PAGE_SWAP,
  PAGE_MMAP
};

struct page{
  void* vaddr;            /* page,  user,   address */
  void* paddr;            /* frame, kernel, address */

  bool writable;          /* user allowed to write */
  bool loaded;            /* ready for read/write */
  bool pinned;            /* must not be evicted */

  size_t swap_id;         /* id of page in swap disk */
  
  struct thread* thread;  /* for frame viction */ 

  enum page_type type;

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
bool page_insert(void* vaddr, void* paddr, bool writable);

bool load_page(struct page* page);
bool grow_stack(void* vaddr);

#endif // VM_PAGE
