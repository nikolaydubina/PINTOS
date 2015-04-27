#include "vm/frame.h"

/* frame descriptor */
static struct frame{
  void* addr;                 /* Frame address */
  struct page* page;          /* Pointer to Page descriptor */
  struct hash_elem hash_elem; /* for frame_table */
};

/* global variables */
static struct lock frame_table_lock;
static struct hash frame_table;

/* Returns a hash value for frame p. */
static unsigned frame_hash(const struct hash_elem *p_, void *aux UNUSED){
  const struct frame* p = hash_entry(p_, struct frame, hash_elem);
  return (unsigned)p->addr;
}

/* Returns true if frame a precedes frame b. */
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
  const struct frame* a = hash_entry(a_, struct frame, hash_elem);
  const struct frame* b = hash_entry(b_, struct frame, hash_elem);
  return a->addr < b->addr;
}

/* initializes internal structures */
void frame_init(){
  lock_init(&frame_table_lock);
  hash_init(&frame_table, frame_hash, frame_less, NULL);
}

/* Returns the frame containing the given virtual address,
 * or a null pointer if no such frame exists. */
static struct frame* frame_lookup(const void *address){
  struct frame p;
  struct hash_elem *e;

  p.addr = (void*)address;
  e = hash_find(&frame_table, &p.hash_elem);
  return e != NULL ? hash_entry(e, struct frame, hash_elem) : NULL;
}

/* create new frame slot */
void* frame_create(enum palloc_flags flags, struct page* page){

  if ((flags & PAL_USER) == 0)
    return NULL;

  lock_acquire(&frame_table_lock);
  void* addr = palloc_get_page(flags);

  if (addr != NULL)
    frame_insert(addr, page);
  else{
    /* frame eviction */
    while (!addr){
      addr = frame_evict(flags);
      lock_release(&frame_table_lock);
    }
    
    // DEBUG
    if (!addr)
      PANIC ("Frame was not evicted properly");

    frame_insert(addr, page);
  }
  lock_release(&frame_table_lock);

  return addr;
}

/* insert new frame with addr and page-descriptor page */
void frame_insert(void* addr, struct page* page){
  struct frame* new_frame = malloc(sizeof(struct frame));
  new_frame->addr = addr;
  new_frame->page = page;

  hash_insert(&frame_table, &new_frame->hash_elem);
}

/* free frame at addr */
void frame_free(void* addr){
  struct frame* f;

  lock_acquire(&frame_table_lock);
  
  f = frame_lookup(addr);
  if (f != NULL){
    hash_delete(&frame_table, &f->hash_elem);
    free(f);
    // FIXME: Why following causes fault?
    //palloc_free_page(addr);
  }

  lock_release(&frame_table_lock);
}

void* frame_evict(enum pallog_flags flags){
  // TODO: code it

  return NULL;
}
