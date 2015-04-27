#include "vm/frame.h"

/* global variables */
static struct lock frame_table_lock;
static struct hash frame_table;

void* frame_evict(enum palloc_flags flags);

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

void* frame_evict(enum palloc_flags flags){
  lock_acquire(&frame_table_lock);

  struct frame* evict_frame = NULL;
  struct page* evict_page = NULL;
  struct thread* evict_thread = NULL;

  /* busy waiting for frame to evict */
  struct hash_iterator e;
  hash_first(&e, &frame_table);
  while(evict_frame == NULL){
    struct frame* curr_frame = hash_entry(hash_cur(&e), struct frame, hash_elem);
    struct page* curr_page = curr_frame->page;

    if (!curr_frame->page->pinned){
        struct thread *pthread = curr_page->thread;

        if (pagedir_is_accessed(pthread->pagedir, curr_page->vaddr))
          pagedir_set_accessed(pthread->pagedir, curr_page->vaddr, false);
        else{
          evict_frame = curr_frame;
          evict_page = curr_page;
          evict_thread = pthread;
        }
    }

    if (!hash_next(&e))
      hash_first(&e, &frame_table);
  }

  if (pagedir_is_dirty(evict_thread->pagedir, evict_page->vaddr) || 
      evict_page->type == PAGE_SWAP)
  {
    // TODO: if MMAP
    /* move to swap */
    evict_page->type = PAGE_SWAP;
    evict_page->swap_id = swap_out(evict_frame->addr);
  }

  /* clear page, frame */
  evict_page->loaded = false;

  pagedir_clear_page(evict_thread->pagedir, evict_page->vaddr);
  palloc_free_page(evict_frame->addr);

  hash_delete(&frame_table, &evict_frame->hash_elem);
  free(evict_frame);

  return palloc_get_page(flags);
}
