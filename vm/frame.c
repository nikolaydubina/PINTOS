#include "vm/frame.h"

/* global variables */
static struct hash frame_table;
static struct lock frame_table_lock;                /* modify lock */
static struct semaphore frame_table_evict;          /* for better eviction */

static void* frame_evict(enum palloc_flags flags);

/* helper functions */
static void frame_insert(void* addr, struct page* page);
static struct frame* frame_lookup(const void *address);
static unsigned frame_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* initializes internal structures */
void frame_init(){
  lock_init(&frame_table_lock);
  hash_init(&frame_table, frame_hash, frame_less, NULL);

  sema_init(&frame_table_evict, 0);
}

/* create new frame slot */
void* frame_create(enum palloc_flags flags, struct page* page){
  if ((flags & PAL_USER) == 0)
    return NULL;

  lock_acquire(&frame_table_lock);
  sema_up(&frame_table_evict);
  void* addr = palloc_get_page(flags);

  /* frame eviction */
  while (addr == NULL){
    lock_release(&frame_table_lock);
    addr = frame_evict(flags);
    lock_acquire(&frame_table_lock);
  }

  frame_insert(addr, page);
  lock_release(&frame_table_lock);

  return addr;
}

/* free frame at addr */
void frame_free(void* addr){
  struct frame* f;

  lock_acquire(&frame_table_lock);
  
  f = frame_lookup(addr);
  if (f != NULL){
    hash_delete(&frame_table, &f->hash_elem);
    free(f);
  }

  lock_release(&frame_table_lock);
}

static void* frame_evict(enum palloc_flags flags){
  struct frame* evict_frame = NULL;
  struct page* evict_page = NULL;
  struct thread* evict_thread = NULL;

  /* looking for frame to evict */
  bool found = false;
  struct hash_iterator e;
  while (!found){
    /* receiving singal of change in frame table */
    sema_down(&frame_table_evict);

    /* checking all frames */
    lock_acquire(&frame_table_lock);

    hash_first(&e, &frame_table);
    while (hash_next(&e) && !found){
      struct frame* curr_frame = hash_entry(hash_cur(&e), struct frame, hash_elem);
      struct page* curr_page = curr_frame->page;

      if (!curr_page->pinned){
        struct thread *pthread = curr_page->thread;

        /* second chanse algorithm. LRU approximation */
        if (pagedir_is_accessed(pthread->pagedir, curr_page->vaddr))
          pagedir_set_accessed(pthread->pagedir, curr_page->vaddr, false);
        else{
          found = true;
          evict_frame = curr_frame;
          evict_page = curr_page;
          evict_thread = pthread;
        }
      }
    }

    lock_release(&frame_table_lock);
  }

  /* evicting frame */
  lock_acquire(&frame_table_lock);

  /* move to swap if was accessed before */
  if (pagedir_is_dirty(evict_thread->pagedir, evict_page->vaddr) || 
      evict_page->type == PAGE_SWAP)
  {
    evict_page->type = PAGE_SWAP;
    evict_page->loaded = false;
    evict_page->pinned = false;
    evict_page->swap_id = swap_out(evict_page);
  }

  /* clear page, frame */
  evict_page->loaded = false;

  pagedir_clear_page(evict_thread->pagedir, evict_page->vaddr);   /* unmaps. to cause page fault next time */
  palloc_free_page(evict_frame->addr);                            /* free resources */

  hash_delete(&frame_table, &evict_frame->hash_elem);
  free(evict_frame);
  lock_release(&frame_table_lock);

  return palloc_get_page(flags);
}

/* 
 * helper functions
 * --------------------------
 */

/* insert new frame with addr and page-descriptor page */
static void frame_insert(void* addr, struct page* page){
  ASSERT(page != NULL);
  
  struct frame* new_frame = malloc(sizeof(struct frame));
  new_frame->addr = addr;
  new_frame->page = page;

  page->frame = new_frame;

  hash_insert(&frame_table, &new_frame->hash_elem);
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
