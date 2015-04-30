#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"

#include <stdlib.h>
#include <stdio.h>

static bool load_swap(struct page* page);
static bool load_file(struct page* page);

/* helper routines */
static struct page* page_lookup(const void *address);
static void destroy_hentry(struct hash_elem* e, void *aux UNUSED);
static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void page_init(void){;}
struct page* page_get(void* vaddr){ return page_lookup(pg_round_down(vaddr)); }

/* initialize page table - per thread */
void page_construct(void){
  struct page_table* new = malloc(sizeof(struct page_table));

  hash_init(&new->table, page_hash, page_less, NULL);

  new->thread = thread_current();
  thread_current()->page_table = new;
}

/* free all allocated resources */
void page_destruct(void){
  hash_destroy(&(thread_current()->page_table->table), destroy_hentry);
  free(thread_current()->page_table);
}

/* loads page if it is not loaded already */
bool load_page(struct page* page){
  bool success = false;
  page->pinned = true;

  if (page->loaded)
    success = true;
  else
    switch (page->type){
      case PAGE_SWAP:
        success = load_swap(page);
        break;
      case PAGE_FILE:
        success = load_file(page);
        break;
    }

  return success;
}

/* load page from swap */
static bool load_swap(struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->swap_id != BITMAP_ERROR);
  ASSERT(page->type == PAGE_SWAP);

  page->paddr = frame_create(PAL_USER, page);
  swap_in(page);

  if (!install_page(page->vaddr, page->paddr, page->writable)){
    frame_free(page->paddr);
    return false;
  }

  page->loaded = true;

  return true;
}

/* allocates fream and loads page from file there */
static bool load_file(struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->type == PAGE_FILE);

  page->paddr       = frame_create(PAL_USER, page);

  page->pinned      = !intr_context();    // TODO: WHY?
  page->type        = PAGE_SWAP;
  page->swap_id     = BITMAP_ERROR;
  
  if (page->vaddr == NULL){
    free(page);
    return false;
  }

  /* install page */
  if (!install_page(page->vaddr, page->paddr, page->writable)){
    frame_free(page->paddr);
    free(page);
    return false;
  }

  /* reading from file to paddr, synchronizing with syscalls */
  lock_acquire(&opened_files_lock);
  if (file_read_at(page->file, page->paddr, page->read_bytes, page->ofs) != (int)page->read_bytes)
  {
    palloc_free_page(page->paddr);
    return false; 
  }
  lock_release(&opened_files_lock);

  memset(page->paddr + page->read_bytes, 0, page->zero_bytes);

  page->loaded      = true;
  return true;
}

/* adds new page that covers passed virtual address
 * called in: page_fault, setup_stack, correct_pointer */
bool grow_stack(void* vaddr){
  struct page* new_page = malloc(sizeof(struct page));
  
  /* check address validity */
  if ((PHYS_BASE - pg_round_down(vaddr)) > MAX_STACK)
    return false;

  /* check frame */
  new_page->vaddr       = pg_round_down(vaddr);   /* rounding down to nearest page */
  new_page->paddr       = frame_create(PAL_USER, new_page);

  new_page->writable    = true;
  new_page->loaded      = true;
  new_page->pinned      = !intr_context();
  new_page->type        = PAGE_SWAP;
  new_page->swap_id     = BITMAP_ERROR;
  new_page->thread      = thread_current();
  
  if (new_page->vaddr == NULL){
    free(new_page);
    return false;
  }

  /* install page */
  if (!install_page(new_page->vaddr, new_page->paddr, new_page->writable)){
    frame_free(new_page->paddr);
    free(new_page);
    return false;
  }
  
  return (hash_insert(&(thread_current()->page_table->table), &new_page->hash_elem) == NULL);
}

/* inserts page. not loads yet. */
bool page_insert_file(struct file* file, void* vaddr, size_t page_read_bytes, 
                      size_t page_zero_bytes, bool writable, off_t ofs)
{
  struct page* new_page = malloc(sizeof(struct page));
  
  /* check address validity */
  if ((PHYS_BASE - pg_round_down(vaddr)) > MAX_STACK)
    return false;

  /* check frame */
  new_page->vaddr       = pg_round_down(vaddr);   /* rounding down to nearest page */
  new_page->paddr       = NULL;

  new_page->writable    = writable;
  new_page->loaded      = false;
  new_page->pinned      = false;
  new_page->type        = PAGE_FILE;
  new_page->swap_id     = BITMAP_ERROR;
  new_page->thread      = thread_current();

  /* PAGE_FILE */
  new_page->file        = file;
  new_page->read_bytes  = page_read_bytes;
  new_page->zero_bytes  = page_zero_bytes;
  new_page->ofs         = ofs;
  
  return (hash_insert(&(thread_current()->page_table->table), &new_page->hash_elem) == NULL);
}

/*
 * helper routines
 * -----------------------------
 */

/* Returns a hash value for page p. */
static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED){
  const struct page* p = hash_entry(p_, struct page, hash_elem);
  return (unsigned)p->vaddr;
}

/* Returns true if page a precedes page b. */
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
  const struct page* a = hash_entry(a_, struct page, hash_elem);
  const struct page* b = hash_entry(b_, struct page, hash_elem);
  return a->vaddr < b->vaddr;
}

/* Returns the page containing the given virtual address,
 * or a null pointer if no such page exists. */
static struct page* page_lookup(const void *vaddress){
  struct page p;
  struct hash_elem *e;
  struct hash* page_table = &(thread_current()->page_table->table);

  p.vaddr = pg_round_down((void*)vaddress);
  e = hash_find(page_table, &p.hash_elem);
  return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* free page table - per thread */
static void destroy_hentry(struct hash_elem* e, void *aux UNUSED){
  struct page* dpage = hash_entry(e, struct page, hash_elem);

  if (dpage != NULL){
    frame_free(dpage->paddr);
    free(dpage);
  }
}
