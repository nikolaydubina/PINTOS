#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"

#include <stdlib.h>
#include <stdio.h>

static bool load_swap(struct page* page);
static bool load_file(struct page* page);
static bool load_mmap(struct page* page);

/* helper routines */
static struct page* page_lookup(const void *address);
static void destroy_hentry(struct hash_elem* e, void *aux UNUSED);
static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void page_init(void){;}
struct page* page_get(void* vaddr){ return page_lookup(vaddr); }

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
      case PAGE_MMAP:
        success = load_mmap(page);
        break;
    }

  return success;
}

/* load page from swap */
static bool load_swap(struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->swap_id != BITMAP_ERROR);
  ASSERT(page->type == PAGE_SWAP);

  page->pinned = true;
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

  page->pinned      = true;
  page->paddr       = frame_create(PAL_USER, page);
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
  if (file_read_at(page->file, page->paddr, page->read_bytes, page->ofs) != (int)page->read_bytes)
  {
    palloc_free_page(page->paddr);
    return false; 
  }

  memset(page->paddr + page->read_bytes, 0, page->zero_bytes);

  page->loaded      = true;
  return true;
}

/* handling mmap case */
static bool load_mmap(struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->type == PAGE_MMAP);
  ASSERT(page->vaddr != NULL);

  page->pinned      = true;
  page->paddr       = frame_create(PAL_USER, page);
  
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
  if (file_read_at(page->file, page->paddr, page->read_bytes, page->ofs) != (int)page->read_bytes)
  {
    palloc_free_page(page->paddr);
    return false; 
  }

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

  /* PAGE_MMAP */
  new_page->file_isok   = true;
  
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

  /* PAGE_MMAP */
  new_page->file_isok   = true;
  
  return (hash_insert(&(thread_current()->page_table->table), &new_page->hash_elem) == NULL);
}

bool page_mmap(int mmap_id, struct file* file, void* vaddr){
  off_t file_size = file_length(file);
  off_t ofs = 0;
  bool writable = true;
 
  void* curr_addr = pg_round_down(vaddr);
  bool success = true;
  for(curr_addr = pg_round_down(vaddr); 
      (curr_addr < pg_round_down(vaddr) + file_size) && success; 
      curr_addr += PGSIZE)
  {
    size_t size = ofs + PGSIZE < file_size ? PGSIZE : file_size - ofs;
    size_t page_read_bytes = size;
    size_t page_zero_bytes = PGSIZE - size;
    struct page* new_page = malloc(sizeof(struct page));

    /* check frame */
    new_page->vaddr       = pg_round_down(curr_addr);   /* rounding down to nearest page */
    new_page->paddr       = NULL;

    new_page->writable    = writable;
    new_page->loaded      = false;
    new_page->pinned      = false;
    new_page->type        = PAGE_MMAP;
    new_page->swap_id     = BITMAP_ERROR;
    new_page->thread      = thread_current();

    /* PAGE_FILE */
    new_page->file        = file;
    new_page->read_bytes  = page_read_bytes;
    new_page->zero_bytes  = page_zero_bytes;
    new_page->ofs         = ofs;

    /* PAGE_MMAP */
    new_page->mmap_id     = mmap_id;
    new_page->file_isok   = true;
    
    success &= hash_insert(&(thread_current()->page_table->table), &new_page->hash_elem) == NULL;
    
    /* NOT lazy loading */
    success &= load_mmap(new_page);

    ofs += size;
  }
  return success;
}

void uninstall_page(struct page* page){
  pagedir_clear_page(thread_current()->pagedir, page->vaddr);
}

/* removing page from page_table */
bool page_munmap(int mmap_id){
  bool success = true;
  bool found = false;
  struct hash* page_table = &(thread_current()->page_table->table);
  struct hash_iterator e;

  hash_first(&e, page_table);
  while(hash_next(&e)){
    struct page* curr = hash_entry(hash_cur(&e), struct page, hash_elem);
    
    if (curr->mmap_id == mmap_id){
      if (curr->paddr != NULL && curr->file != NULL && curr->file_isok &&
          pagedir_is_dirty(thread_current()->pagedir, curr->vaddr))
        success &= file_write_at(curr->file, curr->paddr, PGSIZE, curr->ofs);
      success &= hash_delete(page_table, &curr->hash_elem) != NULL;
     
      uninstall_page(curr);
      frame_free(curr->frame);
      found = true;
      hash_first(&e, page_table);
    }
  }

  success &= found;
  return success;
}

/* updates file availability of all pages of selected mmap */
bool page_update_mmap_file(int mmap_id, bool writable){
  struct hash* page_table = &(thread_current()->page_table->table);
  struct hash_iterator e;

  hash_first(&e, page_table);
  while(hash_next(&e)){
    struct page* curr = hash_entry(hash_cur(&e), struct page, hash_elem);
    
    if (curr->type == PAGE_MMAP && curr->mmap_id == mmap_id)
      curr->file_isok = writable;
  }

  return true;
}

void page_exit_mmap(){
  struct hash* page_table = &(thread_current()->page_table->table);
  struct hash_iterator e;

  hash_first(&e, page_table);
  while(hash_next(&e)){
    struct page* curr = hash_entry(hash_cur(&e), struct page, hash_elem);
    
    if (curr->type == PAGE_MMAP){
      if (curr->paddr != NULL && curr->file != NULL && curr->file_isok)
        file_write_at(curr->file, curr->paddr, PGSIZE, curr->ofs);
      hash_delete(page_table, &curr->hash_elem) != NULL;
     
      uninstall_page(curr);
      frame_free(curr->frame);
      hash_first(&e, page_table);
    }
  }
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
