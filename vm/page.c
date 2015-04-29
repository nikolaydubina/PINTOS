#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

#include <stdlib.h>
#include <stdio.h>

static bool load_swap(struct page* page);

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
    }

  if (success)
    page->loaded = true;

  return success;
}

static bool load_swap(struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->swap_id != BITMAP_ERROR);

  page->paddr = frame_create(PAL_USER, page);

  if (!install_page(page->vaddr, page->paddr, page->writable)){
    frame_free(page->paddr);
    return false;
  }

  swap_in(page);
  page->loaded = true;
  return true;
}

/* adds new page that covers passed virtual address
 * called in: page_fault, setup_stack, correct_pointer */
bool grow_stack(void* vaddr){
  //printf("DEBUG: grow_stack: vaddr=%p\n", vaddr);
  struct page* new_page = malloc(sizeof(struct page));
  
  //printf("DEBUG: grow_stack: before install\n");
  /* check address validity */
  if ((PHYS_BASE - pg_round_down(vaddr)) > MAX_STACK)
    return false;

  /* check frame */
  new_page->vaddr = pg_round_down(vaddr);   /* rounding down to nearest page */
  new_page->writable = true;
  new_page->loaded = true;
  new_page->pinned = !intr_context();
  new_page->type = PAGE_SWAP;
  new_page->swap_id = BITMAP_ERROR;
  new_page->thread = thread_current();

  new_page->paddr = frame_create(PAL_USER, new_page);
  
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

/* adds new page that covers passed virtual address
 * called in: page_fault, setup_stack, correct_pointer */
bool grow_stack_writable(void* vaddr, bool writable){
  struct page* new_page = malloc(sizeof(struct page));
  
  // TODO: adde check for address
  
  /* check frame */
  new_page->vaddr = pg_round_down(vaddr);   /* rounding down to nearest page */
  new_page->writable = writable;
  new_page->loaded = true;
  new_page->pinned = false;
  new_page->type = PAGE_SWAP;
  new_page->swap_id = BITMAP_ERROR;
  new_page->thread = thread_current();

  new_page->paddr = frame_create(PAL_USER, new_page);
  //new_page->paddr = NULL;
  
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

/* called in process -> load -> load_segment */
bool page_insert(void* vaddr, void* paddr, bool writable){
  if (!is_user_vaddr(vaddr) || !is_kernel_vaddr(paddr))
    return false;

  struct page* new_page = malloc(sizeof(struct page));

  /* check frame */
  new_page->vaddr = pg_round_down(vaddr);   /* rounding down to nearest page */
  new_page->paddr = paddr;                  /* FIXME raw because of ad-hoc load_segment */
  new_page->writable = writable;
  new_page->loaded = true;
  new_page->pinned = !intr_context();
  new_page->type = PAGE_SWAP;
  new_page->swap_id = BITMAP_ERROR;
  new_page->thread = thread_current();

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

  p.vaddr = (void*)vaddress;
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
