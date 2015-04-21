#include "vm/page.h"

/* helper routines */
static struct page* page_lookup(const void *address);
static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void page_init(void){
;
}

/* initialize page table - per thread */
void page_construct(void){
  struct page_table* new = malloc(sizeof(struct page_table));

  hash_init(&new->table, page_hash, page_less, NULL);

  new->thread = thread_current();
  thread_current()->page_table = new;
}

/* free page table - per thread */
void destroy_hentry(struct page* dpage){
  if (dpage != NULL){
    frame_free(dpage->vaddr);
  }
}

void page_desctruct(void){
  hash_destroy(&(thread_current()->page_table->table), destroy_hentry);
  free(thread_current()->page_table);
}

/* allocate new entry */
void* page_allocate(enum palloc_flags flags){
  struct page* new_page = malloc(sizeof(struct page));
  new_page->vaddr = frame_create(flags, new_page); // flags == PAL_USER
  
  hash_insert(&(thread_current()->page_table->table), &new_page->hash_elem);

  return new_page->vaddr;
}

/* get pageentry */
struct page* page_get(void* vaddr){
  struct page* ret = page_lookup(vaddr);
  return ret;
}

/* free frame from page-table */
void page_free(void* vaddr){
  struct page* curr_page = page_lookup(vaddr);
  if (curr_page != NULL){
    frame_free(curr_page->vaddr);
    hash_delete(&(thread_current()->page_table->table), &curr_page->hash_elem);
  }
}

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

  p.vaddr = vaddress;
  e = hash_find(page_table, &p.hash_elem);
  return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

void grow_stack(void* vaddr){
  struct page* new_page = malloc(sizeof(struct page));
  
  /* TODO */
  /* som flags */
  new_page->vaddr = frame_create(flags, new_page); // flags == PAL_USER
  /* check frame */

  /* install page */

  /* int contxt ?? */
  
  hash_insert(&(thread_current()->page_table->table), &new_page->hash_elem);
}
