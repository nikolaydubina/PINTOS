#include "vm/page.h"

static struct page_table_des{
  struct hash table;
  tid_t pid;

  struct list_elem elem;
};

/* global structs */
static struct lock page_table_list_lock;
static struct list page_table_list; 

/* pid -> page_table mapping */
struct hash* get_page_table(tid_t pid);
struct hash* create_page_table(tid_t pid);
struct hash* remove_page_table(tid_t pid);

/* helper routines */
static struct page* page_lookup(struct hash* page_table, const void *address);
static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* implementation */

void page_init(void){
  lock_init(&page_table_list_lock);
  list_init(&page_table_list);
}

void* page_allocate(enum palloc_flags flags){
  tid_t curr_pid = thread_current()->tid;

  struct hash* curr_table = get_page_table(curr_pid);

  if (curr_table == NULL)
    return NULL;
  
  struct page* new_page = malloc(sizeof(struct page));
  new_page->vaddr = frame_create(flags, new_page); // flags == PAL_USER
  
  hash_insert(curr_table, &new_page->hash_elem);

  return new_page->vaddr;
}

struct page* page_get(void* vaddr){
  tid_t curr_pid = thread_current()->tid;

  struct page* ret = NULL;
  struct hash* curr_table = get_page_table(curr_pid);
  if (curr_table != NULL)
    ret = page_lookup(curr_table, vaddr);
  return ret;
}

void page_free(void* vaddr){
  tid_t curr_pid = thread_current()->tid;

  struct hash* curr_table = get_page_table(curr_pid);
  if (curr_table != NULL){
    struct page* curr_page = page_lookup(curr_table, vaddr);
    if (curr_page != NULL)
      frame_free(curr_page->vaddr);
  }
}

/* list of pagetables routines */
struct hash* get_page_table(tid_t pid){
  lock_acquire(&page_table_list_lock);
  struct list_elem* e;
  struct hash* ret = NULL;
  for(e = list_begin(&page_table_list);
      e != list_end(&page_table_list) && ret == NULL;
      e = list_next(e))
  {
    struct page_table_des* curr = list_entry(e, struct page_table_des, elem);
    if (curr->pid == pid)
      ret = &curr->table;
  }
  lock_release(&page_table_list_lock);
  return ret;
}

struct hash* remove_page_table(tid_t pid){
  lock_acquire(&page_table_list_lock);
  struct list_elem* e;
  for(e = list_begin(&page_table_list);
      e != list_end(&page_table_list);
      e = list_next(e))
  {
    struct page_table_des* curr = list_entry(e, struct page_table_des, elem);
    if (curr->pid == pid){
      struct hash* removed = &curr->table;
      lock_release(&page_table_list_lock);

      /* freeing all entries
       * allowing other threads manipulate page_table asynchronously
       */
      struct hash_iterator i;
      hash_first (&i, removed);
      while (hash_next(&i)){
        struct page* f = hash_entry(hash_cur(&i), struct page, hash_elem);
        if (f != NULL){
          /* frame should be thread safe */
          frame_free(f->vaddr);
          free(f);
        }
      }
  
      lock_acquire(&page_table_list_lock);
      e = list_remove(e);
      lock_release(&page_table_list_lock);
      return removed;
    }
  }
  lock_release(&page_table_list_lock);
  return NULL;
}

struct hash* create_page_table(tid_t pid){
  lock_acquire(&page_table_list_lock);

  struct page_table_des* new = malloc(sizeof(struct page_table_des));
  new->pid = pid;
  hash_init(&new->table, page_hash, page_less, NULL);

  list_push_back(&page_table_list, &new->elem);

  lock_release(&page_table_list_lock);
  return &new->table;
}

/* helper routines */

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
static struct page* page_lookup(struct hash* page_table, const void *vaddress){
  struct page p;
  struct hash_elem *e;

  p.vaddr = vaddress;
  e = hash_find(page_table, &p.hash_elem);
  return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}
