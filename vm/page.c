#include "vm/frame.h"
#include "vm/page.h"

void page_init(void){
;
}

void* page_get(enum palloc_flags flags){
  struct page* new_page = malloc(sizeof(struct page));
  
  new_page->tid = thread_current();
  new_page->addr = frame_create(flags, new_page); // flags == PAL_USER

  return new_page->addr;
}

void page_free(void* addr){
  frame_free(addr);
}
