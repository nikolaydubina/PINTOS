#include "vm/swap.h"

struct lock swap_lock;
struct bitmap* swap_slots;
struct disk* disk;

void swap_init(){
  disk = disk_get(1, 1);

  ASSERT(disk != NULL);

  swap_slots = bitmap_create(disk_size(disk) / SECTORS_PER_PAGE);

  bitmap_set_all(swap_slots, SWAP_FREE);
  lock_init(&swap_lock);
}

/* move frame from swap */
void swap_in(struct page* page){
  ASSERT(page != NULL);
  lock_acquire(&swap_lock);

  size_t page_index = page->swap_id;
  ASSERT(page_index != BITMAP_ERROR);
  ASSERT(bitmap_test(swap_slots, page_index) == SWAP_USED);

  bitmap_flip(swap_slots, page_index);

  /* move from swap */
  int i;
  for(i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_read(disk, page_index * SECTORS_PER_PAGE + i,
              page->paddr + i * DISK_SECTOR_SIZE);

  lock_release(&swap_lock);
}

/* move frame to swap */
void swap_out(struct page* page){
  ASSERT(page != NULL);

  lock_acquire(&swap_lock);
  
 /* lookup free slot */
  size_t free_index = bitmap_scan_and_flip(swap_slots, 0, 1, SWAP_FREE);
  ASSERT(free_index != BITMAP_ERROR);

  page->swap_id = free_index;

  /* move page to swap */
  int i;
  for (i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_write(disk, free_index * SECTORS_PER_PAGE + i, 
               page->paddr + i * DISK_SECTOR_SIZE);

  lock_release(&swap_lock);
}

