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
void swap_in(const struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->paddr != NULL);

  lock_acquire(&swap_lock);

  size_t page_index = page->swap_id;
  ASSERT(page_index != BITMAP_ERROR);
  ASSERT(bitmap_test(swap_slots, page_index) == SWAP_USED);

  bitmap_flip(swap_slots, page_index);

  /* move from swap */
  int i;
  for(i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_read(disk, page_index * SECTORS_PER_PAGE + i,
              (uint8_t*)page->paddr + i * DISK_SECTOR_SIZE);

  //printf("DEBUG: swap_in: %p - %0x\n", page->paddr, *(uint8_t*)page->paddr);
  lock_release(&swap_lock);
}

/* move frame to swap */
size_t swap_out(const struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->paddr != NULL);

  lock_acquire(&swap_lock);
  
 /* lookup free slot */
  size_t free_index = bitmap_scan_and_flip(swap_slots, 0, 1, SWAP_FREE);
  ASSERT(free_index != BITMAP_ERROR);

  /* move page to swap */
  int i;
  for (i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_write(disk, free_index * SECTORS_PER_PAGE + i, 
               (uint8_t*)page->paddr + i * DISK_SECTOR_SIZE);

  //printf("DEBUG: swap_out: %p - %0x\n", page->paddr, *(uint8_t*)page->paddr);
  lock_release(&swap_lock);

  return free_index;
}
