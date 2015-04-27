#include "vm/swap.h"

struct lock swap_lock;
struct bitmap* swap_slots;
struct disk* disk;

void swap_init(){
  lock_init(&swap_lock);
  swap_slots = bitmap_create(MAX_PAGES * SECTORS_PER_PAGE);

  bitmap_set_all(swap_slots, SWAP_FREE);

  /* disk init */
  //disk_init();
  disk = disk_get(1, 1);
}

/* move frame from swap */
void swap_in(struct frame* frame){
  lock_acquire(&swap_lock);

  /* chekc if it was swapped in before */
  size_t page_index = frame->page->swap_id;
  if (page_index == BITMAP_ERROR)
    return;

  /* checking disk access */
  if (bitmap_test(swap_slots, page_index) == SWAP_FREE)
    PANIC("TRYING TO SWAP FROM FREE LOCATION");

  bitmap_flip(swap_slots, page_index);

  /* move from swap */
  int i;
  for(i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_read(disk, page_index * SECTORS_PER_PAGE + i,
              frame->addr + i * DISK_SECTOR_SIZE);

  lock_release(&swap_lock);
}

/* move frame to swap */
void swap_out(struct frame* frame){
  lock_acquire(&swap_lock);
  
  /* lookup free slot */
  size_t free_index = bitmap_scan_and_flip(swap_slots, 0, 1, SWAP_FREE);

  if (free_index == BITMAP_ERROR)
    PANIC("SWAP IS FULL!");

  frame->page->swap_id = free_index;

  /* move page to swap */
  int i;
  for (i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_write(disk, free_index * SECTORS_PER_PAGE + i, 
               frame->addr + i * DISK_SECTOR_SIZE);

  lock_release(&swap_lock);
}

