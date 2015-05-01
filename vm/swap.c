#include "vm/swap.h"

static unsigned N_slots;            /* number of slots */
static struct disk* disk;           /* swap disk */
static struct bitmap* swap_slots;   /* describes pages slots in swap disk */
static struct semaphore free_slots; /* signals that there are free slots */
static struct lock bitmap_lock;     /* synch access to bitmap */

static inline struct semaphore* get_sema(int index);

void swap_init(){
  disk = disk_get(1, 1);
  ASSERT(disk != NULL);

  N_slots = disk_size(disk) / SECTORS_PER_PAGE;
  ASSERT(N_slots >= 1);

  swap_slots = bitmap_create(N_slots);
  bitmap_set_all(swap_slots, SWAP_FREE);

  lock_init(&bitmap_lock);
  sema_init(&free_slots, N_slots);
}

/* move frame from swap */
void swap_in(const struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->paddr != NULL);

  size_t page_index = page->swap_id;
  ASSERT(page_index != BITMAP_ERROR);

  lock_acquire(&bitmap_lock);
  ASSERT(bitmap_test(swap_slots, page_index) == SWAP_USED);
  bitmap_set(swap_slots, page_index, SWAP_FREE);
  lock_release(&bitmap_lock);

  sema_up(&free_slots);

  /* move from swap */
  int i;
  for(i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_read(disk, page_index * SECTORS_PER_PAGE + i, 
              (uint8_t*)page->paddr + i * DISK_SECTOR_SIZE);
}

/* move frame to swap */
size_t swap_out(const struct page* page){
  ASSERT(page != NULL);
  ASSERT(page->paddr != NULL);

  /* lookup free slot */
  sema_down(&free_slots);

  lock_acquire(&bitmap_lock);
  size_t free_index = bitmap_scan_and_flip(swap_slots, 0, 1, SWAP_FREE);
  lock_release(&bitmap_lock);

  ASSERT(free_index != BITMAP_ERROR);

  /* move page to swap */
  int i;
  for (i = 0; i < SECTORS_PER_PAGE; ++i)
    disk_write(disk, free_index * SECTORS_PER_PAGE + i, 
               (uint8_t*)page->paddr + i * DISK_SECTOR_SIZE);

  return free_index;
}
