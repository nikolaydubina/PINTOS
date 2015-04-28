#ifndef VM_SWAP
#define VM_SWAP

#include <stdlib.h>
#include "devices/disk.h"
#include "kernel/bitmap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

#define MAX_PAGES 1000
#define SECTORS_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)

#define SWAP_FREE 0
#define SWAP_USED 1

void swap_init(void);

void swap_in(struct page* page);
void swap_out(struct page* page);

#endif // VM_SWAP

