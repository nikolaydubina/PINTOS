#include <debug.h>
#include "threads/synch.h"
#include "cache.h"

#define NSECTORS 64

struct cache_block{
  struct disk* disk; 
  disk_sector_t start;

  bool free;            /* sector is not used */
  bool modified;        /* sector was modified */
  bool accessed;        /* sector was accessed */
  uint64_t age;         /* time sinse last accsess */

  char data[DISK_SECTOR_SIZE];

  struct semaphore sema;
};

struct cache_block cache[NSECTORS];

static int cache_evict(void);
static int get_cache_number(struct disk* disk, disk_sector_t start, bool bring);

void cache_init(void){
  int i;
  for(i = 0; i < NSECTORS; ++i){
    cache[i].disk = NULL;
    cache[i].start = 0;

    cache[i].free = true;
    cache[i].modified = false;
    cache[i].accessed = false;
    cache[i].age = 0;

    memset(cache[i].data, 0, DISK_SECTOR_SIZE);

    sema_init(&(cache[i].sema), 1);
  }
}

void cache_write(struct disk* disk, disk_sector_t start, char* data){
  ASSERT(disk != NULL);
  ASSERT(data != NULL);

  int i = get_cache_number(disk, start, false);

  memcpy(&(cache[i].data), data, DISK_SECTOR_SIZE);
  cache[i].accessed = true;
  cache[i].modified = true;
  cache[i].age = 0;

  sema_up(&(cache[i].sema));
};

void cache_read(struct disk* disk, disk_sector_t start, char* data){
  ASSERT(disk != NULL);
  ASSERT(data != NULL);

  int i = get_cache_number(disk, start, true);

  memcpy(data, &(cache[i].data), DISK_SECTOR_SIZE);
  cache[i].accessed = true;
  cache[i].age = 0;

  sema_up(&(cache[i].sema));
};

static int cache_evict(void){
  int i;
  int maxk;
  bool first = true;
  bool found = false;

  /* clock algorithm.
   * evicting least recently used block */
  for(i = 0; i < NSECTORS && !found; i++){
    sema_down(&(cache[i].sema));
    if (cache[i].free){
      maxk = i;
      found = true;
    }
    else {
      if (first && !cache[i].free){
        maxk = i;
        first = false;
      }
      else
        maxk = cache[maxk].age < cache[i].age ? i : maxk;
    }
  }

  /* releasing semaphores for other blocks */
  int j;
  for(j = 0; j < i; j++)
    if (j != maxk)
      sema_up(&(cache[j].sema));

  if (!cache[maxk].free)
    disk_write(cache[maxk].disk, cache[maxk].start, &(cache[maxk].data));

  return maxk;
}

/* called inside clock tick */
void cache_update_age(void){
  int i;
  for(i = 0; i < NSECTORS; i++){
    if (!cache[i].free)
      cache[i].age++;
  }
}

/* writing all pages to disk */
void cache_writeall(void){
  int i;
  for(i = 0; i < NSECTORS; ++i){
    if (!cache[i].free && cache[i].modified)
      disk_write(cache[i].disk, cache[i].start, &(cache[i].data));
  }
}

/* returns number of cached sector if any
 * if not found evicts and loads(if selected) to cache
 * NOTE: DOES NOT UPS SEMAPHORE */
static int get_cache_number(struct disk* disk, disk_sector_t start, 
                            bool bring)
{
  int i = 0;
  bool found = false;

  /* looking for cached sector */
  while(!found && i < NSECTORS){
    sema_down(&(cache[i].sema));
    if (cache[i].disk == disk && cache[i].start == start && 
        !cache[i].free)
    {
      found = true;
    }
    else{
      sema_up(&(cache[i].sema));
      i++;
    }
  }

  /* if not found evict and bring */
  if (!found){
    i = cache_evict();  /* NOTE: does not release i-th semaphore */
    
    cache[i].disk = disk;
    cache[i].start = start;

    cache[i].free = false;
    cache[i].modified = false;
    cache[i].accessed = false;
    cache[i].age = 0;

    if (bring)
      disk_read(cache[i].disk, cache[i].start, &(cache[i].data));
      // TODO: add read ahead
   }

  return i;
}
