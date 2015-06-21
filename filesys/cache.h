#include "devices/disk.h"

void cache_init(void);
void cache_read(struct disk* disk, disk_sector_t start, char* data);
void cache_write(struct disk* disk, disk_sector_t start, char* data);
void cache_writeall(void);
void cache_update_age(void);
