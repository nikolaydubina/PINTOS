#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/directory.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

#define DIR_MAX_DEPTH 100
#define DIR_MAX_NAME NAME_MAX
#define DIR_MAX_PATH DIR_MAX_DEPTH * DIR_MAX_NAME

/* Disk used for file system. */
extern struct disk *filesys_disk;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
void filesys_close(struct file* file);
bool filesys_remove (const char *name);

/* directories management */
bool filesys_chdir(const char* name);
bool filesys_mkdir(const char* name);
bool filesys_readdir(struct file* file, char* name);
bool filesys_isdir(struct file* file);
uint32_t filesys_getinumber(struct file* file);

#endif /* filesys/filesys.h */
