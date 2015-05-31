#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/disk.h"
#include "filesys/inode.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct inode;

/* A directory. */
struct dir 
  {
    struct inode* inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* Opening and closing directories. */
bool dir_create(disk_sector_t sector, size_t entry_cnt, disk_sector_t parent);
struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);

/* Reading and writing. */
bool dir_lookup (const struct dir *, const char *name, struct inode **);
bool dir_lookup_parent (const struct dir *, struct inode **);
bool dir_add (struct dir *, const char *name, disk_sector_t);
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);

/* utilities */
bool dir_isempty(struct dir* dir);
struct inode *dir_get_inodE (struct dir* dir);
bool dir_isroot(struct dir* dir);
bool dir_issame(struct dir* dira, struct dir* dirb);

#endif /* filesys/directory.h */
