#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "filesys/filesys.h"

extern struct dir;

/* A single directory entry. */
struct dir_entry 
  {
    disk_sector_t inode_sector;         /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR. Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt, disk_sector_t parent) 
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry), true, parent);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
  struct dir *dir = calloc (1, sizeof *dir);
  //printf("DEBUG: diropen\n");
  //if (inode_get_sector(dir->inode) == 0xa3)
  //printf("DEBUG: dir_open: inode=%p\n", inode_get_sector(inode));
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  //printf("DEBUG: diropenroot\n");
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  //printf("DEBUG: dirreopen\n");
  //printf("DEBUG: dir_reopen: inode=%p\n",inode_get_sector(dir->inode));
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  //printf("DEBUG: dirclose: dir=%p\n", dir);
  //printf("DEBUG: dir_close: inode=%p\n",inode_get_sector(dir->inode));
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* returns true if dir has parent dir
 * otherwise false
 * sets indode accordingly.
 * The caller must close *INODE */
bool dir_lookup_parent (const struct dir* dir, struct inode** inode){
  ASSERT(dir != NULL);
  ASSERT(inode != NULL);

  *inode = inode_open_parent(dir->inode);

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) 
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

  //printf("DEBUG: dir_add: inode_sector=%p name=[%s]\n", inode_sector, name);

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* check if it is dir and opened */
  if (inode_isdir(inode) && !inode_isremoved(inode) && inode_isused(inode))
    goto done;

  /* check if directory is empty */
  struct dir* cdir = dir_open(inode);
  if (!dir_isempty(cdir)){
      dir_close(cdir);
      goto done;
  }
  dir_close(cdir);

  /* check if it is current dir */
  if (inode_get_sector(inode) == 
      inode_get_sector(dir_get_inode(thread_current()->current_dir)))
    goto done;    

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}


bool dir_isempty(struct dir *dir){
  struct dir_entry e;
  off_t curr_pos = 0;

  while (inode_read_at (dir->inode, &e, sizeof e, curr_pos) == sizeof e)
  {
    curr_pos += sizeof e;
    if (e.in_use)
      return false;
  }
  return true;
}

bool dir_isroot(struct dir* dir){
  ASSERT(dir != NULL);
  return inode_get_sector(dir_get_inode(dir)) == ROOT_DIR_SECTOR;
}

bool dir_issame(struct dir* dira, struct dir* dirb){
  ASSERT(dira != NULL);
  ASSERT(dirb != NULL);
  return inode_get_sector(dir_get_inode(dira)) == 
         inode_get_sector(dir_get_inode(dirb));
}
