#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "lib/string.h"
#include "devices/disk.h"
#include "threads/thread.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/cache.h"
#include "filesys/file.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);
static bool traverse(const char* dirname, struct dir** dir, char* entryname);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  cache_init();
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_writeall();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  /* lookup dir */
  struct dir* dir;
  char dirname[DIR_MAX_NAME];

  if (!traverse(name, &dir, &dirname))
    return false;

  if (strcmp(dirname, "") == 0 
      || strcmp(dirname, ".") == 0 
      || strcmp(dirname, "..") == 0)
    return false;

  /* check if file already exists */
  struct inode* idir;
  if (dir_lookup(dir, dirname, &idir))
    return false;

  disk_sector_t inode_sector = 0;
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false, 0)
                  && dir_add (dir, dirname, inode_sector));

  //printf("DEBUG: filesys_create: name=%s dirname=%s dir=%p\n", name, dirname, dir);
  //printf("DEBUG: filesys_create: dir sector=%p\n", inode_get_sector(dir_get_inode(dir)));
  //printf("DEBUG: filesys_create: f   sector=%p\n", inode_sector);

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  /* incorrect address */
  if (strcmp(name, "") == 0)
    return NULL;

  /* lookup dir */
  struct dir* dir;
  char dirname[DIR_MAX_NAME];

  if (!traverse(name, &dir, &dirname))
    return NULL;
  if (dir == NULL)
    return NULL;

  //printf("DEBUG: filesys_open: name=%s dirname=%s dir=%p\n", name, dirname, dir);
  //printf("DEBUG: filesys_open: dir sector=%p\n", inode_get_sector(dir_get_inode(dir)));

  bool success = true;
  struct inode* inode = NULL;
  bool isfile = strcmp(dirname, "") != 0 
                && strcmp(dirname, ".") != 0 
                && strcmp(dirname, "..") != 0;

  if (strcmp(dirname, "") == 0)
    return dir_isroot(dir) ? dir_open_root() : NULL;
  else if (strcmp(dirname, ".") == 0)
    return dir;
  else if (strcmp(dirname, "..") == 0)
    success = dir_lookup_parent(dir, &inode);
  else
    success = dir_lookup (dir, dirname, &inode);

  dir_close(dir);
  if (!success || inode == NULL)
    return NULL;

  if (isfile && !inode_isdir(inode))
    return file_open(inode);
  else{
    inode_deny_write(inode);
    return dir_open(inode); 
  }
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  /* lookup dir */
  struct dir* dir;
  char dirname[DIR_MAX_NAME];

  if (strcmp(name, "/") == 0)
    return false;

  if (!traverse(name, &dir, &dirname))
    return false;

  if (strcmp(dirname, "") == 0 
      || strcmp(dirname, ".") == 0 
      || strcmp(dirname, "..") == 0)
    return false;

  //printf("DEBUG: filesys_remove: dir=%p dirname=%s\n", dir, dirname);
  bool success = (dir != NULL) && dir_remove (dir, dirname);
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/* directories management */
bool filesys_chdir(const char* name){
  struct dir* parent;
  char dirname[DIR_MAX_NAME];

  if (!traverse(name, &parent, &dirname))
    return false;

  //printf("DEBUG: traversed: parent=%p dirname=%s \n", parent, dirname);
  struct dir* dir;
  bool success = true;

  if (strcmp(dirname, "") == 0){
    if (dir_isroot(parent))
      dir = dir_open_root();
    else{
      dir = parent;
      parent = NULL;
    }
  }
  else if (strcmp(dirname, ".") == 0){
    dir = parent;
    parent = NULL;
  }
  else if (strcmp(dirname, "..") == 0){
    struct inode* inode;
    success = dir_lookup_parent(parent, &inode);
    dir = dir_open(inode);
  }
  else{
    struct inode* idir;
    success = dir_lookup(parent, dirname, &idir);

    if (success){
      dir = dir_open(idir);
      success = dir != NULL;
    }
  }
  
  if (parent != NULL)
    dir_close(parent);

  if (success){
    dir_close(thread_current()->current_dir);
    thread_current()->current_dir = dir;
  }

  return success;
};

bool filesys_mkdir(const char* name){
  struct dir* parent;
  char dirname[DIR_MAX_NAME];

  if (!traverse(name, &parent, &dirname))
    return false;

  if (strcmp(dirname, "") == 0 
      || strcmp(dirname, ".") == 0 
      || strcmp(dirname, "..") == 0)
    return false;

  /* check if it already exists */
  struct inode* idir;
  if (dir_lookup(parent, dirname, &idir))
    return false;

  disk_sector_t newsector = 0;
  disk_sector_t parent_sector = inode_get_sector(dir_get_inode(parent));
  bool success = (parent != NULL
                  && free_map_allocate (1, &newsector)
                  && dir_create(newsector, 16, parent_sector)
                  && dir_add (parent, dirname, newsector));

  //printf("DEBUG: mkdir: parent_sector=%p child_sector=%p\n", parent_sector, newsector);

  if (!success && newsector != 0) 
    free_map_release(newsector, 1);
  dir_close(parent);

  return success;
};

bool filesys_readdir(struct file* file, char* name){
  ASSERT(file != NULL);
  ASSERT(name != NULL);

  return dir_readdir(file, name);
}

bool filesys_isdir(struct file* file){
  ASSERT(file != NULL);
  return file_isdir(file);
}

uint32_t filesys_getinumber(struct file* file){
  ASSERT(file != NULL);
  return file_getinumber(file);
}

/* going through directory tree, by path specified in dirname
 * stops when reaches directory that contain specified file or directory
 * i.e. if target file is directory, it is not opened
 * if reaches final directory, changes dir paramater
 * NOTE: caller should close dir */
static bool traverse(const char* dirname, struct dir** dir, char* entryname){
  bool success = true;
  
  bool absolute = dirname[0] == '/';
  int count = 0;
  int size = 0;
  char path[DIR_MAX_DEPTH][DIR_MAX_NAME];

  /* parsing string */
  char dirnamecpy[DIR_MAX_PATH];

  int len = strlen(dirname) + 1;
  if (len > DIR_MAX_PATH)
    return false;

  strlcpy(dirnamecpy, dirname, len);

  if (strcmp(dirnamecpy, "") == 0)
    return false;

  char *token, *save_ptr;
  int len_token;
  for (token = strtok_r(dirnamecpy, "/", &save_ptr);
      token != NULL && success;
      token = strtok_r(NULL, "/", &save_ptr))
  {
    //printf("DEBUG: loop: %d %s\n", count, token);
    len_token = strlen(token) + 1;

    if (size + len_token > DIR_MAX_PATH ||
        count > DIR_MAX_DEPTH ||
        len_token > DIR_MAX_NAME)
    {
      return false;
    }
    else{
      strlcpy(&(path[count]), token, len_token);
      size += len_token;
      count++;
    }
  }

  strlcpy(entryname, &(path[count - 1]), len_token);
  //printf("DEBUG: travers: %s | last=%s\n", dirnamecpy, entryname);
 
  /* traversing path */
  struct dir* curr;
  if (absolute || thread_current()->current_dir == NULL) // FIXME O_o
    curr = dir_open_root();
  else
    curr = dir_reopen(thread_current()->current_dir);

  int i;
  for(i = 0; (i < count - 1) && success; i++){
    struct inode* next;
    if (strcmp(path[i], "..") == 0)
      success = dir_lookup_parent(curr, &next);
    else if (strcmp(path[i], ".") == 0)
      continue;
    else 
      success = dir_lookup(curr, path[i], &next);

    dir_close(curr);

    if (!success || next == NULL)
      return false;

    if (inode_isdir(next))
      curr = dir_open(next);
    else
      return false;
  }
  
  if (success)
    *dir = curr;

  return success;
}

void filesys_close(struct file* file){
  ASSERT(file != NULL);

  if (!file_isdir(file))
    file_close(file);
  else{
    //inode_allow_write(dir_get_inode(file));
    dir_close(file);
  }
}

