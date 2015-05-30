#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "lib/string.h"
#include "devices/disk.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/directory.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);
static bool traverse(const char* dirname);

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
filesys_create (const char *name, off_t initial_size, struct dir* dir) 
{
  disk_sector_t inode_sector = 0;
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false, 0)
                  && dir_add (dir, name, inode_sector));
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
filesys_open (const char *name, struct dir* dir)
{
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name, struct dir* dir) 
{
  bool success = dir != NULL && dir_remove (dir, name);
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

//TODO: inode does not check for ROOT_DIR_SECTOR on go parent
//TODO: before indode close. children should be nofied of change if any.
//      -> if dir removes. than all children should be closed and removed as well.

/* directories management */
bool filesys_chdir(const char* name){
  bool success = true;
  // TODO
  return success;
};

bool filesys_mkdir(const char* name){
  bool success = true;
 
  disk_sector_t dir = 1;
  disk_sector_t parent = 1;

  success = dir_create(dir, 16, parent);
  return success;
};

bool filesys_readdir(int fd, char* name){
  bool success = true;
  // TODO
  return success;
};

bool filesys_isdir(struct file* file){
  ASSERT(file != NULL);

  return file_isdir(file);
}

uint32_t filesys_getinumber(struct file* file){
  ASSERT(file != NULL);

  return file_getinumber(file);
}

/* going through directory tree, by path specified in dirname
 * if reaches final directory
 *  - file, length of path - 1
 *  - dir,  length of path
 * changes dir paramater */
static bool traverse(const char* dirname, bool isdir, struct dir* dir){
  bool success = true;
  
  bool absolute = dirname[0] == '/';
  int count = 0;
  int size = 0;
  const char path[DIR_MAX_DEPTH][DIR_MAX_NAME];

  char *token, *save_ptr;
  for (token = strtok_r(dirname, "/", &save_ptr);
      token != NULL && count <= DIR_MAX_DEPTH;
      token = strtok_r(NULL, "/", &save_ptr))
  {
    int len_token = strlen(token) + 1;

    if (size + len_token > DIR_MAX_PATH ||
        len_token > DIR_MAX_NAME){
      success = false;
      return success;
    }
    else{
      strlcpy(&(path[count]), token, len_token);
      size += len_token;
      count++;
    }
  }
 
  /* traversing path */
  struct dir* curr;
  if (absolute)
    curr = dir_open_root();
  else
    curr = dir_reopen(thread_current()->current_dir);

  int i;
  int ni = isdir ? count : count - 1;
  for(i = 0; i < ni && success; i++){
    struct inode* next;
    if (strcmp(path[i], "..") == 0)
      success = dir_parent(curr, &next);
    else if (strcmp(path[i], ".") == 0)
      continue;
    else 
      success = dir_lookup(curr, path[i], &next);

    dir_close(curr);
    if (success)
      curr = dir_open(next);
  }
  
  /* check if file present */
  if (!isdir)


  if (success)
    dir = curr;

  return success;
}
