#include <stdio.h>
#include <lib/kernel/console.h>
#include <syscall-nr.h>
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"

static void syscall_handler (struct intr_frame*);

static void syscall_halt(struct intr_frame*);
static void syscall_exit(struct intr_frame*);
static void syscall_exec(struct intr_frame*);
static void syscall_wait(struct intr_frame*);
static void syscall_create(struct intr_frame*);
static void syscall_remove(struct intr_frame*);
static void syscall_open(struct intr_frame*);
static void syscall_filesize(struct intr_frame*);
static void syscall_read(struct intr_frame*);
static void syscall_write(struct intr_frame*);
static void syscall_seek(struct intr_frame*);
static void syscall_tell(struct intr_frame*);
static void syscall_close(struct intr_frame*);
static void syscall_chdir(struct intr_frame*);
static void syscall_mkdir(struct intr_frame*);
static void syscall_readdir(struct intr_frame*);
static void syscall_isdir(struct intr_frame*);
static void syscall_inumber(struct intr_frame*);

static struct file_descr* lookup_file(int fid);

struct file_descr{
  int fid;
  tid_t pid;
  struct file* file;
  struct list_elem elem;
};

/* NOTE: process.c - load() uses filesys_open */
struct list opened_files;
struct lock opened_files_lock;

void syscall_init (void){
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&opened_files);
  lock_init(&opened_files_lock);
}

bool correct_pointer(void* p){
  return is_user_vaddr(p) && (pagedir_get_page(thread_current()->pagedir, p) != NULL);
}

void safe_exit(int exit_status){
  thread_current()->exit_status = exit_status;
  printf( "%s: exit(%d)\n", thread_name(), exit_status);
  thread_exit();
}

static void
syscall_handler (struct intr_frame* f){
  int syscall_num;

  if (!correct_pointer(f->esp))
    safe_exit(-1);

  memcpy(&syscall_num, f->esp, 4);

  /* dispatch */
  switch(syscall_num){
    /* Projects 2 and later. */
    case SYS_HALT:
      syscall_halt(f);
      break;
    case SYS_EXIT:                   
      syscall_exit(f);
      break;
    case SYS_EXEC:
      syscall_exec(f);
      break;
    case SYS_WAIT:   
      syscall_wait(f);
      break;
    case SYS_CREATE: 
      syscall_create(f);
      break;
    case SYS_REMOVE:
      syscall_remove(f);
      break;
    case SYS_OPEN:      
      syscall_open(f);
      break;
    case SYS_FILESIZE:
      syscall_filesize(f);
      break;
    case SYS_READ:       
      syscall_read(f);
      break;
    case SYS_WRITE:                  
      syscall_write(f);
      break;
    case SYS_SEEK:    
      syscall_seek(f);
      break;
    case SYS_TELL:    
      syscall_tell(f);
      break;
    case SYS_CLOSE:   
      syscall_close(f);
      break;
    /* Project 3 and optionally project 4. */
    //SYS_MMAP,                   /* Map a file into memory. */
    //SYS_MUNMAP,                 /* Remove a memory mapping. */
    /* Project 4 only. */
    case SYS_CHDIR:                  
      syscall_chdir(f);
      break;
    case SYS_MKDIR:                  
      syscall_mkdir(f);
      break;
    case SYS_READDIR:                
      syscall_readdir(f);
      break;
    case SYS_ISDIR:                  
      syscall_isdir(f);
      break;
    case SYS_INUMBER:                 
      syscall_inumber(f);
      break;
    default:
      printf("ERROR!\n");
  }
}

/* Halt the operating system. */
static void syscall_halt(struct intr_frame* f){
  power_off();
  NOT_REACHED ();
}

/* Terminate this process. */
static void syscall_exit(struct intr_frame* f){
  int exit_status;
  
  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&exit_status, f->esp + 4, 4);

  lock_acquire(&opened_files_lock);

  /* allowing write to executable */
  struct file* exec_file = thread_current()->exec_file;
  if (exec_file != NULL){
    file_allow_write(exec_file);
    filesys_close(exec_file);
  }

  /* closing files */
  struct list_elem* e;
  for(e = list_begin(&opened_files);
      e != list_end(&opened_files);)
  {
    struct file_descr* curr = list_entry(e, struct file_descr, elem);
    if (thread_current()->tid == curr->pid){
      filesys_close(curr->file);
      e = list_remove(e);
    }
    else
      e = list_next(e);
  }
  lock_release(&opened_files_lock);

  /* exiting */
  safe_exit(exit_status);
}

/* Start another process. */
static void syscall_exec(struct intr_frame* f){
  char* cmd_line;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&cmd_line, f->esp + 4, 4);
  
  if (!(correct_pointer(cmd_line) && cmd_line != NULL)){
    f->eax = -1;
    return;
  }

  int new_pid;
  new_pid = process_execute(cmd_line); // pid == tid
  if (new_pid == TID_ERROR)
    f->eax = -1;
  else
    f->eax = new_pid;
}

/* Wait for a child process to die. */
static void syscall_wait(struct intr_frame* f){
  int wpid;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&wpid, f->esp + 4, 4);

  int ret = process_wait(wpid);
  f->eax = ret;
}

/* Create a file. */
static void syscall_create(struct intr_frame* f){
  const char* file;
  unsigned initial_size;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4) &&
        correct_pointer(f->esp + 8)))
    safe_exit(-1);

  memcpy(&file, f->esp + 4, 4);
  memcpy(&initial_size, f->esp + 8, 4);

  if (!(correct_pointer(file) && file != NULL))
    safe_exit(-1);

  lock_acquire(&opened_files_lock);
  bool success = filesys_create(file, initial_size);
  f->eax = success;
  lock_release(&opened_files_lock);
}

/* Delete a file. */
static void syscall_remove(struct intr_frame* f){
  const char* filename;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&filename, f->esp + 4, 4);

  if (!(correct_pointer(filename) && filename != NULL))
    safe_exit(-1);

  lock_acquire(&opened_files_lock);

  if (!filesys_remove(filename)){
    lock_release(&opened_files_lock);
    f->eax = 0;
    return;
  }

  lock_release(&opened_files_lock);
}

/* Open a file. */
static void syscall_open(struct intr_frame* f){
  const char* filename;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&filename, f->esp + 4, 4);

  if (!(correct_pointer(filename) && filename != NULL))
    safe_exit(-1);

  static int last_fid = 2;

  int new_fid = last_fid++;

  lock_acquire(&opened_files_lock);
  struct file* new_file = filesys_open(filename);

  if (new_file == NULL)
    f->eax = -1;
  else{
    struct file_descr* newfile_descr = malloc(sizeof(struct file_descr));
    newfile_descr->fid = new_fid;
    newfile_descr->pid = thread_current()->tid;
    newfile_descr->file = new_file;
    list_push_back(&opened_files, &newfile_descr->elem);
    f->eax = newfile_descr->fid;
  }
  lock_release(&opened_files_lock);
}

/* Obtain a file's size. */
static void syscall_filesize(struct intr_frame* f){
  int fid;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&fid, f->esp + 4, 4);

  if (fid == 0 || fid == 1)
    safe_exit(-1);

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    safe_exit(-1);
  }

  f->eax = file_length(fdescr->file);
  lock_release(&opened_files_lock);
}

static void syscall_read(struct intr_frame* f){
  int fid;
  char* buffer;
  unsigned size;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4) &&
        correct_pointer(f->esp + 8) &&
        correct_pointer(f->esp + 12)))
    safe_exit(-1);

  memcpy(&fid, f->esp + 4, 4);
  memcpy(&buffer, f->esp + 8, 4);
  memcpy(&size, f->esp + 12, 4);

  if (!(correct_pointer(buffer) && buffer != NULL))
    safe_exit(-1);
    
  int asize =  size < 10000000 ? size : 10000000;

  if (fid == 1)
    safe_exit(-1);

  if (fid == 0){
    int i;
    for(i = 0; i < asize; ++i)
      buffer[i] = input_getc();
    if (i == asize)
      f->eax = asize;
    else
      f->eax = -1;
  }
  else{
    lock_acquire(&opened_files_lock);
    struct file_descr* fdescr = lookup_file(fid);

    if (fdescr == NULL){
      lock_release(&opened_files_lock);
      safe_exit(-1);
    }

    f->eax = file_read(fdescr->file, buffer, asize);
    lock_release(&opened_files_lock);
  }
}

static void syscall_write(struct intr_frame* f){
  int fid;
  const char* buffer;
  unsigned size;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4) &&
        correct_pointer(f->esp + 8) &&
        correct_pointer(f->esp + 12)))
    safe_exit(-1);

  memcpy(&fid, f->esp + 4, 4);
  memcpy(&buffer, f->esp + 8, 4);
  memcpy(&size, f->esp + 12, 4);

  if (!(correct_pointer(buffer) && buffer != NULL))
    safe_exit(-1);
   
  if (fid == 0)
    safe_exit(-1);

  int asize =  size < 10000000 ? size : 10000000;

  if (fid == 1){
    lock_acquire(&opened_files_lock);
    putbuf(buffer, asize);
    f->eax = asize;
    lock_release(&opened_files_lock);
  }
  else{
    lock_acquire(&opened_files_lock);
    struct file_descr* fdescr = lookup_file(fid);

    if (fdescr == NULL){
      lock_release(&opened_files_lock);
      f->eax = -1;
      return;
    }

    int written = file_write(fdescr->file, buffer, asize);
    if (written > 0)
      f->eax = written;
    else
      f->eax = -1;
    lock_release(&opened_files_lock);
  }
}

/* Change position in a file. */
static void syscall_seek(struct intr_frame* f){
  int fid;
  unsigned position;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4) &&
        correct_pointer(f->esp + 8)))
    safe_exit(-1);

  memcpy(&fid, f->esp + 4, 4);
  memcpy(&position, f->esp + 8, 4);

  if (fid == 0 || fid == 1){
    f->eax = -1;
    return;
  }

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    f->eax = -1;
    return;
  }

  f->eax = file_seek(fdescr->file, position);
  lock_release(&opened_files_lock);
}

/* Report current position in a file. */
static void syscall_tell(struct intr_frame* f){
  int fid;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&fid, f->esp + 4, 4);

  if (fid == 0 || fid == 1){
    f->eax = -1;
    return;
  }

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    f->eax = -1;
    return;
  }

  f->eax = file_tell(fdescr->file);
  lock_release(&opened_files_lock);
}

/* Close a file. */
static void syscall_close(struct intr_frame* f){
  int fid;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&fid, f->esp + 4, 4);

  if (fid == 0 || fid == 1){
    f->eax = -1;
    return;
  }

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    f->eax = -1;
    return;
  }

  filesys_close(fdescr->file);
  list_remove(&fdescr->elem);
  lock_release(&opened_files_lock);
}

/* Change the current directory. */
static void syscall_chdir(struct intr_frame* f){
  const char* dir;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&dir, f->esp + 4, 4);

  if (!(correct_pointer(dir) && dir != NULL))
    safe_exit(-1);
   
  f->eax = filesys_chdir(dir);
  return;
}

/* Create a directory. */
static void syscall_mkdir(struct intr_frame* f){
  const char* dir;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&dir, f->esp + 4, 4);

  if (!(correct_pointer(dir) && dir != NULL))
    safe_exit(-1);
   
  f->eax = filesys_mkdir(dir);
  return;
}

/* Reads a directory entry. */
static void syscall_readdir(struct intr_frame* f){
  int fd;
  char* dir;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4) &&
        correct_pointer(f->esp + 8)))
    safe_exit(-1);

  memcpy(&fd, f->esp + 4, 4);
  memcpy(&dir, f->esp + 8, 4);

  if (!(correct_pointer(dir) &&
        correct_pointer(dir + DIR_MAX_NAME + 1) && 
        dir != NULL))
    safe_exit(-1);
   
  struct file_descr* entry = lookup_file(fd);
 
  if (entry == NULL){
    f->eax = false;
    return;
  }

  if (!filesys_isdir(entry->file)){
    f->eax = false;
    return;
  }

  f->eax = filesys_readdir(entry->file, dir);
  return true;
}

/* Tests if a fd represents a directory. */
static void syscall_isdir(struct intr_frame* f){
  int fd;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&fd, f->esp + 4, 4);
   
  struct file_descr* entry = lookup_file(fd);
  
  f->eax = filesys_isdir(entry->file);
  return;
}

/* Returns the inode number for a fd. */
static void syscall_inumber(struct intr_frame* f){
  int fd;

  if (!(correct_pointer(f->esp) &&
        correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&fd, f->esp + 4, 4);
   
  struct file_descr* entry = lookup_file(fd);

  if (entry != NULL)
    f->eax = filesys_getinumber(entry->file);
  else
    f->eax = -1;
  return;
}

/* helper function. retrieves file descrtiptor
 * from opened files list
 * NOT thread safe */
static struct file_descr* lookup_file(int fid){
  struct list_elem* e;
  struct file_descr* fdescr = NULL;

  for(e = list_begin(&opened_files);
      e != list_end(&opened_files);
      e = list_next(e))
  {
    struct file_descr* curr = list_entry(e, struct file_descr, elem);
    if ((curr->fid == fid) && (thread_current()->tid == curr->pid)){
      fdescr = curr;
    }
  }

  return fdescr;
}
