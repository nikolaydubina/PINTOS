#include "userprog/syscall.h"
#include <stdio.h>
#include <lib/kernel/console.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

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

bool address_correct(void* addr){
  return is_user_vaddr(addr);
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
    default:
      printf("ERROR!\n");

    /* Project 3 and optionally project 4. */
    //SYS_MMAP,                   /* Map a file into memory. */
    //SYS_MUNMAP,                 /* Remove a memory mapping. */

    /* Project 4 only. */
    //SYS_CHDIR,                  /* Change the current directory. */
    //SYS_MKDIR,                  /* Create a directory. */
    //SYS_READDIR,                /* Reads a directory entry. */
    //SYS_ISDIR,                  /* Tests if a fd represents a directory. */
    //SYS_INUMBER                 /* Returns the inode number for a fd. */
  }
}

/* Halt the operating system. */
static void syscall_halt(struct intr_frame* f){
  //printf("syscall: halt\n");
  power_off();
  NOT_REACHED ();
}

/* Terminate this process. */
static void syscall_exit(struct intr_frame* f){
  //printf("syscall: exit\n");
  int exit_status;
  
  if (!(correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&exit_status, f->esp + 4, 4);
  safe_exit(exit_status);
}

/* Start another process. */
static void syscall_exec(struct intr_frame* f){
  //printf("syscall: exec\n");
  char* cmd_line;
  if (!(correct_pointer(f->esp + 4)))
    safe_exit(-1);
  memcpy(&cmd_line, f->esp + 4, 4);
  
  if (correct_pointer(cmd_line) && cmd_line != NULL){
    int new_pid;
    new_pid = process_execute(cmd_line); // pid == tid
    f->eax = new_pid;
  }
  else
    safe_exit(-1);
}

/* Wait for a child process to die. */
static void syscall_wait(struct intr_frame* f){
  int wpid;
  if (!(correct_pointer(f->esp + 4)))
    safe_exit(-1);
  memcpy(&wpid, f->esp + 4, 4);

  int ret = process_wait(wpid);
  f->eax = ret;
}

/* Create a file. */
static void syscall_create(struct intr_frame* f){
  const char* file;
  unsigned initial_size;

  if (!(correct_pointer(f->esp + 4) &&
        correct_pointer(f->esp + 8)))
    safe_exit(-1);

  memcpy(&file, f->esp + 4, 4);
  memcpy(&initial_size, f->esp + 8, 4);

  if (!(correct_pointer(file) && file != NULL))
    safe_exit(-1);
    
  bool success = filesys_create(file, initial_size);
  f->eax = success;
}

/* Delete a file. */
static void syscall_remove(struct intr_frame* f){
  printf("syscall: remove\n");
}

/* Open a file. */
static void syscall_open(struct intr_frame* f){
  char* filename;

  if (!(correct_pointer(f->esp + 4)))
    safe_exit(-1);

  memcpy(&filename, f->esp + 4, 4);

  if (!(correct_pointer(filename) && filename != NULL))
    safe_exit(-1);

  /* searching for new id */
  int new_fid = 2;
  struct list_elem* e;
  lock_acquire(&opened_files_lock);
  for(e = list_begin(&opened_files);
      e != list_end(&opened_files);
      e = list_next(e))
  {
    struct file_descr* curr = list_entry(e, struct file_descr, elem);
    if (curr->pid == thread_current()->pid){
      if (new_fid < curr->fid)
        new_fid = curr->fid + 1;
    }
  }

  struct file_descr* newfile_descr = malloc(sizeof(struct file_descr));
  newfile_descr->fid = new_fid;
  newfile_descr->pid = thread_current()->pid;

  struct file* new_file = filesys_open(filename);
  if (new_file != NULL){
    newfile_descr->file = new_file;

    list_push_back(&opened_files, &newfile_descr->elem);

    f->eax = newfile_descr->fid;
  }
  else{
    f->eax = -1;
    free(newfile_descr);
  }
  lock_release(&opened_files_lock);
}

/* Obtain a file's size. */
static void syscall_filesize(struct intr_frame* f){
  printf("syscall: filesize\n");
}

static void syscall_read(struct intr_frame* f){
  printf("syscall: read\n");
}

static void syscall_write(struct intr_frame* f){
  int fd;
  const char* buffer;
  unsigned size;

  if (!(correct_pointer(f->esp + 4) &&
        correct_pointer(f->esp + 8) &&
        correct_pointer(f->esp + 12)))
    safe_exit(-1);

  memcpy(&fd, f->esp + 4, 4);
  memcpy(&buffer, f->esp + 8, 4);
  memcpy(&size, f->esp + 12, 4);

  if (!(address_correct(buffer)))
    safe_exit(-1);
    
  int asize =  size < 100 ? size : 100;

  if (fd == 1){
    putbuf(buffer, asize);
    f->eax = asize;
  }
  else{
    // TODO: write to file
    void;
  }
}

/* Change position in a file. */
static void syscall_seek(struct intr_frame* f){
  printf("syscall: seek\n");
}

/* Report current position in a file. */
static void syscall_tell(struct intr_frame* f){
  printf("syscall: tell\n");
}

/* Close a file. */
static void syscall_close(struct intr_frame* f){
  printf("syscall: close\n");
}

