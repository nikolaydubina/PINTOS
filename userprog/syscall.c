#include <stdio.h>
#include <lib/kernel/console.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include "vm/page.h"

#define ERROR -1

#define ARG0 correct_address(f->esp, f->esp)
#define ARG1 ARG0 && correct_address(f->esp + 4, f->esp)
#define ARG2 ARG1 && correct_address(f->esp + 8, f->esp)
#define ARG3 ARG2 && correct_address(f->esp + 12, f->esp)
#define CHECK(c) if (!(c)) safe_exit(ERROR);

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

static struct file_descr* lookup_file(int fid);
bool correct_address(void* p, void* esp);
bool correct_buffer(void* p, size_t n, void* esp);
bool correct_string(void* p, void* esp);

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

bool is_stack_access(void* addr, void* esp){
  return addr >= esp - STACK_ACCESS_HEURISTIC;
}

bool correct_address(void* addr, void* esp){
  if (!(is_user_vaddr(addr) && addr > USER_VADDR_MIN && addr != NULL))
    return false;

  bool success = false;
  struct page* curr_page = page_get(addr);
  if (curr_page != NULL){
    load_page(curr_page);
    success = curr_page->loaded;
  }
  else if (is_stack_access(addr, esp))
    success = grow_stack(addr);

  return success;
}

bool correct_buffer(void* p, unsigned n, void* esp){
  if (!correct_address(p, esp))
    return false;

  unsigned i;
  bool ret = true;

  for(i = 0; i < n && ret; ++i){
    ret = correct_address(p + i, esp);
  }

  return ret;
}

bool correct_string(void* p, void* esp){
  if (!correct_address(p, esp))
    return false;

  bool ret = true;
  void* pc = p;
  ret = correct_address(pc, esp);
  while (*(char*)pc != 0 && ret){
    pc = (char*)pc + 1;
    ret = correct_address(pc, esp);
  }
  return ret;
}

void safe_exit(int exit_status){
  thread_current()->exit_status = exit_status;
  printf("%s: exit(%d)\n", thread_name(), exit_status);
  thread_exit();
}

static void
syscall_handler (struct intr_frame* f){
  CHECK(ARG0)

  int syscall_num;
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
  power_off();
  NOT_REACHED ();
}

/* Terminate this process. */
static void syscall_exit(struct intr_frame* f){
  CHECK(ARG1)

  int exit_status;

  memcpy(&exit_status, f->esp + 4, 4);

  lock_acquire(&opened_files_lock);

  /* allowing write to executable */
  struct file* exec_file = thread_current()->exec_file;
  if (exec_file != NULL){
    file_allow_write(exec_file);
    file_close(exec_file);
  }

  /* closing files */
  struct list_elem* e;
  for(e = list_begin(&opened_files);
      e != list_end(&opened_files);)
  {
    struct file_descr* curr = list_entry(e, struct file_descr, elem);
    if (thread_current()->tid == curr->pid){
      file_close(curr->file);
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
  CHECK(ARG1)

  char* cmd_line;

  memcpy(&cmd_line, f->esp + 4, 4);
  
  if (!correct_string(cmd_line, f->esp)){
    f->eax = ERROR;
    return;
  }

  int new_pid;
  new_pid = process_execute(cmd_line); // pid == tid
  if (new_pid == TID_ERROR)
    f->eax = ERROR;
  else
    f->eax = new_pid;
}

/* Wait for a child process to die. */
static void syscall_wait(struct intr_frame* f){
  CHECK(ARG1)

  int wpid;

  memcpy(&wpid, f->esp + 4, 4);

  int ret = process_wait(wpid);
  f->eax = ret;
}

/* Create a file. */
static void syscall_create(struct intr_frame* f){
  CHECK(ARG2)

  const char* file;
  unsigned initial_size;

  memcpy(&file, f->esp + 4, 4);
  memcpy(&initial_size, f->esp + 8, 4);

  if (!correct_string(file, f->esp))
    safe_exit(ERROR);
    
  lock_acquire(&opened_files_lock);
  bool success = filesys_create(file, initial_size);
  f->eax = success;
  lock_release(&opened_files_lock);
}

/* Delete a file. */
static void syscall_remove(struct intr_frame* f){
  CHECK(ARG1)
    
  const char* filename;

  memcpy(&filename, f->esp + 4, 4);

  if (!correct_string(filename, f->esp))
    safe_exit(ERROR);

  lock_acquire(&opened_files_lock);

  struct file* rm_file = filesys_open(filename);
  if (rm_file == NULL){
    lock_release(&opened_files_lock);
    f->eax = ERROR;
    return;
  }

  inode_remove(file_get_inode(rm_file));

  lock_release(&opened_files_lock);
}

/* Open a file. */
static void syscall_open(struct intr_frame* f){
  CHECK(ARG1)

  const char* filename;

  memcpy(&filename, f->esp + 4, 4);

  if (!correct_string(filename, f->esp))
    safe_exit(ERROR);

  static int last_fid = 2;

  int new_fid = last_fid++;

  lock_acquire(&opened_files_lock);
  struct file* new_file = filesys_open(filename);

  if (new_file == NULL)
    f->eax = ERROR;
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
  CHECK(ARG1)

  int fid;

  memcpy(&fid, f->esp + 4, 4);

  if (fid == 0 || fid == 1)
    safe_exit(ERROR);

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    safe_exit(ERROR);
  }

  f->eax = file_length(fdescr->file);
  lock_release(&opened_files_lock);
}

static void syscall_read(struct intr_frame* f){
  if (f == NULL)
    safe_exit(ERROR);

  CHECK(ARG3)

  int fid;
  char* buffer;
  unsigned size;

  memcpy(&fid, f->esp + 4, 4);
  memcpy(&buffer, f->esp + 8, 4);
  memcpy(&size, f->esp + 12, 4);

  if (!correct_buffer(buffer, size, f->esp))
    safe_exit(ERROR);
    
  int asize =  size < 10000000 ? size : 10000000;

  if (fid == 1)
    safe_exit(ERROR);

  if (fid == 0){
    int i;
    for(i = 0; i < asize; ++i)
      buffer[i] = input_getc();
    if (i == asize)
      f->eax = asize;
    else
      f->eax = ERROR;
  }
  else{
    lock_acquire(&opened_files_lock);
    struct file_descr* fdescr = lookup_file(fid);

    if (fdescr == NULL){
      lock_release(&opened_files_lock);
      safe_exit(ERROR);
    }

    f->eax = file_read(fdescr->file, buffer, asize);
    lock_release(&opened_files_lock);
  }
}

static void syscall_write(struct intr_frame* f){
  CHECK(ARG3)

  int fid;
  const char* buffer;
  unsigned size;

  memcpy(&fid, f->esp + 4, 4);
  memcpy(&buffer, f->esp + 8, 4);
  memcpy(&size, f->esp + 12, 4);

  if (!correct_buffer(buffer, size, f->esp))
    safe_exit(ERROR);
   
  if (fid == 0)
    safe_exit(ERROR);

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
      f->eax = ERROR;
      return;
    }

    f->eax = file_write(fdescr->file, buffer, asize);
    lock_release(&opened_files_lock);
  }
}

/* Change position in a file. */
static void syscall_seek(struct intr_frame* f){
  CHECK(ARG2)

  int fid;
  unsigned position;

  memcpy(&fid, f->esp + 4, 4);
  memcpy(&position, f->esp + 8, 4);

  if (fid == 0 || fid == 1){
    f->eax = ERROR;
    return;
  }

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    f->eax = ERROR;
    return;
  }

  f->eax = file_seek(fdescr->file, position);
  lock_release(&opened_files_lock);
}

/* Report current position in a file. */
static void syscall_tell(struct intr_frame* f){
  CHECK(ARG1)

  int fid;

  memcpy(&fid, f->esp + 4, 4);

  if (fid == 0 || fid == 1){
    f->eax = ERROR;
    return;
  }

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    f->eax = ERROR;
    return;
  }

  f->eax = file_tell(fdescr->file);
  lock_release(&opened_files_lock);
}

/* Close a file. */
static void syscall_close(struct intr_frame* f){
  CHECK(ARG1)

  int fid;

  memcpy(&fid, f->esp + 4, 4);

  if (fid == 0 || fid == 1){
    f->eax = ERROR;
    return;
  }

  lock_acquire(&opened_files_lock);
  struct file_descr* fdescr = lookup_file(fid);

  if (fdescr == NULL){
    lock_release(&opened_files_lock);
    f->eax = ERROR;
    return;
  }

  file_close(fdescr->file);
  list_remove(&fdescr->elem);
  lock_release(&opened_files_lock);
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
