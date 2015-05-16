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

#define ROBUST_BUFFER_CHECK false             /* requires a lot of resoruces */
#define ERROR -1

#define ARG0 correct_address(f->esp, PHYS_BASE)
#define ARG1 ARG0 && correct_address(f->esp + 4, PHYS_BASE)
#define ARG2 ARG1 && correct_address(f->esp + 8, PHYS_BASE)
#define ARG3 ARG2 && correct_address(f->esp + 12, PHYS_BASE)
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
static void syscall_mmap(struct intr_frame* f);
static void syscall_munmap(struct intr_frame* f);

static struct file_descr* lookup_file(int fid);
bool correct_address(void* p, void* esp);
bool correct_buffer(void* p, size_t n, void* esp, bool write);
bool correct_string(void* p, void* esp);

struct file_descr{
  int fid;              /* file id */
  tid_t pid;            /* process id */
  bool closed;          /* syscall close was called */
  bool is_mmap;         /* there is mmap that uses this file */
  int mmap_id;          /* mmap id of corresponding mmap */
  struct file* file;    /* file struct */
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

inline bool is_stack_access(void* addr, void* esp){
  return addr >= esp - STACK_ACCESS_HEURISTIC;
}

inline bool correct_address(void* addr, void* esp){
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

inline bool correct_buffer(void* p, unsigned n, void* esp, bool write){
  /* quick check */
  if (!correct_address(p, esp) ||
      !correct_address(p + n, esp))
    return false;

  bool ret = true;
  if (write){
    struct page* curr;

    /* first */
    curr = page_get(p);
    ret &= curr != NULL && curr->writable;
    
    /* last */
    curr = page_get(p + n);
    ret &= curr != NULL && curr->writable;
  }

  /* roboust check */
  if (ROBUST_BUFFER_CHECK){
    unsigned i;
    for(i = 0; i < n && ret; ++i){
      ret = correct_address(p + i, esp);
      if (write){
        struct page* curr = page_get(p);
        ret &= curr->writable;
      }
    }
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
    /* Project 3 and optionally project 4. */
    case SYS_MMAP:
      syscall_mmap(f);
      break;
    case SYS_MUNMAP:
      syscall_munmap(f);
      break;
    default:
      printf("ERROR!\n");

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

  page_exit_mmap();

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

  lock_acquire(&opened_files_lock);
  int new_pid = process_execute(cmd_line); // pid == tid
  lock_release(&opened_files_lock);

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
    newfile_descr->closed = false;
    newfile_descr->is_mmap = false;
    newfile_descr->mmap_id = 0;
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

  if (!correct_buffer(buffer, size, f->esp, true))
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

  if (!correct_buffer(buffer, size, f->esp, false)) // FIXME: Check writable flag
    safe_exit(ERROR);
   
  if (fid == 0)
    safe_exit(ERROR);

  int asize =  size < 10000000 ? size : 10000000;

  lock_acquire(&opened_files_lock);
  if (fid == 1){
    putbuf(buffer, asize);
    f->eax = asize;
  }
  else{
    struct file_descr* fdescr = lookup_file(fid);

    if (fdescr == NULL){
      lock_release(&opened_files_lock);
      f->eax = ERROR;
      return;
    }

    f->eax = file_write(fdescr->file, buffer, asize);
  }
  lock_release(&opened_files_lock);
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

  if (!fdescr->is_mmap)
    file_close(fdescr->file);
  fdescr->closed = true;
  list_remove(&fdescr->elem);
  lock_release(&opened_files_lock);
}

inline bool correct_address_mmap(void* addr, void* esp){
  if (!(is_user_vaddr(addr) && addr > USER_VADDR_MIN && addr != NULL))
    return false;

  bool success = false;
  if (page_get(addr) == NULL)
    success = true;

  return success;
}

bool correct_mmap(void* addr, off_t file_length, void* esp){
  bool ret = true;
  void* curr_addr = pg_round_down(addr);

  /* missalignment */
  if (curr_addr != addr)
    return false;

  for(curr_addr = pg_round_down(addr); 
      curr_addr < addr + file_length && ret;
      curr_addr += PGSIZE)
  {
    ret = correct_address_mmap(curr_addr, esp);
  }

  return ret;
}

/* Map a file into memory. */
static void syscall_mmap(struct intr_frame* f){
  CHECK(ARG2)
  int fid;
  void* addr;

  memcpy(&fid, f->esp + 4, 4);
  memcpy(&addr, f->esp + 8, 4);

  if (addr == NULL){
    f->eax = ERROR;
    return;
  }

  /* check and lookup file-id */
  lock_acquire(&opened_files_lock);
  static int new_mmapid = 0;
  new_mmapid++;

  struct file_descr* file;
  struct list_elem* e;
  bool found = false;
  for(e = list_begin(&opened_files);
      e != list_end(&opened_files) && !found;
      e = list_next(e))
  {
    struct file_descr* curr = list_entry(e, struct file_descr, elem);
    if (curr->pid == thread_current()->tid && curr->fid == fid){
      curr->is_mmap = true;
      curr->mmap_id = new_mmapid;
      file = curr;
      found = true;
    }
  }

  if (!found || file == NULL){
    lock_release(&opened_files_lock);
    safe_exit(ERROR);
  }

  /* check new address */
  if (!correct_mmap(addr, file_length(file->file), f->esp)){
    lock_release(&opened_files_lock);
    f->eax = ERROR;
    return;
  }

  /* mmap file */
  if (!page_mmap(new_mmapid, file->file, addr)){
    lock_release(&opened_files_lock);
    f->eax = ERROR;
    return;
  }

  f->eax = new_mmapid;
  lock_release(&opened_files_lock);
}

/* Remove a memory mapping. */
static void syscall_munmap(struct intr_frame* f){
  CHECK(ARG1)
  int mmap_id;

  memcpy(&mmap_id, f->esp + 4, 4);
  
  /* closing file */
  struct file_descr* file;
  struct list_elem* e;
  bool found = false;
  for(e = list_begin(&opened_files);
      e != list_end(&opened_files) && !found;
      e = list_next(e))
  {
    struct file_descr* curr = list_entry(e, struct file_descr, elem);
    if (curr->mmap_id == mmap_id && curr->pid == thread_current()->tid){
      file = curr;
      found = true;
    }
  }

  if (found){
    if (file->closed)
      file_close(file->file);
    file->is_mmap = false;
  }

  /* removing page tables */
  if (!page_munmap(mmap_id))
    f->eax= ERROR;
}

/* helper routine */

/* retrieves file descrtiptor
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
