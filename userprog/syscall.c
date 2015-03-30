#include "userprog/syscall.h"
#include <stdio.h>
#include <lib/kernel/console.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

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

void syscall_init (void){
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame* f){
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
  printf("syscall: halt\n");
  power_off();
  NOT_REACHED ();
}

/* Terminate this process. */
static void syscall_exit(struct intr_frame* f){
  printf("syscall: exit\n");
  int exit_status;

  memcpy(&exit_status, f->esp + 4, 4);

  f->eax = exit_status;
  /* TODO: notify parent for exit status */
  thread_exit();
}

/* Start another process. */
static void syscall_exec(struct intr_frame* f){
  printf("syscall: exec\n");
  // TODO

}

/* Wait for a child process to die. */
static void syscall_wait(struct intr_frame* f){
  printf("syscall: wait\n");

  pid_t wpid;
  memcpy(&wpid, f->esp + 4, 4);

  int ret = process_wait(wpid);
  f->eax = ret;

  thread_exit();
}

/* Create a file. */
static void syscall_create(struct intr_frame* f){
  printf("syscall: create\n");
}

/* Delete a file. */
static void syscall_remove(struct intr_frame* f){
  printf("syscall: remove\n");
}

/* Open a file. */
static void syscall_open(struct intr_frame* f){
  printf("syscall: open\n");
}

/* Obtain a file's size. */
static void syscall_filesize(struct intr_frame* f){
  printf("syscall: filesize\n");
}

static void syscall_read(struct intr_frame* f){
  printf("syscall: read\n");
}

static void syscall_write(struct intr_frame* f){
  printf("syscall: write\n");
  int fd;
  const char* buffer;
  unsigned size;

  memcpy(&fd, f->esp + 4, 4);
  memcpy(&buffer, f->esp + 8, 4);
  memcpy(&size, f->esp + 12, 4);

  if (is_user_vaddr(buffer)){
    int asize =  size < 100 ? size : 100;
    if (fd == 1){
      putbuf(buffer, asize);
      f->eax = asize;
    }
    else{
      // TODO: write to file
    }
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

