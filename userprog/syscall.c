#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void){
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f){
  printf("system call!\n");

  /* debug */
  //printf("esp: %0x\n", f->esp);
  //hex_dump((uintptr_t) (f->esp - 200), (void **) (f->esp - 200), 500, true);

  int syscall_num = *(int*)(f->esp);

  /* dispatch */
  switch(syscall_num){
    /* Projects 2 and later. */
    case SYS_HALT:
      /* Halt the operating system. */
      printf("syscall: halt\n");
      power_off();
      NOT_REACHED ();
      break;
    case SYS_EXIT:                   
      /* Terminate this process. */
      printf("syscall: exit\n");
      int exit_status = *(int*)(f->esp + 4);
      /* TODO: notify parent for exit status */
      thread_exit();
      break;
    case SYS_EXEC:                   
      /* Start another process. */
      break;
    case SYS_WAIT:                   
      /* Wait for a child process to die. */
      printf("syscall: wait\n");
      break;
    case SYS_CREATE:                 
      /* Create a file. */
      break;
    case SYS_REMOVE:                 
      /* Delete a file. */
      break;
    case SYS_OPEN:                   
      /* Open a file. */
      break;
    case SYS_FILESIZE:               
      /* Obtain a file's size. */
      break;
    case SYS_READ:                   
      /* Read from a file. */
      printf("syscall: read\n");
      break;
    case SYS_WRITE:                  
      /* Write to a file. */
      printf("syscall: write\n");
      break;
    case SYS_SEEK:                   
      /* Change position in a file. */
      break;
    case SYS_TELL:                   
      /* Report current position in a file. */
      break;
    case SYS_CLOSE:                  
      /* Close a file. */
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
