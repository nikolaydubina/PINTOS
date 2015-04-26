#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdio.h>

#define STACK_ACCESS_HEURISTIC 32             /* 32 bytes */
#define USER_VADDR_MIN ((void *) 0x08048000)  /* ??? */

bool is_stack_access(void* addr, void* esp);
void syscall_init (void);
void safe_exit(int exit_status);

#endif /* userprog/syscall.h */
