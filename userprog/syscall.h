#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define USER_VADDR_BOTTOM ((void *) 0x08048000)

void syscall_init (void);
void safe_exit(int exit_status);

#endif /* userprog/syscall.h */
