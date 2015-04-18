#ifndef VM_PAGE
#define VM_PAGE

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "kernel/hash.h"
#include "kernel/list.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/frame.h"

struct page{
  tid_t tid;
  struct frame* frame;
  struct thread* thread;

  struct hash_elem hash_elem;
};

#endif // VM_PAGE
