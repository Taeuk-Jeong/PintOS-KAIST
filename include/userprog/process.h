#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

#ifdef VM
/* information(arguments) to set up in lazy_load_segment. */
struct lazy_load_arg {
	size_t size;
	struct file *file;
	off_t offset;
	size_t page_read_bytes;
};

bool lazy_load_segment (struct page *page, void *aux);
#endif

#endif /* userprog/process.h */
