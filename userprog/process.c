#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#ifdef VM
#include "vm/vm.h"
#endif

#define FORK_ERROR 19920826

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

static void argument_parse (char *file_name, int *argc_ptr, char **argv);
static bool argument_stack (struct intr_frame *if_, int argc, char **argv);
static struct wait_status *get_child_wait_status (int child_tid);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy, *save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	strtok_r (file_name, " ", &save_ptr);
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	tid_t child_tid = thread_create (name, PRI_DEFAULT, __do_fork, thread_current ());
	if (child_tid == TID_ERROR)
		return TID_ERROR;

	struct wait_status *w = get_child_wait_status (child_tid);
	sema_down (&w->load_sema);          // Wait until child successfully loads.
	if (w->exit_status == FORK_ERROR) { // If load(fork) is failed, remove form children list.
		list_remove (&w->w_elem);
		sema_up (&w->dead_sema);
		return TID_ERROR;
	}

	return child_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr (va))
		return true;

	/* Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL)
		return false;

	/* Allocate new PAL_USER page for the child and set result to NEWPAGE. */
	newpage = palloc_get_page (PAL_USER);
	if (newpage == NULL)
		return false;

	/* Duplicate parent's page to the new page and check whether parent's page is writable or not
	 * (set WRITABLE according to the result). */
	memcpy (newpage, parent_page, PGSIZE);
	writable = is_writable (pte);

	/* Add new page to child's page table at address VA with WRITABLE permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	struct intr_frame *parent_if = &parent->user_if;
	bool success = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0;

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	current->running = file_reopen (parent->running);
	if (current->running == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	/* Duplicate file descriptor table of the parent process. */
	struct list *fd_table_parent = &parent->fd_table;
	struct fd_str *fd_str_parent;
	struct list *fd_table_current = &current->fd_table;
	struct fd_str *fd_str_current;

	for (struct list_elem *e = list_begin (fd_table_parent); e != list_end (fd_table_parent); e = list_next (e)) {
		fd_str_parent = list_entry (e, struct fd_str, f_elem);
		fd_str_current = calloc (1, sizeof *fd_str_current);
		if (fd_str_current == NULL)
			goto error;
		fd_str_current->fd = fd_str_parent->fd;
		fd_str_current->file = file_duplicate (fd_str_parent->file);
		list_push_back (fd_table_current, &fd_str_current->f_elem);
	}

	sema_up (&current->wait_status->load_sema);

	process_init ();

	/* Finally, switch to the newly created process. */
	if (success)
		do_iret (&if_);
error:
	exit (FORK_ERROR);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting. */
int
process_wait (tid_t child_tid) {
	/* Find the child in the list of shared data structures. */
	struct wait_status *w_child = get_child_wait_status (child_tid);

	/* If none is found, return -1. */
	if (w_child == NULL)
		return -1;

	/* Wait for the child to die, by downing a semaphore in the shared data. */
	sema_down (&w_child->dead_sema);

	/* Obtain the child’s exit code from the shared data. */
	int exit_status = w_child->exit_status;

	/* Destroy the shared data structure and remove it from the list. */
	list_remove (&w_child->w_elem);
	free (w_child);

	/* Return the child's exit code. */
	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	struct list_elem *e;
	struct fd_str *fd_str;
	struct wait_status *w = curr->wait_status;
	struct wait_status *w_child;
	int ref_cnt, ref_cnt_child;

	e = list_begin (&curr->fd_table);
	while (e != list_end (&curr->fd_table)) {
		fd_str = list_entry (e, struct fd_str, f_elem);
		e = list_next (e);
		file_close (fd_str->file);
		free (fd_str);
	}

	/* Destroy the current process's page directory and switch back to the kernel-only page directory. */
	process_cleanup ();

	/* Close running file. */
	file_close (curr->running);

	/* If load(fork) is failed, free child's wait_status. */
	if (w->exit_status == FORK_ERROR) {
		sema_down (&w->dead_sema); // Wait for parent process to get exit status(FORK_ERROR) and remove this process from children list.
		free (w);
		return;
	}

	/* Iterate the list of children and, as in the previous step. */
	e = list_begin (&curr->children);
	while (e != list_end (&curr->children)) {
		w_child = list_entry (e, struct wait_status, w_elem);
		/* Mark them as no longer used by us. */
		lock_acquire (&w_child->lock);
		ref_cnt_child = --w_child->ref_cnt;
		lock_release (&w_child->lock);

		/* Free them if the child is also dead. */
		if (ref_cnt_child == 0) {
			e = list_remove (e);
			free (w_child);
		} else {
			e = list_next (e);
		}
	}
	
	/* Up the semaphore in the data shared with our parent process (if any).
	 * In some kind of race-free way (such as using a lock and a reference count in the shared data area),
	 * mark the shared data as unused by us and free it if the parent is also dead. */
	lock_acquire (&w->lock);
	ref_cnt = --w->ref_cnt;
	lock_release (&w->lock);

    if (ref_cnt == 0) // If parent process is already dead without waiting.
        free (w);
    else                 // If parent process is still alive.
        sema_up (&w->dead_sema);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the next thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	int argc = 0;
	char **argv = palloc_get_page (0);
	if (argv == NULL)
		goto done;

	/* Argument parsing. */
	argument_parse (file_name, &argc, argv);

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	if (t->running)
		file_close (t->running);

	/* Open executable file. */
	lock_acquire (&filesys_lock);
	t->running = file = filesys_open (file_name);
	if (file == NULL) {
		lock_release (&filesys_lock);
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	file_deny_write (file);
	lock_release (&filesys_lock);

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page, read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* Argument passing. */
	if (!argument_stack (if_, argc, argv))
		goto done;

	/* Debugging purpose. */
	// hex_dump (if_->rsp, if_->rsp, USER_STACK - if_->rsp, true);

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	palloc_free_page (argv);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf ("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

/* Load the segment from the file.
 * This function called when the first page fault occurs on address VA.
 * VA is available when calling this function. */
bool
lazy_load_segment (struct page *page, void *aux) {
	struct lazy_load_arg *arg = aux;

	struct file *file = arg->file;
	off_t ofs = arg->offset;
	size_t page_read_bytes = arg->page_read_bytes;

	free (aux);

	if (page_get_type (page) == VM_FILE) {
		struct file_page *file_page = &page->file;
		file_page->file = file;
		file_page->offset = ofs;
		file_page->page_read_bytes = page_read_bytes;
	}

	uint8_t *kpage = page->frame->kva;

	/* Load this page. */
	file_seek (file, ofs);
	if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
		palloc_free_page (kpage);
		return false;
	}
	memset (kpage + page_read_bytes, 0, PGSIZE - page_read_bytes);

	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Set up aux to pass information to the lazy_load_segment. */
		struct lazy_load_arg *aux = malloc (sizeof *aux);
		if (aux == NULL)
			return false;
		
		aux->size = sizeof *aux;
		aux->file = file;
		aux->offset = ofs;
		aux->page_read_bytes = page_read_bytes;

		/* Create the pending page object with initializer. */
		if (!vm_alloc_page_with_initializer (VM_ANON, upage, writable, lazy_load_segment, aux)) {
			free (aux);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* Map the stack on stack_bottom and claim the page immediately.
	 * and mark the page is stack. */
	if (vm_alloc_page (VM_ANON | VM_STACK, stack_bottom, true) && vm_claim_page (stack_bottom)) {
		/* If success, set the rsp accordingly. */
		if_->rsp = USER_STACK;
		success = true;
	}
	return success;
}
#endif /* VM */

/* Parse command line by tokenizing command line into arguments */
static void
argument_parse (char *file_name, int *argc_ptr, char **argv) {
	char *token, *save_ptr;

	for (token = strtok_r (file_name, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr))
        argv[(*argc_ptr)++] = token;

	argv[*argc_ptr] = token; // NULL
}

/* Pass the arguments to the user program by pushing to the user stack */
static bool
argument_stack (struct intr_frame *if_, int argc, char **argv) {
	char **argv_addr = palloc_get_page (0);
	if (argv_addr == NULL)
		return false;

	/* Argument(string). */
	for (int i = argc - 1; i >= 0; i--) {
		if_->rsp -= strlen (argv[i]) + 1;
		memcpy (if_->rsp, argv[i], strlen (argv[i]) + 1);
		argv_addr[i] = if_->rsp;
	}

	/* Padding(8 byte word-align). */
	while (if_->rsp % 8 != 0) {
		if_->rsp -= sizeof (uint8_t);
		*(uint8_t *) (if_->rsp) = 0x00;
	}

	/* Null pointer sentinel */
	if_->rsp -= sizeof (uintptr_t *);
	*(uintptr_t *) if_->rsp = argv[argc]; // NULL

	/* Argument's address. */
	for (int i = argc - 1; i >= 0; i--) {
		if_->rsp -= sizeof (uintptr_t *);
		*(uintptr_t *) if_->rsp = argv_addr[i];
	}

	/* Point rsi to argv (the address of argv[0]) and set %rdi to argc. */
	if_->R.rsi = if_->rsp; 
	if_->R.rdi = argc;

	/* Fake return address. */
	if_->rsp -= sizeof (uintptr_t *);
	*(uintptr_t *) if_->rsp = NULL;

	palloc_free_page (argv_addr);
	return true;
}

/* Get wait_status of child process that have TID. */
static struct wait_status *
get_child_wait_status (int child_tid) {
	struct list *children = &thread_current ()->children;
	struct wait_status *w;

	for (struct list_elem *e = list_begin (children); e != list_end (children); e = list_next (e)) {
		w = list_entry (e, struct wait_status, w_elem);
		if (w->tid == child_tid)
			return w;
	}

	return NULL;
}