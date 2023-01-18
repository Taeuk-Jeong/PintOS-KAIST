#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include "lib/stdio.h"
#include "lib/kernel/stdio.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/string.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "vm/vm.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt (void);
void exit (int status);
tid_t fork (const char *thread_name);
int exec (const char *file);
int wait (tid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int dup2 (int oldfd, int newfd);
#ifdef VM
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);
#endif

static void check_address (void *addr);
#ifdef VM
static void check_buffer (void *buffer, unsigned size);
static bool check_mmap (void *addr, size_t length, int fd, struct file *file, off_t offset);
#endif
static int fdt_add_fd (struct file *file);
static struct file* fdt_get_file (int fd);
static void fdt_remove_fd (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	/* When the system call handler syscall_handler() gets control,
	 * the system call number is in the rax, and arguments are passed
	 * with the order %rdi, %rsi, %rdx, %r10, %r8, and %r9. */

#ifdef VM
	/* Store userland stack pointer. */
	thread_current ()->rsp = f->rsp;
#endif

	/* The x86-64 convention for function return values is to place them in the RAX register.
	   System calls that return a value can do so by modifying the rax member of struct intr_frame. */
	switch (f->R.rax) {
		case SYS_HALT:        /* Halt the operating system. */
			halt ();
			break;
		case SYS_EXIT:        /* Terminate this process. */
			exit (f->R.rdi);
			break;
		case SYS_FORK:        /* Clone current process. */
			memcpy (&thread_current ()->user_if, f, sizeof (struct intr_frame));
			f->R.rax = fork (f->R.rdi);
			break;
		case SYS_EXEC:        /* Switch current process. */
			if (exec (f->R.rdi) == -1)
				exit (-1);
			break;
		case SYS_WAIT:        /* Wait for a child process to die. */
			f->R.rax = wait (f->R.rdi);
			break;
		case SYS_CREATE:      /* Create a file. */
			f->R.rax = create (f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:      /* Delete a file. */
			f->R.rax = remove (f->R.rdi);
			break;
		case SYS_OPEN:        /* Open a file. */
			f->R.rax = open (f->R.rdi);
			break;
		case SYS_FILESIZE:    /* Obtain a file's size. */
			f->R.rax = filesize (f->R.rdi);
			break;
		case SYS_READ:        /* Read from a file. */
			f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:       /* Write to a file. */
			f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:        /* Change position in a file. */
			seek (f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:        /* Report current position in a file. */
			f->R.rax = tell (f->R.rdi);
			break;
		case SYS_CLOSE:       /* Close a file. */
			close (f->R.rdi);
			break;
		case SYS_DUP2:        /* Duplicate the file descriptor. */
			f->R.rax = dup2 (f->R.rdi, f->R.rsi);
			break;
#ifdef VM
		case SYS_MMAP:        /* Map a file into memory. */
			f->R.rax = mmap (f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:      /* Remove a memory mapping. */
			munmap (f->R.rdi);
			break;
#endif
		default:
			exit (-1);
			break;
	}
}

/* Terminates PintOS */
void
halt (void) {
	power_off ();
}

/* Terminates the current user program, returning STATUS to the kernel. 
 * If the process's parent waits for it, this is the status that will be returned.
 * Conventionally, a status of 0 indicates success and nonzero values indicate errors. */
void
exit (int status) {
	/* Save the exit code in the shared data. */
	struct wait_status *w = thread_current ()->wait_status;
	w->exit_status = status;
	sema_up (&w->load_sema); // If fork(load) is failed, wake up parent process.
	printf ("%s: exit(%d)\n", thread_name (), status);
	thread_exit ();
}

/* Creates a new file called FILE initially INITIAL_SIZE bytes in size. Returns true if successful, false otherwise. */
bool
create (const char *file, unsigned initial_size) {
	check_address (file);

	filesys_acquire ();
	bool result = filesys_create (file, initial_size);
	filesys_release ();

	return result;
}

/* Create new process which is the clone of current process with the name THREAD_NAME. */
tid_t
fork (const char *thread_name) {
	check_address (thread_name);
	return process_fork (thread_name, NULL);
}

/* Change current process to the executable whose name is given in CMD_LINE,
 * passing any given arguments. This never returns if successful.
 * Otherwise the process terminates with exit state -1, if the program cannot load or run for any reason.
 * This function does not change the name of the thread that called exec. Please note that file descriptors remain open across an exec call. */
int
exec (const char *cmd_line) {
	check_address (cmd_line);

	char *fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return -1;
	strlcpy (fn_copy, cmd_line, PGSIZE);

	if (process_exec (fn_copy) < 0)
		return -1;
}

/* Wait for termination of child process whose process id is TID(PID) */
int
wait (tid_t tid) {
	return process_wait (tid);
}

/* Deletes the file called FILE. Returns true if successful, false otherwise.
   A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. */
bool
remove (const char *file) {
	check_address (file);

	filesys_acquire ();
	bool result = filesys_remove (file);
	filesys_release ();

	return result;
}

/* Opens the file called FILE. Returns a nonnegative integer handle called a "file descriptor" (fd),
 * or -1 if the file could not be opened. File descriptors numbered 0 and 1 are reserved for the console:
 * fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. */
int
open (const char *file) {
	check_address (file);

	filesys_acquire ();
	struct file *f = filesys_open (file);
	filesys_release ();
	if (f == NULL)
		return -1;

	int fd = fdt_add_fd (f);
	if (fd == -1)
		file_close (f);

	return fd;
}

/* Returns the size, in bytes, of the file open as FD. */
int
filesize (int fd) {
	struct file *f = fdt_get_file (fd);

	if (f == NULL)
		return -1;

	return file_length (f);
}

/* Reads SIZE(LENGTH) bytes from the file open as FD into BUFFER. Returns the number of bytes actually read (0 at end of file),
   or -1 if the file could not be read (due to a condition other than end of file). fd 0 reads from the keyboard using input_getc(). */
int
read (int fd, void *buffer, unsigned size) {
	uint8_t key;
	uint8_t *buffer_read = buffer; // Type casting
	int size_read;
	struct file *f;

	check_address (buffer);
#ifdef VM
	check_buffer (buffer, size);
#endif

	if (fd == STDIN_FILENO) {
		for (size_read = 0; size_read < size; size_read++) {
			key = input_getc ();
			*(buffer_read++) = key;

			if (key == '\0')
				break;
		}
	} else if (fd == STDOUT_FILENO) {
		return -1;
	} else {
		f = fdt_get_file (fd);

		if (f == NULL)
			return -1;

		size_read = file_read (f, buffer, size);
	}

	return size_read;
}

/* Writes SIZE(LENGTH) bytes from BUFFER to the open file FD. Returns the number of bytes actually written. */
int
write (int fd, const void *buffer, unsigned size) {
	int size_written;
	struct file *f;

	check_address (buffer);

	if (fd == STDIN_FILENO) {
		return -1;
	} else if (fd == STDOUT_FILENO) {
		putbuf (buffer, size);
		return size;
	} else {
		f = fdt_get_file (fd);

		if (f == NULL)
			return -1;

		size_written = file_write (f, buffer, size);
	}

	return size_written;
}

/* Changes the next byte to be read or written in open file FD to POSITION,
   expressed in bytes from the beginning of the file (Thus, a position of 0 is the file's start). */
void
seek (int fd, unsigned position) {
	struct file *f = fdt_get_file (fd);

	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || f == NULL)
		return;
	
	file_seek (f, position);
}

/* Returns the position of the next byte to be read or written in open file FD, expressed in bytes from the beginning of the file. */
unsigned
tell (int fd) {
	struct file *f = fdt_get_file (fd);

	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || f == NULL)
		return -1;

	return file_tell (f);
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors,
   as if by calling this function for each one. */
void
close (int fd) {
	struct file *f = fdt_get_file (fd);

	if (f == NULL)
		return;

	file_close (f);
	fdt_remove_fd (fd);
}

int
dup2 (int oldfd, int newfd) {
	printf ("Need to implementation.\n");
	exit (-1);
}

#ifdef VM
void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	struct file *file = fdt_get_file (fd);

	if(!check_mmap (addr, length, fd, file, offset))
		return NULL;

	return do_mmap (addr, length, writable, file, offset);
}

void
munmap (void *addr) {
	do_munmap (addr);
}
#endif

#ifndef VM
/* Check validation of the pointers in the parameter list.
 * - These pointers must point to user area, not kernel area.
 * - If these pointers don't point the valid address, it is page fault.
 * 
 * Invalid pointers
 * - A null pointer
 * - A pointer to kernel virtual memory address space
 * - A pointer to unmapped virtual memory */
static void
check_address (void *addr) {
	struct thread *t = thread_current ();
	if (addr == NULL || !is_user_vaddr (addr) || pml4_get_page (t->pml4, addr) == NULL)
		exit(-1);
}
#else
static void
check_address (void *addr) {
	struct thread *t = thread_current ();
	if (addr == NULL || !is_user_vaddr (addr))
		exit(-1);
}

static void
check_buffer (void *buffer, unsigned size) {
	struct thread *t = thread_current ();

	for (void *upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE) {
		struct page *p = spt_find_page (&t->spt, upage);
		if (p && !p->writable)
			exit(-1);
	}
}

static bool
check_mmap (void *addr, size_t length, int fd, struct file *file, off_t offset) {
	/* The file descriptors representing console input and output are not mappable. */
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || file == NULL)
		return NULL;

	/* A call to mmap may fail if the file opened as fd has a length of zero bytes. It must fail if addr is not page-aligned. */
	if (file_length (file) == 0 || pg_ofs (addr))
		return false;

	/* If addr is 0, it must fail, because some Pintos code assumes virtual page 0 is not mapped.
	 * mmap should also fail when length is zero.*/
	if (addr == 0 || length == 0)
		return false;

	/* Tries to mmap an invalid offset, which must either fail silently or terminate the process with exit code -1. */
	if (offset % PGSIZE != 0)
		return false;

	/* Verifies that mapping over the kernel is disallowed. */
	if (!is_user_vaddr (addr) || !is_user_vaddr (addr + length) || !is_user_vaddr (length))
		return false;

	/* It must fail if the range of pages mapped overlaps any existing set of mapped pages,
	 * including the stack or pages mapped at executable load time. */
	for (void *upage = addr; upage < addr + length; upage += PGSIZE)
		if (spt_find_page (&thread_current ()->spt, upage))
			return false;

	return true;
}
#endif

/* Add file(FILE) to file descriptor table of running thread */
static int
fdt_add_fd (struct file *file) {
	struct list *fd_table = &thread_current ()->fd_table;
	struct fd_str *fd_str;

	/* Allocate file descriptor. */
	fd_str = calloc (1, sizeof *fd_str);
	if (fd_str == NULL)
		return -1;

	/* Set file descriptor. */
	if (list_empty (fd_table))
		fd_str->fd = 2;
	else
		fd_str->fd = list_entry (list_back (fd_table), struct fd_str, f_elem)->fd + 1;

	fd_str->file = file;
	list_push_back (fd_table, &fd_str->f_elem);

	return fd_str->fd;
}

/* Get pointer of file object from file descriptor(FD) */
static struct file*
fdt_get_file (int fd) {
	struct list *fd_table = &thread_current ()->fd_table;
	struct fd_str *fd_str;

	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
		return NULL;

	for (struct list_elem *e = list_begin (fd_table); e != list_end (fd_table); e = list_next (e)) {
		fd_str = list_entry (e, struct fd_str, f_elem);
		if (fd_str->fd == fd)
			return fd_str->file;
		else if (fd_str->fd > fd)
			return NULL;
	}

	return NULL;
}

/* When file is closed, set 0 at file descriptor entry at index fd */
static void
fdt_remove_fd (int fd) {
	struct list *fd_table = &thread_current ()->fd_table;
	struct fd_str *fd_str;

	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
		return;

	for (struct list_elem *e = list_begin (fd_table); e != list_end (fd_table); e = list_next (e)) {
		fd_str = list_entry (e, struct fd_str, f_elem);
		if (fd_str->fd == fd) {
			list_remove (e);
			free (fd_str);
			return;
		} else if (fd_str->fd > fd) {
			return;
		}
	}
}