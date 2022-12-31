#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/file.h"
#include "filesys/filesys.h"

#define FDT_COUNT_LIMIT (1<<9) /* Limit of file descriptor index: 1<<12(PGSIZE, 4 KB) / 1<<3(size of pointer, 8 Bytes) */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
int write (int fd, const void *buffer, unsigned length);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

static void check_address (void *addr);
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

	/* The x86-64 convention for function return values is to place them in the RAX register.
	   System calls that return a value can do so by modifying the rax member of struct intr_frame. */
	switch (f->R.rax) {
		case SYS_HALT:
			halt ();
			break;
		case SYS_EXIT:
			exit (f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create (f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove (f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open (f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize (f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek (f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell (f->R.rdi);
			break;
		case SYS_CLOSE:
			close (f->R.rdi);
			break;
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
	struct thread *t = thread_current ();
	printf ("%s: exit(%d)\n", t->name, status);
	thread_exit ();
}

/* Creates a new file called FILE initially INITIAL_SIZE bytes in size. Returns true if successful, false otherwise. */
bool
create (const char *file, unsigned initial_size) {
	check_address (file);
	return filesys_create (file, initial_size);
}

/* Deletes the file called FILE. Returns true if successful, false otherwise.
   A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. */
bool
remove (const char *file) {
	check_address (file);
	return filesys_remove (file);
}

/* Opens the file called FILE. Returns a nonnegative integer handle called a "file descriptor" (fd),
 * or -1 if the file could not be opened. File descriptors numbered 0 and 1 are reserved for the console:
 * fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. */
int
open (const char *file) {
	check_address (file);

	struct file *f = filesys_open (file);

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
		return;
	
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
	struct thread *t = thread_current();
	if (addr == NULL || !is_user_vaddr (addr) || pml4_get_page (t->pml4, addr) == NULL)
			exit(-1);
}


/* Add file(FILE) to file descriptor table of running thread */
static int
fdt_add_fd (struct file *file) {
	struct thread *t = thread_current ();
	struct file **fdt = t->fdt;
	int fd = t->fdx;

	/* When FDT is full. */
	if (fd == FDT_COUNT_LIMIT)
		return -1;

	/* Set file descriptor. */
	fdt[fd] = file;
	
	/* Find FD of next-open file(minimum usable fd). */
	for (; t->fdx < FDT_COUNT_LIMIT; t->fdx++)
		if (fdt[t->fdx] == NULL)
			break;

	return fd;
}

/* Get pointer of file object from file descriptor(FD) */
static struct file*
fdt_get_file (int fd) {
	struct thread *t = thread_current ();

	if (!(0 <= fd && fd < FDT_COUNT_LIMIT))
		return NULL;

	return t->fdt[fd];
}

/* When file is closed, set 0 at file descriptor entry at index fd */
static void
fdt_remove_fd (int fd) {
	struct thread *t = thread_current ();

	if (!(0 <= fd && fd < FDT_COUNT_LIMIT))
		return;

	t->fdt[fd] = NULL;

	/* Reset minimum usable fd if needed */
	if (t->fdx > fd)
		t->fdx = fd;
}