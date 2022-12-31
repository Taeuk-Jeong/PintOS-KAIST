#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
int write (int fd, const void *buffer, unsigned length);

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
		case SYS_WRITE:
			f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
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

/* Writes SIZE(LENGTH) bytes from BUFFER to the open file FD. Returns the number of bytes actually written. */
int
write (int fd, const void *buffer, unsigned size) {
	/* Test를 위한 기본 기능 */
	if (fd == STDOUT_FILENO)
		putbuf (buffer, size);
	return size;
}