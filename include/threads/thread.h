#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	int priority_base;                  /* Base priority. */
	struct lock *wait_on_lock;          /* Lock that have to be acquired. */

	int64_t wakeup_tick;                /* Ticks for wake up (local ticks). */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

	struct list donations;              /* List of donors. */
	struct list_elem d_elem;            /* List element of donations. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */

	struct list fd_table;               /* File descriptor table(linked list of structure 'fd_str'). */

	struct file *running;               /* Running file. */

	struct intr_frame user_if;          /* User context. */
	struct wait_status *wait_status;    /* This process’s completion state. */
	struct list children;               /* Completion status of children. */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt; /* Supplemental page table. */
	uintptr_t rsp;                      /* Stack pointer. */
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* File descriptor structure */
struct fd_str {
	int fd;                             /* File descriptor. */
	struct file *file;                  /* An open file. */
	struct list_elem f_elem;            /* fd_table list element. */
};

/* Data shared by parent and child process. */
struct wait_status {
	struct list_elem w_elem;            /* ‘children’ list element. */
	struct lock lock;                   /* Protects ref_cnt. */
	int ref_cnt;                        /* 2 = child and parent both alive, 1 = either child or parent alive, 0 = child and parent both dead. */
	tid_t tid;                          /* Child thread id. */
	int exit_status;                    /* Child exit code, if dead. */
	struct semaphore load_sema;         /* For waiting for completion of loading. */
	struct semaphore dead_sema;         /* 1 = child dead, 0 = child alive. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

int64_t get_global_ticks (void);
void set_global_ticks (int64_t);
void thread_sleep (int64_t);
void thread_awake (int64_t);
bool cmp_priority (const struct list_elem *, const struct list_elem *, void *aux);
void refresh_priority (void);

#endif /* threads/thread.h */
