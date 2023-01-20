/* vm.c: Generic interface for virtual memory objects. */

#include "threads/mmu.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "vm/vm.h"
#include "vm/anon.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"

/* Lock(mutex) for modifying spt(hash table). */
static struct lock pages_lock;

/* Lock(mutex) for frame table. */
struct lock frames_lock;

/* Frame table. */
static struct list frames;

/* hash function and a comparison function using va as the key. */
static unsigned page_hash (const struct hash_elem *, void *aux);
static bool page_less (const struct hash_elem *, const struct hash_elem *, void *aux);
static bool install_page (void *upage, void *kpage, bool writable);
static void page_destructor (struct hash_elem *e, void *aux);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init (&pages_lock);
	lock_init (&frames_lock);
	list_init (&frames);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE (type) != VM_UNINIT)

	struct thread *t = thread_current ();
	struct supplemental_page_table *spt = &t->spt;
	bool success = false;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* Create the "uninit" page struct by calling uninit_new,
		 * fetch the initializer according to the VM type. */
		struct page *page = malloc (sizeof *page);
		if (page == NULL)
			goto done;

		switch (VM_TYPE (type)) {
			case VM_ANON:
				uninit_new (page, upage, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new (page, upage, init, type, aux, file_backed_initializer);
				break;
#ifdef EFILESYS  /* For project 4 */
			case VM_PAGE_CACHE:
				uninit_new (page, upage, init, type, aux, page_cache_initializer);
				break;
#endif
			default:
				NOT_REACHED ();
		}
		page->writable = writable;
		page->owner = t;

		/* Insert the page into the spt. */
		if (!spt_insert_page (spt, page)) {
			free (page);
			goto done;
		}
		success = true;
	}
done:
	return success;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
  struct page page;
  struct hash_elem *e;

  page.va = pg_round_down (va);
  e = hash_find (&spt->pages, &page.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	bool success = false;

	lock_acquire (&pages_lock);
	struct list_elem *e = hash_insert (&spt->pages, &page->hash_elem);
	lock_release (&pages_lock);

	if (e == NULL)
		success = true;

	return success;
}

/* Delete PAGE from spt and dealloc PAGE. */
void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	lock_acquire (&pages_lock);
	struct list_elem *e = hash_delete (&spt->pages, &page->hash_elem);
	lock_release (&pages_lock);

	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	if (list_empty (&frames))
		PANIC ("vm_get_victim failed");

	/* FIFO policy for eviction(page replacement). */
	lock_acquire (&frames_lock);
	struct frame *frame = list_entry (list_pop_back (&frames), struct frame, f_elem);
	lock_release (&frames_lock);

	return frame;
}

/* Evict(swap out) one page and return the corresponding(evicted) frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	if (victim && swap_out (victim->page))
		return victim;
	else
		return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;

	/* Gets a new physical page from the user pool by calling palloc_get_page.
	 * When successfully got a page from the user pool, also allocates a frame,
	 * initialize its members, and returns it. */
	void *kva = palloc_get_page (PAL_USER);
	if (kva == NULL) {
		frame = vm_evict_frame ();
		if (frame == NULL)
			PANIC ("Swap out failed");
	} else {
		frame = malloc (sizeof *frame);
		ASSERT (frame != NULL);
		frame->kva = kva;
	}

	frame->page = NULL;
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void *stack_bottom = pg_round_down (addr);

	/* Limit the stack size to be 1MB at maximum. */
	if (stack_bottom >= ((uint8_t *) USER_STACK) - (1<<20))
		vm_alloc_page (VM_ANON | VM_STACK, stack_bottom, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present UNUSED) {
	struct thread *t = thread_current ();
	struct supplemental_page_table *spt = &t->spt;
	struct page *page = NULL;

	/* First checks if it is a valid page fault. By valid, we mean the fault that accesses invalid.
	 * If the supplemental page table indicates that the user process should not expect any data
	 * at the address it was trying to access, or if the page lies within kernel virtual memory,
	 * or if the access is an attempt to write to a read-only page, then the access is invalid.
	 * Any invalid access terminates the process and thereby frees all of its resources. */
	if (!is_user_vaddr (addr) || !not_present)
		return false;

	/* Stack growth in user or kernel context. */
	uintptr_t rsp = user ? f->rsp : t->rsp;
	if (USER_STACK > addr && addr >= (uint8_t *) rsp - sizeof (uintptr_t *))
		vm_stack_growth (addr);

	page = spt_find_page (spt, addr);
	if (page == NULL)
		return false;

	if (write && !page->writable)
		return false;

	/* If it is a bogus fault, you load some contents into the page and return control to the user program.
	 * There are three cases of bogus page fault: lazy-loaded, swaped-out page, and write-protected page(extra). */
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = spt_find_page (&thread_current ()->spt, va);
	if (page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* Insert page table entry to map page's VA to frame's PA. */
	if (install_page (page->va, frame->kva, page->writable)) {
		lock_acquire (&frames_lock);
		list_push_front (&frames, &frame->f_elem);
		lock_release (&frames_lock);
		
		return swap_in (page, frame->kva);
	} else {
		return false;
	}
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init (&spt->pages, page_hash, page_less, NULL);
	list_init (&spt->mmap_file_list);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct thread *t = thread_current ();

	struct hash_iterator i;
	hash_first (&i, &src->pages);
	while (hash_next (&i)) {
		struct page *p_src = hash_entry (hash_cur (&i), struct page, hash_elem);
		enum vm_type type = VM_TYPE (p_src->operations->type);

		if (type == VM_UNINIT) {
			size_t size = *((size_t *) p_src->uninit.aux);
			void *aux = malloc (size);
			if (aux == NULL)
				return false;

			memcpy (aux, p_src->uninit.aux, size);

			type = page_get_type (p_src);
			if (type == VM_ANON)
				((struct lazy_load_arg *) aux)->file = t->running;

			if (!vm_alloc_page_with_initializer (type, p_src->va, p_src->writable, p_src->uninit.init, aux))
				return false;
		} else {
			if (!vm_alloc_page (type, p_src->va, p_src->writable) || !vm_claim_page (p_src->va))
				return false;

			struct page *p_dst = spt_find_page (dst, p_src->va);
			if (p_dst == NULL)
				return false;

			memcpy (p_dst->frame->kva, p_src->frame->kva, PGSIZE);
		}
	}

	struct list *mf_list_src = &src->mmap_file_list;
	struct list *mf_list_dst = &dst->mmap_file_list;
	struct mmap_file *mf_src, *mf_dst;
	struct list *mp_list_src, *mp_list_dst;

	for (struct list_elem *mf_e = list_begin (mf_list_src); mf_e != list_end (mf_list_src); mf_e = list_next (mf_e)) {
		mf_src = list_entry (mf_e, struct mmap_file, mf_elem);
		mf_dst = malloc (sizeof *mf_dst);
		if (mf_dst == NULL)
			return false;

		struct file *file = file_reopen (mf_src->file);
		if (file == NULL)
			return false;

		mf_dst->addr = mf_src->addr;
		mf_dst->file = file;
		list_push_back (mf_list_dst, &mf_dst->mf_elem);

		mp_list_src = &mf_src->mmap_page_list;
		mp_list_dst = &mf_dst->mmap_page_list;
		list_init (mp_list_dst);

		for (struct list_elem *mp_e = list_begin (mp_list_src); mp_e != list_end (mp_list_src); mp_e = list_next (mp_e)) {
			struct page *p_src = list_entry (mp_e, struct page, mp_elem);
			struct page *p_dst = spt_find_page (dst, p_src->va);
			if (p_dst == NULL)
				return false;

			enum vm_type type = VM_TYPE (p_dst->operations->type);

			if (type == VM_UNINIT)
				((struct lazy_load_arg *) p_dst->uninit.aux)->file = file;
			else if (type == VM_FILE)
				p_dst->file.file = file;

			list_push_back (mp_list_dst, &p_dst->mp_elem);
		}
	}

	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	struct hash *pages = &spt->pages;

	/* Threads-tests. */
	if (!pages->buckets)
		return;

	/* All mappings are implicitly unmapped when a process exits. */
	struct list *mf_list = &spt->mmap_file_list;
	while (!list_empty (mf_list)) {
		struct mmap_file *m = list_entry (list_begin (mf_list), struct mmap_file, mf_elem);
		munmap (m->addr);
	}

	/* Destroy all the supplemental_page_table hold by thread. */
	hash_destroy (pages, page_destructor);
}

/* Returns a hash value for page p. */
static unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry (p_, struct page, hash_elem);
	return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
static bool
page_less (const struct hash_elem *a_,
		   const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry (a_, struct page, hash_elem);
	const struct page *b = hash_entry (b_, struct page, hash_elem);

	return a->va < b->va;
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

static void
page_destructor (struct hash_elem *e, void *aux UNUSED) {
	struct page *page = hash_entry (e, struct page, hash_elem);
	vm_dealloc_page (page);
}