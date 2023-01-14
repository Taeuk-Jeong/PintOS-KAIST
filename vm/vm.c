/* vm.c: Generic interface for virtual memory objects. */

#include "threads/mmu.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "vm/vm.h"
#include "vm/anon.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"

static struct lock vm_lock;

/* hash function and a comparison function using va as the key. */
static unsigned page_hash (const struct hash_elem *, void *aux);
static bool page_less (const struct hash_elem *, const struct hash_elem *, void *aux);
static bool install_page (void *upage, void *kpage, bool writable);
static void page_destructor (struct hash_elem *e, void *aux UNUSED);

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
	lock_init (&vm_lock);
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

	struct supplemental_page_table *spt = &thread_current ()->spt;
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

	lock_acquire (&vm_lock);
	struct list_elem *e = hash_insert (&spt->pages, &page->hash_elem);
	lock_release (&vm_lock);

	if (e == NULL)
		success = true;

	return success;
}

/* Delete PAGE from spt and dealloc PAGE. */
void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	lock_acquire (&vm_lock);
	struct list_elem *e = hash_delete (&spt->pages, &page->hash_elem);
	lock_release (&vm_lock);

	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
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
	struct frame *frame = malloc (sizeof *frame);

	ASSERT (frame != NULL);
	
	/* Gets a new physical page from the user pool by calling palloc_get_page.
	 * When successfully got a page from the user pool, also allocates a frame,
	 * initialize its members, and returns it. */
	void *kva = palloc_get_page (PAL_USER);
	if (kva == NULL) {
		PANIC ("todo");
		free (frame);
		frame = vm_evict_frame ();
	} else {
		frame->kva = kva;
	}

	frame->page = NULL;
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;

	/* First checks if it is a valid page fault. By valid, we mean the fault that accesses invalid.
	 * If the supplemental page table indicates that the user process should not expect any data
	 * at the address it was trying to access, or if the page lies within kernel virtual memory,
	 * or if the access is an attempt to write to a read-only page, then the access is invalid.
	 * Any invalid access terminates the process and thereby frees all of its resources. */
	if (user && !is_user_vaddr (addr))
		return false;

	// if (!not_present) //check
	// 	return false;

	// if (write && !page->writable) //check
	// 	return false;

	page = spt_find_page (&thread_current ()->spt, addr);
	if (page == NULL)
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
	if (install_page (page->va, frame->kva, page->writable))
		return swap_in (page, frame->kva);
	else
		return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init (&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	hash_first (&i, &src->pages);
	while (hash_next (&i)) {
		struct page *p = hash_entry (hash_cur (&i), struct page, hash_elem);
		enum vm_type type = VM_TYPE (p->operations->type);

		if (type == VM_UNINIT) {
			size_t size = *((size_t *) p->uninit.aux);
			void *aux = malloc (size);
			memcpy (aux, p->uninit.aux, size);

			if (!vm_alloc_page_with_initializer (page_get_type (p), p->va, p->writable, p->uninit.init, aux))
				return false;
		} else {
			if (!vm_alloc_page (type, p->va, p->writable) || !vm_claim_page (p->va))
				return false;

			struct page *p_child = spt_find_page (dst, p->va);
			memcpy (p_child->frame->kva, p->frame->kva, PGSIZE);
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* Destroy all the supplemental_page_table hold by thread. */
	hash_destroy (&spt->pages, page_destructor);

	/* TODO: Writeback all the modified contents to the storage. */
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
	destroy (page);
	free (page);
}