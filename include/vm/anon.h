#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"

struct page;
enum vm_type;

struct anon_page {
    enum vm_type type;        /* Page type that include VM_MARKER. */
    disk_sector_t sec_no;     /* Index of a disk sector that save page swapped out. */
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
