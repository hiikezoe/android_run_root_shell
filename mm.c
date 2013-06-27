#include "kallsyms.h"
#include "mm.h"
#include "device_database/device_database.h"

unsigned long int
_get_remap_pfn_range_address(void)
{
  unsigned long int address = device_get_symbol_address(DEVICE_SYMBOL(remap_pfn_range));

  if (address) {
    return address;
  }

  print_reason_device_not_supported();

  return 0;
}

void *
get_remap_pfn_range_address(void)
{
  if (kallsyms_exist()) {
    return kallsyms_get_symbol_address("remap_pfn_range");
  }
  return (void*)_get_remap_pfn_range_address();
}

static unsigned long int kernel_phys_offset = 0;

void
set_kernel_phys_offset(unsigned long int offset)
{
  kernel_phys_offset = offset;
}

#define PAGE_SHIFT  12

int
ptmx_mmap(struct file *filep, struct vm_area_struct *vma)
{
  return remap_pfn_range(vma, vma->vm_start,
                         kernel_phys_offset >> PAGE_SHIFT,
                         vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

