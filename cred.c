#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cred.h"
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

bool
setup_creds_functions(void)
{
  if (kallsyms_exist()) {
    prepare_kernel_cred = kallsyms_get_symbol_address("prepare_kernel_cred");
    commit_creds = kallsyms_get_symbol_address("commit_creds");
  } else {
    get_creds_functions_addresses((void**)&prepare_kernel_cred, (void**)&commit_creds);
  }

  return prepare_kernel_cred && commit_creds;
}

