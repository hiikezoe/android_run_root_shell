#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/system_properties.h>

#include "ptmx.h"

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

unsigned long int
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
