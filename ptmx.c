#include "ptmx.h"
#include "device_database/device_database.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int ptmx_fops_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEVICE_F11D_V24R40A,           0xc1056998 },
  { DEVICE_ISW12K_010_0_3000,      0xc0dc0a10 },
  { DEVICE_SCL21_KDALJD,           0xc0c71dc0 },

  // ptmx_fops is 0xc09fc5fc but it doesn't work (kernel 2.6.39.4)
  { DEVICE_ISW13F_V69R51I,         0xc09fc5fc + 4 },

  { DEVICE_IS17SH_01_00_04,        0xc0edae90 },
  { DEVICE_SONYTABLET_S_RELEASE5A, 0xc06e0d18 },
  { DEVICE_SONYTABLET_P_RELEASE5A, 0xc06e2f20 },
  { DEVICE_SH04E_01_00_02,         0xc0eed190 },
  { DEVICE_SOL21_9_1_D_0_395,      0xc0d030c8 },
  { DEVICE_HTL21_JRO03C,           0xc0d1d944 },
  { DEVICE_N05E_A1000311,          0xc0f58700 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
get_ptmx_fops_address(void)
{
  int i;
  device_id_t device_id;

  device_id = detect_device();

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id){
      return supported_devices[i].ptmx_fops_address;
    }
  }

  print_reason_device_not_supported();

  return 0;
}
