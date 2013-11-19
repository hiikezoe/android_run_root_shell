#include "ptmx.h"
#include "device_database/device_database.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int ptmx_fops_address;
} supported_device;

static supported_device supported_devices[] = {
  // F10D: Fujitsu added a method in struct file_operations
  { DEVICE_F10D_V21R48A,                    0xc09a60dc + 4 },

  { DEVICE_F11D_V24R40A,                    0xc1056998 },
  { DEVICE_ISW12K_010_0_3000,               0xc0dc0a10 },
  { DEVICE_SCL21_LJD,                       0xc0c71dc0 },
  { DEVICE_SC01E_LJ3,                       0xc10a5a48 },
  { DEVICE_SC04E_MDI,                       0xc1169808 },
  { DEVICE_SC04E_MF1,                       0xc1169848 },

  // ISW13F: Fujitsu added a method in struct file_operations
  { DEVICE_ISW13F_V69R51I,                  0xc09fc5fc + 4 },

  { DEVICE_IS17SH_01_00_04,                 0xc0edae90 },
  { DEVICE_SONYTABLET_S_RELEASE5A,          0xc06e4d18 },
  { DEVICE_SONYTABLET_P_RELEASE5A,          0xc06e6da0 },
  { DEVICE_SH04E_01_00_02,                  0xc0eed190 },
  { DEVICE_SH04E_01_00_03,                  0xc0eed190 },
  { DEVICE_SGP312_10_1_C_0_370,             0xc0d35ca8 },
  { DEVICE_SO01E_9_1_C_0_473,               0xc0d03208 },
  { DEVICE_SO02E_10_1_D_0_343,              0xc0e38620 },
  { DEVICE_SO03E_10_1_E_0_265,              0xc0d36aa8 },
  { DEVICE_SO03E_10_1_E_0_269,              0xc0d36aa8 },
  { DEVICE_SO04D_7_0_D_1_137,               0xc0c9d8a0 },
  { DEVICE_SO04E_10_1_1_D_0_179,            0xc0f392d8 },
  { DEVICE_SOL22_10_2_F_3_43,               0xc0e389b0 },
  { DEVICE_SOL21_9_1_D_0_395,               0xc0d030c8 },
  { DEVICE_HTL21_1_29_970_1,                0xc0d1d944 },
  { DEVICE_HTL22_1_05_970_1,                0xc0df467c },
  { DEVICE_HTL22_1_07_970_4,                0xc0df52bc },
  { DEVICE_HTX21_1_20_971_1,                0xc0ccc0b4 },
  { DEVICE_LG_E975_V10e,                    0xc0f9da70 },
  { DEVICE_LT26W_1265_3909_6_2_B_0_200,     0xc0cc3dc0 },
  { DEVICE_LT26I_1257_8080_6_2_B_0_211,     0xc0cc37e8 },
  { DEVICE_C6603_1269_5309_10_1_1_A_1_307,  0xc0d37488 },
  { DEVICE_C6603_1275_1562_10_1_1_A_1_253,  0xc0d37488 },
  { DEVICE_C5302_1272_1092_12_0_A_1_284,    0xc0e3bed8 },
  { DEVICE_N05E_A1000311,                   0xc0f58700 },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
get_ptmx_fops_address(void)
{
  int i;
  device_id_t device_id;

  device_id = detect_device();

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id) {
      return supported_devices[i].ptmx_fops_address;
    }
  }

  if (kallsyms_exist()) {
    unsigned long int address;

    address = kallsyms_get_symbol_address("ptmx_fops");
    if (address) {
      return address;
    }
  }

  print_reason_device_not_supported();
  return 0;
}
