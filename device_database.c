#include <stdio.h>
#include <sys/system_properties.h>
#include "device_database.h"

typedef struct _supported_device {
  int device_id;
  const char *device;
  const char *build_id;
  const char *check_property_name;
  const char *check_property_value;
} supported_device;

static supported_device supported_devices[] = {
  { DEVICE_F10D_V21R48A,            "F-10D",            "V21R48A"            },
  { DEVICE_F11D_V24R40A,            "F-11D",            "V24R40A"            },
  { DEVICE_HTL21_JRO03C,            "HTL21",            "JRO03C"             "ro.aa.romver",                  "1.29.970.1" },
  { DEVICE_HTL22_JZO54K,            "HTL22",            "JZO54K"             "ro.aa.romver",                  "1.05.970.1" },
  { DEVICE_HTX21_JRO03C,            "HTX21",            "JRO03C"             "ro.aa.romver",                  "1.20.971.1" },
  { DEVICE_IS17SH_01_00_04,         "IS17SH",           "01.00.04"           },
  { DEVICE_ISW12K_010_0_3000,       "URBANO PROGRESSO", "010.0.3000"         },
  { DEVICE_ISW13F_V69R51I,          "ISW13F",           "V69R51I"            },
  { DEVICE_L01D_V20d,               "L-01D",            "IMM76D",            "ro.build.version.incremental",  "L01D-V20d.1e516ca5db" },
  { DEVICE_L02E_V10c,               "L-02E",            "IMM76L",            "ro.build.version.incremental",  "L02E10c.1354024955" },
  { DEVICE_L02E_V10e,               "L-02E",            "IMM76L",            "ro.build.version.incremental",  "L02E10e.1366099439" },
  { DEVICE_L06D_V10k,               "L-06D",            "IMM76D",            "ro.build.version.incremental",  "L06DV10k.4821c158" },
  { DEVICE_N05E_A1000311,           "N05E",             "A1000311"           },
  { DEVICE_SC04E_OMUAMDI,           "SC-04E"            "JDQ39.SC04EOMUAMDI" },
  { DEVICE_SCL21_KDALJD,            "SCL21",            "IMM76D.SCL21KDALJD" },
  { DEVICE_SH04E_01_00_02,          "SH-04E",           "01.00.02"           },
  { DEVICE_SH04E_01_00_03,          "SH-04E",           "01.00.03"           },
  { DEVICE_SO04D_7_0_D_1_137,       "SO-04D",           "7.0.D.1.137"        },
  { DEVICE_SO05D_7_0_D_1_137,       "SO-05D",           "7.0.D.1.137"        },
  { DEVICE_SOL21_9_1_D_0_395,       "SOL21",            "9.1.D.0.395"        },
  { DEVICE_SONYTABLET_P_RELEASE5A,  "Sony Tablet P",    "TISU0144"           },
  { DEVICE_SONYTABLET_S_RELEASE5A,  "Sony Tablet S",    "TISU0143"           },
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

device_id_t
detect_device(void)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];
  char check_property_value[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
      if (!supported_devices[i].check_property_name) {
        return supported_devices[i].device_id;
      }

      __system_property_get(supported_devices[i].check_property_name, check_property_value);

      if (!strcmp(check_property_value, supported_devices[i].check_property_value)) {
        return supported_devices[i].device_id;
      }
    }
  }

  return DEVICE_NOT_SUPPORTED;
}

void
print_reason_device_not_supported(void)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device)) {
      char check_property_value[PROP_VALUE_MAX];

      if (!supported_devices[i].check_property_name) {
        break;
      }

      __system_property_get(supported_devices[i].check_property_name, check_property_value);

      printf("%s (%s %s) is not supported.\n", device, build_id, check_property_value);
      return;
    }
  }

  printf("%s (%s) is not supported.\n", device, build_id);
}
