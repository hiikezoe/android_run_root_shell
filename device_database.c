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
  { DEVICE_C5302_1272_1092_12_0_A_1_284, "C5302",       "12.0.A.1.284",      "ro.semc.version.cust",          "1272-1092" },
  { DEVICE_C6603_1269_5309_10_1_1_A_1_307, "C6603",     "10.1.1.A.1.307",    "ro.semc.version.cust",          "1270-6704" },
  { DEVICE_C6603_1275_1562_10_1_1_A_1_253, "C6603",     "10.1.1.A.1.253",    "ro.semc.version.cust",          "1275-1562" },
  { DEVICE_C6503_1266_7597_10_3_A_0_423, "C6503",		"10.3.A.0.423",      "ro.semc.version.sw",          "1266-7597" },
  { DEVICE_F10D_V21R48A,            "F-10D",            "V21R48A"            },
  { DEVICE_F11D_V24R40A,            "F-11D",            "V24R40A"            },
  { DEVICE_HTL21_1_29_970_1,        "HTL21",            "JRO03C"             "ro.aa.romver",                  "1.29.970.1" },
  { DEVICE_HTL22_1_05_970_1,        "HTL22",            "JZO54K"             "ro.aa.romver",                  "1.05.970.1" },
  { DEVICE_HTL22_1_07_970_4,        "HTL22",            "JZO54K"             "ro.aa.romver",                  "1.07.970.4" },
  { DEVICE_HTX21_1_20_971_1,        "HTX21",            "JRO03C"             "ro.aa.romver",                  "1.20.971.1" },
  { DEVICE_IS17SH_01_00_04,         "IS17SH",           "01.00.04"           },
  { DEVICE_ISW12K_010_0_3000,       "URBANO PROGRESSO", "010.0.3000"         },
  { DEVICE_ISW13F_V69R51I,          "ISW13F",           "V69R51I"            },
  { DEVICE_L01D_V20d,               "L-01D",            "IMM76D",            "ro.build.version.incremental",  "L01D-V20d.1e516ca5db" },
  { DEVICE_L02E_V10c,               "L-02E",            "IMM76L",            "ro.build.version.incremental",  "L02E10c.1354024955" },
  { DEVICE_L02E_V10e,               "L-02E",            "IMM76L",            "ro.build.version.incremental",  "L02E10e.1366099439" },
  { DEVICE_L06D_V10k,               "L-06D",            "IMM76D",            "ro.build.version.incremental",  "L06DV10k.4821c158" },
  { DEVICE_LG_E975_V10e,            "LG-E975",          "JZO54K",            "ro.build.version.incremental",  "E97510e.1366300274" },
  { DEVICE_LT26I_1257_8080_6_2_B_0_211, "LT26i",        "6.2.B.0.211",       "ro.semc.version.cust",          "1257-8080" },
  { DEVICE_LT26W_1265_3909_6_2_B_0_200, "LT26w",        "6.2.B.0.200",       "ro.semc.version.sw",            "1265-3909" },
  { DEVICE_N05E_A1000311,           "N05E",             "A1000311"           },
  { DEVICE_SC01E_LJ3,               "SC-01E",           "IMM76D.SC01EOMALJ3" },
  { DEVICE_SC04E_MDI,               "SC-04E",           "JDQ39.SC04EOMUAMDI" },
  { DEVICE_SC04E_MF1,               "SC-04E",           "JDQ39.SC04EOMUAMF1" },
  { DEVICE_SCL21_LJD,               "SCL21",            "IMM76D.SCL21KDALJD" },
  { DEVICE_SGP312_10_1_C_0_370,     "SGP312",           "10.1.C.0.370"       },
  { DEVICE_SH04E_01_00_02,          "SH-04E",           "01.00.02"           },
  { DEVICE_SH04E_01_00_03,          "SH-04E",           "01.00.03"           },
  { DEVICE_SO01E_9_1_C_0_473,       "SO-01E",           "9.1.C.0.473"        },
  { DEVICE_SO02E_10_1_D_0_343,      "SO-02E",           "10.1.D.0.343"       },
  { DEVICE_SO03E_10_1_E_0_265,      "SO-03E",           "10.1.E.0.265"       },
  { DEVICE_SO03E_10_1_E_0_269,      "SO-03E",           "10.1.E.0.269"       },
  { DEVICE_SO04D_7_0_D_1_137,       "SO-04D",           "7.0.D.1.137"        },
  { DEVICE_SO04E_10_1_1_D_0_179,    "SO-04E",           "10.1.1.D.0.179"     },
  { DEVICE_SO05D_7_0_D_1_137,       "SO-05D",           "7.0.D.1.137"        },
  { DEVICE_SOL21_9_1_D_0_395,       "SOL21",            "9.1.D.0.395"        },
  { DEVICE_SOL22_10_2_F_3_43,       "SOL22",            "10.2.F.3.43"        },
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
