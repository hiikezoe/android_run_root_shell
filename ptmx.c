#include "ptmx.h"
#include "device_database/device_database.h"

unsigned long int
get_ptmx_fops_address(void)
{
  unsigned long int address;

  address = device_get_symbol_address(DEVICE_SYMBOL(ptmx_fops));
  if (address) {
    return address;
  }

  if (kallsyms_exist()) {
    address = kallsyms_get_symbol_address("ptmx_fops");
    if (address) {
      return address;
    }
  }

  print_reason_device_not_supported();
  return 0;
}
