#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "creds.h"

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

bool
setup_creds_functions(void)
{
  prepare_kernel_cred = get_symbol_address("prepare_kernel_cred");
  commit_creds = get_symbol_address("commit_creds");

  return prepare_kernel_cred && commit_creds;
}

