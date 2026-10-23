// LD_PRELOAD helper for the reference (unpatched) server: exit() on SIGTERM, so the gcov
// counters are written. The original beanstalkd handles SIGTERM only when it runs as pid 1;
// otherwise SIGTERM kills it before the coverage data is saved. The server code is unchanged.
#include <signal.h>
#include <stdlib.h>

static void on_term(int sig) {
  (void)sig;
  exit(0);
}

__attribute__((constructor)) static void install(void) {
  signal(SIGTERM, on_term);
}
