/* Prints N mutations of a seed file: ./test_mutator <seed> [n] */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
void *afl_custom_init(void *afl, unsigned int seed);
size_t afl_custom_fuzz(void *, uint8_t *, size_t, uint8_t **, uint8_t *, size_t, size_t);
void afl_custom_deinit(void *);
int main(int argc, char **argv) {
  static uint8_t buf[1 << 20];
  FILE *f = fopen(argv[1], "rb");
  size_t len = fread(buf, 1, sizeof(buf), f), i, j;
  int n = argc > 2 ? atoi(argv[2]) : 5;
  void *m = afl_custom_init(NULL, 1234);
  fclose(f);
  for (i = 0; i < (size_t)n; i++) {
    uint8_t *out;
    size_t ol = afl_custom_fuzz(m, buf, len, &out, buf, len, 1 << 20);
    printf("---- mutation %zu (%zu bytes)\n", i, ol);
    for (j = 0; j < ol && j < 600; j++)
      putchar(out[j] == '\r' ? '~' : (out[j] < 32 && out[j] != '\n') || out[j] > 126 ? '.' : out[j]);
    putchar('\n');
  }
  afl_custom_deinit(m);
  return 0;
}
