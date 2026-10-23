// Mutation stub for the verification run: returns the input unchanged. With
// AFL_CUSTOM_MUTATOR_PROB=100 every havoc iteration uses it, so the fuzzer keeps sending the seed
// exactly as it is.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *copy;

void *afl_custom_init(void *afl, unsigned int seed) {
  (void)afl;
  (void)seed;
  return &copy;
}

// The output is a copy: the caller reallocates its buffer before copying from ours.
size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
  (void)data;
  (void)add_buf;
  (void)add_buf_size;
  (void)max_size;
  uint8_t *p = realloc(copy, buf_size ? buf_size : 1);
  if (!p) return 0;
  copy = p;
  memcpy(copy, buf, buf_size);
  *out_buf = copy;
  return buf_size;
}

void afl_custom_deinit(void *data) {
  (void)data;
  free(copy);
  copy = NULL;
}
