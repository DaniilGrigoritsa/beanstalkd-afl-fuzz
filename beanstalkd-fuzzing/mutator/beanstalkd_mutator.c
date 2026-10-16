#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CMDS 256
#define LINE_MAX_LEN 224

typedef struct {
  uint8_t *data;
  size_t   len;
} cmd_t;

typedef struct {
  uint64_t rng;
  cmd_t    cmds[MAX_CMDS];
  size_t   n;
  cmd_t    extra[MAX_CMDS]; /* commands parsed from add_buf */
  size_t   n_extra;
  uint8_t *out;
  size_t   out_cap;
  int      puts;            /* number of puts in the current list (job ids are 1..puts) */
} state_t;

/* ---------------------------------------------------------------- random */

static uint64_t rnd(state_t *s) {
  /* xorshift64* */
  s->rng ^= s->rng >> 12;
  s->rng ^= s->rng << 25;
  s->rng ^= s->rng >> 27;
  return s->rng * 2685821657736338717ULL;
}

static uint32_t ur(state_t *s, uint32_t limit) {
  return limit ? (uint32_t)(rnd(s) % limit) : 0;
}

/* ---------------------------------------------------------------- grammar */

typedef enum { A_PRI, A_DELAY, A_TTR, A_ID, A_TUBE, A_TIMEOUT, A_BOUND } arg_t;

typedef struct {
  const char *verb;
  int         nargs;
  arg_t       args[3];
  int         weight;
} cmd_spec_t;

/* "put" is generated separately */
static const cmd_spec_t specs[] = {
  {"use", 1, {A_TUBE}, 6},
  {"reserve", 0, {0}, 1},
  {"reserve-with-timeout", 1, {A_TIMEOUT}, 8},
  {"reserve-job", 1, {A_ID}, 6},
  {"delete", 1, {A_ID}, 6},
  {"release", 3, {A_ID, A_PRI, A_DELAY}, 6},
  {"bury", 2, {A_ID, A_PRI}, 6},
  {"touch", 1, {A_ID}, 4},
  {"watch", 1, {A_TUBE}, 6},
  {"ignore", 1, {A_TUBE}, 5},
  {"peek", 1, {A_ID}, 4},
  {"peek-ready", 0, {0}, 3},
  {"peek-delayed", 0, {0}, 3},
  {"peek-buried", 0, {0}, 3},
  {"kick", 1, {A_BOUND}, 4},
  {"kick-job", 1, {A_ID}, 4},
  {"stats-job", 1, {A_ID}, 4},
  {"stats-tube", 1, {A_TUBE}, 4},
  {"stats", 0, {0}, 2},
  {"list-tubes", 0, {0}, 2},
  {"list-tube-used", 0, {0}, 2},
  {"list-tubes-watched", 0, {0}, 2},
  {"pause-tube", 2, {A_TUBE, A_DELAY}, 4},
  {"quit", 0, {0}, 1},
};
#define N_SPECS (sizeof(specs) / sizeof(specs[0]))

static const char *interesting_nums[] = {
  "0", "1", "2", "3", "7", "10", "100", "1023", "1024", "65534", "65535", "65536",
  "2147483647", "2147483648", "4294967294", "4294967295", "4294967296",
  "9223372036854775807", "18446744073709551615", "18446744073709551616",
  "99999999999999999999999", "-1", "+1", "01", "0x10", "1a", " 1", "", "1 1",
};
#define N_NUMS (sizeof(interesting_nums) / sizeof(interesting_nums[0]))

static const char *tube_names[] = {
  "default", "default", "t", "tube", "emails", "a-b", "A_Z.09", "x;y", "$(x)", "a+b/c",
  "-dash", "a b", "a\tb", "a\x01" "b", "", "\xff",
};
#define N_TUBES (sizeof(tube_names) / sizeof(tube_names[0]))

/* ---------------------------------------------------------------- buffers */

static void cmd_set(cmd_t *c, const uint8_t *data, size_t len) {
  c->data = realloc(c->data, len ? len : 1);
  memcpy(c->data, data, len);
  c->len = len;
}

/* append-only string builder */
typedef struct {
  uint8_t buf[70000];
  size_t  len;
} sb_t;

static void sb_add(sb_t *b, const void *p, size_t n) {
  if (b->len + n > sizeof(b->buf)) n = sizeof(b->buf) - b->len;
  memcpy(b->buf + b->len, p, n);
  b->len += n;
}

static void sb_str(sb_t *b, const char *s) { sb_add(b, s, strlen(s)); }

static void sb_num(sb_t *b, unsigned long long v) {
  char tmp[32];
  snprintf(tmp, sizeof(tmp), "%llu", v);
  sb_str(b, tmp);
}

static sb_t sb; /* scratch; the mutator is single-threaded */

/* ---------------------------------------------------------------- parsing */

/* Splits buf into commands following the server's framing (a valid put header
  takes its <bytes>+2 body bytes with it). Unterminated trailing bytes become
  one last command so nothing is lost. */
static size_t split(const uint8_t *buf, size_t len, cmd_t *out, size_t max) {
  size_t pos = 0, n = 0;

  while (pos < len && n < max) {
    size_t eol = pos, end;
    while (eol + 1 < len && !(buf[eol] == '\r' && buf[eol + 1] == '\n')) eol++;
    if (eol + 1 >= len) {
      end = len;
    } else {
      end = eol + 2;
      if (eol - pos > 4 && !memcmp(buf + pos, "put ", 4)) {
        char line[LINE_MAX_LEN];
        unsigned long long a, b, c, size;
        size_t l = eol - pos < sizeof(line) - 1 ? eol - pos : sizeof(line) - 1;
        memcpy(line, buf + pos, l);
        line[l] = 0;
        if (sscanf(line, "put %llu %llu %llu %llu", &a, &b, &c, &size) == 4 && size <= 65535) {
          end = end + size + 2 > len ? len : end + size + 2;
        }
      }
    }
    cmd_set(&out[n++], buf + pos, end - pos);
    pos = end;
  }
  return n;
}

static int is_put(const cmd_t *c) { return c->len > 4 && !memcmp(c->data, "put ", 4); }

static void count_puts(state_t *s) {
  size_t i;
  s->puts = 0;
  for (i = 0; i < s->n; i++) s->puts += is_put(&s->cmds[i]);
}

/* ---------------------------------------------------------------- generation */

static void gen_tube(state_t *s, sb_t *b) {
  switch (ur(s, 10)) {
    case 0: { /* maximal (200) or too long (201+) name */
      size_t n = 199 + ur(s, 4), i;
      for (i = 0; i < n; i++) sb_str(b, "x");
      break;
    }
    case 1: { /* random name from the allowed charset */
      static const char cs[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-+/;.$_()";
      size_t n = 1 + ur(s, 12), i;
      for (i = 0; i < n; i++) sb_add(b, &cs[ur(s, sizeof(cs) - 1)], 1);
      break;
    }
    default:
      sb_str(b, tube_names[ur(s, N_TUBES)]);
  }
}

static void gen_arg(state_t *s, sb_t *b, arg_t a) {
  if (ur(s, 12) == 0) { /* any interesting number in any position */
    sb_str(b, interesting_nums[ur(s, N_NUMS)]);
    return;
  }
  switch (a) {
    case A_ID: /* ids are 1..puts in every fresh server: hit existing jobs mostly */
      sb_num(b, ur(s, 5) ? 1 + ur(s, s->puts + 2) : ur(s, 1000));
      break;
    case A_PRI:
      sb_num(b, ur(s, 3) ? ur(s, 10) : (ur(s, 2) ? 4294967295ULL : 1024));
      break;
    case A_DELAY: /* mostly 0 so that jobs stay ready during the session */
      sb_num(b, ur(s, 4) ? 0 : 1 + ur(s, 100));
      break;
    case A_TTR:
      sb_num(b, ur(s, 4) ? 60 : ur(s, 3));
      break;
    case A_TIMEOUT: /* non-zero timeouts block the session: keep them rare */
      sb_num(b, ur(s, 8) ? 0 : 1);
      break;
    case A_BOUND:
      sb_num(b, ur(s, 3) ? 1 + ur(s, 10) : 0);
      break;
    case A_TUBE:
      gen_tube(s, b);
      break;
  }
}

static void gen_put(state_t *s, sb_t *b) {
  size_t body = ur(s, 8) ? ur(s, 16) : (ur(s, 2) ? ur(s, 1024) : 65535 + ur(s, 3));
  size_t declared = body, i;

  if (ur(s, 10) == 0) declared = body + ur(s, 3) - 1;

  sb_str(b, "put ");
  gen_arg(s, b, A_PRI);
  sb_str(b, " ");
  gen_arg(s, b, A_DELAY);
  sb_str(b, " ");
  gen_arg(s, b, A_TTR);
  sb_str(b, " ");
  sb_num(b, declared);
  sb_str(b, "\r\n");
  for (i = 0; i < body && b->len < sizeof(b->buf) - 2; i++) {
    uint8_t c = ur(s, 4) ? 'a' + ur(s, 26) : (uint8_t)ur(s, 256);
    sb_add(b, &c, 1);
  }
  sb_str(b, "\r\n");
}

static void gen_cmd(state_t *s, cmd_t *out) {
  uint32_t total = 0, r, i;

  sb.len = 0;
  if (ur(s, 4) == 0) {
    gen_put(s, &sb);
  } else {
    for (i = 0; i < N_SPECS; i++) total += specs[i].weight;
    r = ur(s, total);
    for (i = 0; i < N_SPECS; i++) {
      if (r < (uint32_t)specs[i].weight) break;
      r -= specs[i].weight;
    }
    sb_str(&sb, specs[i].verb);
    for (r = 0; r < (uint32_t)specs[i].nargs; r++) {
      sb_str(&sb, " ");
      gen_arg(s, &sb, specs[i].args[r]);
    }
    sb_str(&sb, "\r\n");
  }
  cmd_set(out, sb.buf, sb.len);
}

/* ---------------------------------------------------------------- mutations */

static void insert_at(state_t *s, size_t pos, const cmd_t *src) {
  cmd_t tmp = {0};
  if (s->n >= MAX_CMDS) return;
  cmd_set(&tmp, src->data, src->len);
  free(s->cmds[s->n].data); /* stale buffer from an earlier, longer split */
  memmove(&s->cmds[pos + 1], &s->cmds[pos], (s->n - pos) * sizeof(cmd_t));
  s->cmds[pos] = tmp;
  s->n++;
}

static void delete_at(state_t *s, size_t pos) {
  free(s->cmds[pos].data);
  memmove(&s->cmds[pos], &s->cmds[pos + 1], (s->n - pos - 1) * sizeof(cmd_t));
  s->n--;
  s->cmds[s->n].data = NULL;
  s->cmds[s->n].len = 0;
}

/* Rewrites one argument of a command line (keeps the rest, including a put body). */
static void mutate_arg(state_t *s, cmd_t *c) {
  size_t eol = 0, starts[8], ends[8], nt = 0, i, t;
  int    in_tok = 0;

  while (eol + 1 < c->len && !(c->data[eol] == '\r' && c->data[eol + 1] == '\n')) eol++;
  if (eol + 1 >= c->len) eol = c->len;

  for (i = 0; i < eol && nt < 8; i++) {
    if (c->data[i] != ' ' && !in_tok) { starts[nt] = i; in_tok = 1; }
    if (c->data[i] == ' ' && in_tok) { ends[nt++] = i; in_tok = 0; }
  }
  if (in_tok && nt < 8) ends[nt++] = eol;
  if (nt == 0) { /* empty line: the verb is empty */
    starts[0] = ends[0] = 0;
    nt = 1;
  }
  if (nt < 2) { /* no arguments: append one */
    starts[nt] = ends[nt] = eol;
    nt++;
  }

  t = 1 + ur(s, nt - 1);
  sb.len = 0;
  sb_add(&sb, c->data, starts[t]);
  if (c->data[0] >= 'a' && (ur(s, 3) == 0 || (ends[t] > starts[t] && c->data[starts[t]] > '9')))
    gen_tube(s, &sb);
  else
    gen_arg(s, &sb, ur(s, 2) ? A_ID : A_PRI);
  sb_add(&sb, c->data + ends[t], c->len - ends[t]);
  cmd_set(c, sb.buf, sb.len);
}

/* Puts a different verb in front of the same arguments. */
static void mutate_verb(state_t *s, cmd_t *c) {
  size_t sp = 0;
  const char *verb;
  while (sp < c->len && c->data[sp] != ' ' && c->data[sp] != '\r') sp++;
  verb = ur(s, 8) ? specs[ur(s, N_SPECS)].verb : "put";
  sb.len = 0;
  sb_str(&sb, verb);
  sb_add(&sb, c->data + sp, c->len - sp);
  cmd_set(c, sb.buf, sb.len);
}

/* Changes a put body and rewrites the <bytes> field to match (or not). */
static void mutate_body(state_t *s, cmd_t *c) {
  size_t eol = 0, body_len, i, sp, new_len;
  uint8_t body[1100];

  while (eol + 1 < c->len && !(c->data[eol] == '\r' && c->data[eol + 1] == '\n')) eol++;
  if (eol + 1 >= c->len) return;
  body_len = c->len - (eol + 2);
  if (body_len >= 2) body_len -= 2; /* trailing "\r\n" */
  if (body_len > 1024) body_len = 1024;
  memcpy(body, c->data + eol + 2, body_len);

  switch (ur(s, 4)) {
    case 0: new_len = 0; break;                            /* empty job */
    case 1: new_len = body_len + 1 + ur(s, 32); break;     /* grow */
    case 2: new_len = body_len ? ur(s, body_len) : 1; break;/* shrink */
    default: new_len = body_len; break;                    /* same size, new bytes */
  }
  if (new_len > 1024) new_len = 1024;
  for (i = (new_len == body_len ? 0 : body_len); i < new_len; i++) body[i] = (uint8_t)ur(s, 256);
  if (new_len == body_len && new_len) body[ur(s, new_len)] = ur(s, 2) ? '\r' : '\n';

  /* the header without its last field (<bytes>) */
  sp = eol;
  while (sp > 0 && c->data[sp - 1] != ' ') sp--;
  sb.len = 0;
  sb_add(&sb, c->data, sp);
  sb_num(&sb, ur(s, 12) ? new_len : new_len + ur(s, 3) - 1);
  sb_str(&sb, "\r\n");
  sb_add(&sb, body, new_len);
  if (ur(s, 16)) sb_str(&sb, "\r\n");
  cmd_set(c, sb.buf, sb.len);
}

/* put; reserve; <op on the reserved job>; ... : drives jobs through their states */
static void insert_scenario(state_t *s, size_t pos) {
  static const char *ops[] = {"bury %d 0", "release %d 0 0", "release %d 1 1", "touch %d",
                              "delete %d", "kick-job %d", "stats-job %d", "peek %d"};
  char line[64];
  int  id;
  cmd_t c = {0};
  int  k, steps = 1 + ur(s, 3);

  sb.len = 0;
  sb_str(&sb, "put 0 0 60 1\r\nx\r\n");
  cmd_set(&c, sb.buf, sb.len);
  insert_at(s, pos++, &c);
  count_puts(s);
  id = s->puts; /* ids are assigned in put order from a fresh server */

  sb.len = 0;
  sb_str(&sb, ur(s, 3) ? "reserve-with-timeout 0\r\n" : "reserve-job ");
  if (sb.buf[sb.len - 1] == ' ') { sb_num(&sb, id); sb_str(&sb, "\r\n"); }
  cmd_set(&c, sb.buf, sb.len);
  insert_at(s, pos++, &c);

  for (k = 0; k < steps; k++) {
    snprintf(line, sizeof(line), ops[ur(s, sizeof(ops) / sizeof(ops[0]))], id);
    sb.len = 0;
    sb_str(&sb, line);
    sb_str(&sb, "\r\n");
    cmd_set(&c, sb.buf, sb.len);
    insert_at(s, pos++, &c);
  }
  free(c.data);
}

static void mutate_once(state_t *s) {
  size_t pos = s->n ? ur(s, s->n) : 0;
  cmd_t  c = {0};

  switch (ur(s, 12)) {
    case 0: case 1: /* insert a generated command */
      gen_cmd(s, &c);
      insert_at(s, s->n ? ur(s, s->n + 1) : 0, &c);
      break;
    case 2: /* replace a command */
      if (!s->n) break;
      gen_cmd(s, &s->cmds[pos]);
      break;
    case 3: /* delete */
      if (s->n > 1) delete_at(s, pos);
      break;
    case 4: /* duplicate */
      if (s->n) insert_at(s, pos, &s->cmds[pos]);
      break;
    case 5: /* swap two commands */
      if (s->n > 1) {
        size_t q = ur(s, s->n);
        cmd_t  t = s->cmds[pos];
        s->cmds[pos] = s->cmds[q];
        s->cmds[q] = t;
      }
      break;
    case 6: case 7: /* change an argument */
      if (s->n) mutate_arg(s, &s->cmds[pos]);
      break;
    case 8: /* change the verb */
      if (s->n) mutate_verb(s, &s->cmds[pos]);
      break;
    case 9: { /* change a put body */
      size_t i, k = ur(s, s->n ? s->n : 1);
      for (i = 0; i < s->n; i++, k = (k + 1) % s->n)
        if (is_put(&s->cmds[k])) { mutate_body(s, &s->cmds[k]); break; }
      break;
    }
    case 10: /* a command from another seed */
      if (s->n_extra) insert_at(s, s->n ? ur(s, s->n + 1) : 0, &s->extra[ur(s, s->n_extra)]);
      break;
    case 11:
      insert_scenario(s, s->n ? ur(s, s->n + 1) : 0);
      break;
  }
  free(c.data);
  count_puts(s);
}

/* ---------------------------------------------------------------- AFL++ API */

void *afl_custom_init(void *afl, unsigned int seed) {
  state_t *s = calloc(1, sizeof(state_t));
  (void)afl;
  s->rng = seed ? seed : 0x9e3779b97f4a7c15ULL;
  return s;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
  state_t *s = data;
  size_t   i, total = 0, rounds = 1 + ur(s, 4);

  s->n = split(buf, buf_size, s->cmds, MAX_CMDS);
  s->n_extra = add_buf ? split(add_buf, add_buf_size, s->extra, MAX_CMDS) : 0;
  count_puts(s);

  for (i = 0; i < rounds; i++) mutate_once(s);

  for (i = 0; i < s->n; i++) total += s->cmds[i].len;
  if (total > max_size) total = max_size;
  if (s->out_cap < total + 1) {
    s->out_cap = total + 1;
    s->out = realloc(s->out, s->out_cap);
  }
  total = 0;
  for (i = 0; i < s->n && total + s->cmds[i].len <= max_size; i++) {
    memcpy(s->out + total, s->cmds[i].data, s->cmds[i].len);
    total += s->cmds[i].len;
  }
  if (!total) { /* never hand back an empty buffer */
    memcpy(s->out, "stats\r\n", 7);
    total = 7;
  }

  *out_buf = s->out;
  return total;
}

void afl_custom_deinit(void *data) {
  state_t *s = data;
  size_t   i;
  for (i = 0; i < MAX_CMDS; i++) {
    free(s->cmds[i].data);
    free(s->extra[i].data);
  }
  free(s->out);
  free(s);
}
