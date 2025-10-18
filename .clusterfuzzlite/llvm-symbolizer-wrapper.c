#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef WRAPPED_LOADER_BASENAME
#  error "WRAPPED_LOADER_BASENAME must be defined"
#endif
#ifndef WRAPPED_SYMBOLIZER_REAL
#  error "WRAPPED_SYMBOLIZER_REAL must be defined"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern char **environ;

static int resolve_self(char *out, size_t out_sz, char **argv)
{
  ssize_t len = readlink("/proc/self/exe", out, out_sz - 1);
  if (len > 0 && (size_t)len < out_sz) {
    out[len] = '\0';
    return 0;
  }

  if (argv == NULL || argv[0] == NULL) {
    errno = ENOENT;
    return -1;
  }

  if (realpath(argv[0], out) == NULL) {
    size_t arg_len = strlen(argv[0]);
    if (arg_len >= out_sz) {
      errno = ENAMETOOLONG;
      return -1;
    }
    memcpy(out, argv[0], arg_len);
    out[arg_len] = '\0';
  }

  return 0;
}

static int dir_from_path(const char *path, char *dir, size_t dir_sz)
{
  if (path == NULL) {
    errno = ENOENT;
    return -1;
  }

  const char *slash = strrchr(path, '/');
  if (slash == NULL) {
    if (dir_sz < 2) {
      errno = ENAMETOOLONG;
      return -1;
    }
    dir[0] = '.';
    dir[1] = '\0';
    return 0;
  }

  size_t len = (size_t)(slash - path);
  if (len == 0) {
    if (dir_sz < 2) {
      errno = ENAMETOOLONG;
      return -1;
    }
    dir[0] = '/';
    dir[1] = '\0';
    return 0;
  }

  if (len >= dir_sz) {
    errno = ENAMETOOLONG;
    return -1;
  }

  memcpy(dir, path, len);
  dir[len] = '\0';
  return 0;
}

static int join_path(char *out, size_t out_sz, const char *dir, const char *base)
{
  int written;
  if (dir[0] == '\0') {
    written = snprintf(out, out_sz, "%s", base);
  } else if (dir[0] == '/' && dir[1] == '\0') {
    written = snprintf(out, out_sz, "/%s", base);
  } else {
    written = snprintf(out, out_sz, "%s/%s", dir, base);
  }

  if (written < 0 || (size_t)written >= out_sz) {
    errno = ENAMETOOLONG;
    return -1;
  }

  return 0;
}

int main(int argc, char **argv)
{
  char self_path[PATH_MAX];
  if (resolve_self(self_path, sizeof(self_path), argv) != 0) {
    fprintf(stderr, "[cfl] llvm-symbolizer wrapper failed to resolve argv0: %s\n", strerror(errno));
    return 127;
  }

  char dir_path[PATH_MAX];
  if (dir_from_path(self_path, dir_path, sizeof(dir_path)) != 0) {
    fprintf(stderr, "[cfl] llvm-symbolizer wrapper failed to derive directory: %s\n", strerror(errno));
    return 127;
  }

  char loader_path[PATH_MAX];
  char symbolizer_path[PATH_MAX];
  if (join_path(loader_path, sizeof(loader_path), dir_path, WRAPPED_LOADER_BASENAME) != 0 ||
      join_path(symbolizer_path, sizeof(symbolizer_path), dir_path, WRAPPED_SYMBOLIZER_REAL) != 0) {
    fprintf(stderr, "[cfl] llvm-symbolizer wrapper failed to construct paths: %s\n", strerror(errno));
    return 127;
  }

  size_t extra = 4;
  size_t total = (size_t)argc + extra;
  char *new_argv[total + 1];
  size_t idx = 0;
  new_argv[idx++] = loader_path;
  new_argv[idx++] = "--library-path";
  new_argv[idx++] = dir_path;
  new_argv[idx++] = symbolizer_path;
  for (int i = 1; i < argc; ++i) {
    new_argv[idx++] = argv[i];
  }
  new_argv[idx] = NULL;

  execve(loader_path, new_argv, environ);
  fprintf(stderr, "[cfl] llvm-symbolizer wrapper execve failed: %s\n", strerror(errno));
  return 127;
}
