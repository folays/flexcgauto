#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dlfcn.h>
#include <pcre.h>

#define HOOK_LIB_PATH NULL
#define HOOK_INIT(fname) static void *handle, (*f)(); if (!handle) handle = hook_init_ptr(&f, fname);

static void *hook_init_ptr(void (**f)(), const char *fname)
{
  static void *handle;

  handle = dlopen(HOOK_LIB_PATH, RTLD_LAZY);
  if (!handle)
    err(1, "dlopen %s", HOOK_LIB_PATH);
  *f = dlsym(RTLD_NEXT, fname);
  if (!*f)
    err(1, "dlsym %s", fname);
  return handle;
}

static void _flex_cgroup_create(const char *path_usergroup_uid)
{
  char *path_limit_in_bytes;
  FILE *file;

  mkdir(path_usergroup_uid, 0755);

  if (asprintf(&path_limit_in_bytes, "%s/memory.limit_in_bytes", path_usergroup_uid) < 0)
    return;

  if (!(file = fopen(path_limit_in_bytes, "w")))
    goto out_asprintf;

  fprintf(file, "%u", 800 * 1000 * 1000);

 out_fd:
  fclose(file);
 out_asprintf:
  free(path_limit_in_bytes);
}

static void _flex_cgroup_auto_create(const char *path)
{
  pcre *re;
  const char *error;
  int erroffset;
  int ret;
  int ovector[3 * (1 + 1)]; /* 3 * (nb_captures + 1) */
  char *path_usergroup_uid;
  struct stat sb;

  re = pcre_compile("^(/sys/fs/cgroup/memory/+usergroup/\\d+)/+tasks$", 0, &error, &erroffset, 0);
  if (!re)
    return;
  int rc = pcre_exec(re, 0, path, strlen(path), 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
  if (rc < 0)
    goto out_pcre_compile;

  if (asprintf(&path_usergroup_uid, "%.*s", ovector[3] - ovector[2], path + ovector[2]) < 0)
    goto out_pcre_compile;

  if (lstat(path_usergroup_uid, &sb) != 0 && errno == ENOENT)
    _flex_cgroup_create(path_usergroup_uid);

 out_asprintf:
  free(path_usergroup_uid);
 out_pcre_compile:
  free(re);
}

FILE *fopen(const char *path, const char *mode)
{
  HOOK_INIT("fopen");
  FILE *ret;

  _flex_cgroup_auto_create(path);

  ret = ((FILE *(*)())f)(path, mode);

  return ret;
}
