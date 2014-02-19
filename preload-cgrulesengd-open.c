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

static void _flex_cgroup_create_memory(const char *path_usergroup_uid)
{
  char *path_limit_in_bytes;
  FILE *file;

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

static void _flex_cgroup_create_cpu(const char *path_usergroup_uid)
{
  char *path_shares;
  FILE *file;

  if (asprintf(&path_shares, "%s/cpu.shares", path_usergroup_uid) < 0)
    return;

  if (!(file = fopen(path_shares, "w")))
    goto out_asprintf;

  fprintf(file, "%u", 100);

 out_fd:
  fclose(file);
 out_asprintf:
  free(path_shares);
}

static void _flex_cgroup_auto_create(const char *path)
{
  pcre *re;
  const char *error;
  int erroffset;
  int ret;
  int ovector[3 * (3 + 1)]; /* 3 * (nb_captures + 1) */
  char *path_usergroup_uid;
  char *subsystem;
  char *uid;
  unsigned int is_an_uid = 0;
  struct stat sb;

  re = pcre_compile("^(/sys/fs/cgroup/(memory|cpu)/+usergroup/([\\w_-]+))/+tasks$", 0, &error, &erroffset, 0);
  if (!re)
    return;
  int rc = pcre_exec(re, 0, path, strlen(path), 0, 0, ovector, sizeof(ovector) / sizeof(*ovector));
  if (rc < 0)
    goto out_pcre_compile;

  /* absolute path to usergroup/user/ */
  if (asprintf(&path_usergroup_uid, "%.*s", ovector[3] - ovector[2], path + ovector[2]) < 0)
    goto out_pcre_compile;

  /* cgroup controller (memory, cpu, ...) */
  if (asprintf(&subsystem, "%.*s", ovector[5] - ovector[4], path + ovector[4]) < 0)
    goto out_asprintf_path_usergroup_uid;

  /* UID (or user name) */
  if (asprintf(&uid, "%.*s", ovector[7] - ovector[6], path + ovector[6]) < 0)
    goto out_asprintf_subsystem;

  if (strlen(uid) == strspn(uid, "0123456789"))
    is_an_uid = 1;

  if (lstat(path_usergroup_uid, &sb) != 0 && errno == ENOENT)
    {
      mkdir(path_usergroup_uid, 0755);

      if (is_an_uid)
	{
	  if (!strcmp(subsystem, "memory"))
	    _flex_cgroup_create_memory(path_usergroup_uid);
	  if (!strcmp(subsystem, "cpu"))
	    _flex_cgroup_create_cpu(path_usergroup_uid);
	}
    }

 out_asprintf_uid:
  free(uid);
 out_asprintf_subsystem:
  free(subsystem);
 out_asprintf_path_usergroup_uid:
  free(path_usergroup_uid);
 out_pcre_compile:
  free(re);
}

FILE *fopen(const char *path, const char *mode)
{
  HOOK_INIT("fopen");
  FILE *ret;

  ret = ((FILE *(*)())f)(path, mode);

  if (!ret && errno == ENOENT)
    {
      _flex_cgroup_auto_create(path);
      ret = ((FILE *(*)())f)(path, mode);
    }

  return ret;
}
