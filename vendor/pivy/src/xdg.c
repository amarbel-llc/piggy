/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "xdg.h"

static char *xdg_dir(const char *env, const char *home, const char *suffix) {
  const char *val;
  char *buf;

  if (env != NULL) {
    val = getenv(env);
    if (val != NULL && val[0] == '/')
      return (strdup(val));
  }

  if (home == NULL)
    return (NULL);

  buf = malloc(PATH_MAX);
  if (buf == NULL)
    return (NULL);
  snprintf(buf, PATH_MAX, "%s/%s", home, suffix);
  return (buf);
}

static char *xdg_dir_env(const char *env, const char *suffix) {
  const char *home = getenv("HOME");
  return (xdg_dir(env, home, suffix));
}

char *xdg_config_home(void) {
  return (xdg_dir_env("XDG_CONFIG_HOME", ".config"));
}

char *xdg_config_home_for(const char *home) {
  return (xdg_dir("XDG_CONFIG_HOME", home, ".config"));
}

char *xdg_data_home(void) {
  return (xdg_dir_env("XDG_DATA_HOME", ".local/share"));
}

char *xdg_data_home_for(const char *home) {
  return (xdg_dir("XDG_DATA_HOME", home, ".local/share"));
}

char *xdg_state_home(void) {
  return (xdg_dir_env("XDG_STATE_HOME", ".local/state"));
}

char *xdg_state_home_for(const char *home) {
  return (xdg_dir("XDG_STATE_HOME", home, ".local/state"));
}

char *xdg_log_home(void) { return (xdg_dir_env("XDG_LOG_HOME", ".local/log")); }

char *xdg_log_home_for(const char *home) {
  return (xdg_dir("XDG_LOG_HOME", home, ".local/log"));
}

char *xdg_cache_home(void) { return (xdg_dir_env("XDG_CACHE_HOME", ".cache")); }

char *xdg_cache_home_for(const char *home) {
  return (xdg_dir("XDG_CACHE_HOME", home, ".cache"));
}

char *xdg_runtime_dir(void) { return (xdg_dir_env("XDG_RUNTIME_DIR", NULL)); }

int xdg_mkdir_p(const char *path, mode_t mode) {
  char buf[PATH_MAX];
  size_t len;
  size_t i;

  len = strlcpy(buf, path, sizeof(buf));
  if (len >= sizeof(buf)) {
    errno = ENAMETOOLONG;
    return (-1);
  }

  for (i = 1; i < len; ++i) {
    if (buf[i] != '/')
      continue;
    buf[i] = '\0';
    if (mkdir(buf, mode) != 0 && errno != EEXIST)
      return (-1);
    buf[i] = '/';
  }
  if (mkdir(buf, mode) != 0 && errno != EEXIST)
    return (-1);
  return (0);
}
