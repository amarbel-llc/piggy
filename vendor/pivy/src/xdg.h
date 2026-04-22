/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef _XDG_H
#define _XDG_H

#include <sys/stat.h>
#include <sys/types.h>

/*
 * XDG Base Directory helpers.
 *
 * Each function returns a malloc'd string (caller frees).
 * The _for() variants accept an explicit home dir (for PAM modules
 * that resolve paths for a target user, not the calling process).
 *
 * Follows amarbel-llc/xdg spec v0.9 which adds XDG_LOG_HOME.
 */

/* $XDG_CONFIG_HOME, default $HOME/.config */
char *xdg_config_home(void);
char *xdg_config_home_for(const char *home);

/* $XDG_DATA_HOME, default $HOME/.local/share */
char *xdg_data_home(void);
char *xdg_data_home_for(const char *home);

/* $XDG_STATE_HOME, default $HOME/.local/state */
char *xdg_state_home(void);
char *xdg_state_home_for(const char *home);

/* $XDG_LOG_HOME, default $HOME/.local/log (amarbel-llc/xdg extension) */
char *xdg_log_home(void);
char *xdg_log_home_for(const char *home);

/* $XDG_CACHE_HOME, default $HOME/.cache */
char *xdg_cache_home(void);
char *xdg_cache_home_for(const char *home);

/* $XDG_RUNTIME_DIR, no default (returns NULL if unset) */
char *xdg_runtime_dir(void);

/*
 * Create directory and parents with given mode.
 * Returns 0 on success, -1 on error (errno set).
 */
int xdg_mkdir_p(const char *path, mode_t mode);

#endif /* _XDG_H */
