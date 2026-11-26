/* TODO(#408): a stand-in sudo approval plugin for the pam_piggy design
 * probe (pam-sudo-approval-probe.nix). It records the user_info,
 * command_info, run_argv and run_envp sudo gives it, then answers as a
 * root-owned switch says: allow, refuse, hold (allow once told to) or
 * safe (hold, after the root-only path check). A probe, never a
 * template. */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sudo_plugin.h>

#define STATE "/run/pam-probe"

static char *const *saved_user_info;

/* One record per line: "<kind> <value>", newlines in a value escaped. */
static void dump(FILE *out, const char *kind, char *const values[]) {
  for (int i = 0; values != NULL && values[i] != NULL; i++) {
    fprintf(out, "%s ", kind);
    for (const char *c = values[i]; *c != '\0'; c++) {
      if (*c == '\n')
        fputs("\\n", out);
      else
        fputc(*c, out);
    }
    fputc('\n', out);
  }
}

/* The candidate remedy: can only root change what `path` leads to? Walks it
 * one component at a time, following links. Everything on the way must be
 * root's, and nothing group- or other-writable, except a sticky directory
 * (as /nix/store is), where others cannot replace root's entries. POSIX
 * ACLs are not read. */
static int only_root_can_change(const char *path) {
  char todo[PATH_MAX], done[PATH_MAX] = "";
  struct stat st;
  int links = 0;
  if (path[0] != '/' || strlen(path) >= sizeof todo)
    return 0;
  strcpy(todo, path);
  if (stat("/", &st) != 0 || st.st_uid != 0 || (st.st_mode & 022))
    return 0;

  char *rest = todo;
  while (*rest != '\0') {
    if (*rest == '/') {
      rest++;
      continue;
    }
    size_t length = strcspn(rest, "/");
    if (length == 1 && rest[0] == '.') {
      rest += length;
      continue;
    }
    if (length == 2 && rest[0] == '.' && rest[1] == '.') {
      char *slash = strrchr(done, '/');
      if (slash != NULL)
        *slash = '\0';
      rest += length;
      continue;
    }
    char next[PATH_MAX];
    if (snprintf(next, sizeof next, "%s/%.*s", done, (int)length, rest) >=
        (int)sizeof next)
      return 0;
    rest += length;
    if (lstat(next, &st) != 0 || st.st_uid != 0)
      return 0;
    if (S_ISLNK(st.st_mode)) {
      char target[PATH_MAX], joined[PATH_MAX];
      ssize_t got = readlink(next, target, sizeof target - 1);
      if (got < 0 || ++links > 40)
        return 0;
      target[got] = '\0';
      if (snprintf(joined, sizeof joined, "%s%s", target, rest) >=
          (int)sizeof joined)
        return 0;
      strcpy(todo, joined);
      rest = todo;
      if (target[0] == '/')
        done[0] = '\0';
      continue;
    }
    if ((st.st_mode & 022) && !(S_ISDIR(st.st_mode) && (st.st_mode & S_ISVTX)))
      return 0;
    if (!S_ISDIR(st.st_mode) && *rest != '\0')
      return 0;
    strcpy(done, next);
  }
  return 1;
}

static const char *value_of(char *const list[], const char *name) {
  size_t length = strlen(name);
  for (int i = 0; list != NULL && list[i] != NULL; i++)
    if (strncmp(list[i], name, length) == 0 && list[i][length] == '=')
      return list[i] + length + 1;
  return NULL;
}

/* The command as an absolute path. A relative one is resolved where sudo
 * will run it: command_info's cwd when sudo changes directory, else the
 * caller's. A changed root is refused: the checked path would not be the
 * one that runs. */
static int command_is_safe(char *const command_info[]) {
  const char *command = value_of(command_info, "command");
  const char *cwd = value_of(command_info, "cwd");
  char absolute[PATH_MAX];
  if (cwd == NULL)
    cwd = value_of(saved_user_info, "cwd");
  if (command == NULL || value_of(command_info, "chroot") != NULL)
    return 0;
  if (command[0] == '/')
    return only_root_can_change(command);
  if (cwd == NULL || snprintf(absolute, sizeof absolute, "%s/%s", cwd,
                              command) >= (int)sizeof absolute)
    return 0;
  return only_root_can_change(absolute);
}

/* "hold": approve only once the test has had its turn. */
static int wait_for_go(void) {
  for (int i = 0; i < 600; i++) {
    /* Not access(): it checks as the real uid, which is the caller's. */
    struct stat go;
    if (stat(STATE "/go", &go) == 0)
      return 1;
    usleep(100000);
  }
  return 0;
}

static int probe_open(unsigned int version, sudo_conv_t conversation,
                      sudo_printf_t plugin_printf, char *const settings[],
                      char *const user_info[], int submit_optind,
                      char *const submit_argv[], char *const submit_envp[],
                      char *const plugin_options[], const char **errstr) {
  (void)version, (void)conversation, (void)plugin_printf, (void)settings;
  (void)submit_optind, (void)submit_argv, (void)submit_envp;
  (void)plugin_options, (void)errstr;
  saved_user_info = user_info;
  return 1;
}

static int probe_check(char *const command_info[], char *const run_argv[],
                       char *const run_envp[], const char **errstr) {
  (void)errstr;
  FILE *out = fopen(STATE "/approval", "a");
  if (out == NULL)
    return 0;
  fputs("call\n", out);
  dump(out, "user", saved_user_info);
  dump(out, "info", command_info);
  dump(out, "argv", run_argv);
  dump(out, "env", run_envp);
  fputs("end\n", out);
  if (fclose(out) != 0)
    return 0;

  char mode[16] = "";
  FILE *in = fopen(STATE "/mode", "r");
  if (in == NULL)
    return 0;
  if (fgets(mode, sizeof mode, in) == NULL)
    mode[0] = '\0';
  fclose(in);
  mode[strcspn(mode, "\n")] = '\0';

  if (strcmp(mode, "hold") == 0)
    return wait_for_go();
  /* "safe" applies the candidate remedy, then waits like "hold". */
  if (strcmp(mode, "safe") == 0)
    return command_is_safe(command_info) && wait_for_go();
  return strcmp(mode, "allow") == 0;
}

__attribute__((visibility("default")))
struct approval_plugin pam_probe_approval = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = probe_open,
    .check = probe_check,
};
