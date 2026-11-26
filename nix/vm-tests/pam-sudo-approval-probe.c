/* TODO(#408): a stand-in sudo approval plugin for the pam_piggy design
 * probe (pam-sudo-approval-probe.nix). It records what sudo gives it and
 * then allows or refuses by a root-owned switch. A probe, never a
 * template. */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sudo_plugin.h>

#define STATE "/run/pam-probe"

static char *const *saved_user_info;
static char *const *saved_submit_argv;

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

static int probe_open(unsigned int version, sudo_conv_t conversation,
                      sudo_printf_t plugin_printf, char *const settings[],
                      char *const user_info[], int submit_optind,
                      char *const submit_argv[], char *const submit_envp[],
                      char *const plugin_options[], const char **errstr) {
  (void)version, (void)conversation, (void)plugin_printf, (void)settings;
  (void)submit_optind, (void)submit_envp, (void)plugin_options, (void)errstr;
  saved_user_info = user_info;
  saved_submit_argv = submit_argv;
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
  dump(out, "submit", saved_submit_argv);
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

  /* "hold": approve only once the test has had its turn. */
  if (strcmp(mode, "hold") == 0) {
    for (int i = 0; i < 600; i++) {
      /* Not access(): it checks as the real uid, which is the caller's. */
      struct stat go;
      if (stat(STATE "/go", &go) == 0)
        return 1;
      usleep(100000);
    }
    return 0;
  }
  return strcmp(mode, "allow") == 0;
}

__attribute__((visibility("default")))
struct approval_plugin pam_probe_approval = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = probe_open,
    .check = probe_check,
};
