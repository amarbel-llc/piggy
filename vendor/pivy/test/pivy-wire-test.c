/*
 * pivy-wire-test.c — Wire format compliance tests for SSH agent extensions.
 *
 * Validates that extension response messages conform to the IETF SSH agent
 * spec (draft-ietf-sshm-ssh-agent §3.8): all SSH_AGENT_EXTENSION_RESPONSE
 * (type 29) messages MUST echo the extension name as the first string field.
 *
 * Unit mode:  pivy-wire-test unit
 *   Constructs sshbufs using the same put_* sequences as the handlers,
 *   parses them back, and validates the wire format.
 *
 * Agent mode: pivy-wire-test agent <socket> <extension>
 *   Sends extension requests to a running agent and validates responses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "openssh/authfd.h"
#include "openssh/ssh2.h"
#include "openssh/sshbuf.h"
#include "openssh/ssherr.h"

/*
 * Stubs for symbols pulled in by libssh.a but not needed by this test binary.
 */
void cleanup_exit(int i) { exit(i); }
void *malloc_conceal(size_t size) { return (malloc(size)); }
uid_t platform_sys_dir_uid(uid_t uid) { return (uid); }
const char *ssh_err(int n) {
  (void)n;
  return ("ssh error");
}

#define SSH_AGENTC_EXTENSION 27
#define SSH2_AGENT_EXT_RESPONSE_VAL 29
#define SSH_AGENT_SUCCESS_VAL 6
#define SSH_AGENT_FAILURE_VAL 5

static int failures = 0;
static int passes = 0;

static void pass(const char *name, const char *detail) {
  printf("  PASS: %s — %s\n", name, detail);
  passes++;
}

static void fail(const char *name, const char *detail) {
  fprintf(stderr, "  FAIL: %s — %s\n", name, detail);
  failures++;
}

/*
 * Validate that an sshbuf containing an extension response has the correct
 * type byte and extension name echo.
 */
static int validate_ext_response(struct sshbuf *msg, const char *ext_name,
                                 uint8_t expected_type) {
  int rc;
  uint8_t type;
  char *echo = NULL;

  if ((rc = sshbuf_get_u8(msg, &type)) != 0) {
    fail(ext_name, "failed to read type byte");
    return (-1);
  }
  if (type != expected_type) {
    char detail[128];
    snprintf(detail, sizeof(detail), "wrong type byte: got %d, expected %d",
             (int)type, (int)expected_type);
    fail(ext_name, detail);
    return (-1);
  }

  if (expected_type == SSH2_AGENT_EXT_RESPONSE_VAL) {
    if ((rc = sshbuf_get_cstring(msg, &echo, NULL)) != 0) {
      fail(ext_name, "failed to read extension name echo");
      return (-1);
    }
    if (strcmp(echo, ext_name) != 0) {
      char detail[256];
      snprintf(detail, sizeof(detail), "wrong echo: got '%s', expected '%s'",
               echo, ext_name);
      free(echo);
      fail(ext_name, detail);
      return (-1);
    }
    free(echo);
  }

  return (0);
}

/*
 * Test: query extension response.
 * Wire format: u8(29) + cstring("query") + cstring(name)...
 */
static void test_query(void) {
  struct sshbuf *msg;
  int rc;
  const char *name = "query";
  const char *ext1 = "ecdh@joyent.com";
  const char *ext2 = "ecdh-rebox@joyent.com";

  msg = sshbuf_new();
  if (msg == NULL) {
    fail(name, "sshbuf_new failed");
    return;
  }

  /* Construct response (same as process_ext_query) */
  if ((rc = sshbuf_put_u8(msg, SSH2_AGENT_EXT_RESPONSE_VAL)) != 0 ||
      (rc = sshbuf_put_cstring(msg, name)) != 0 ||
      (rc = sshbuf_put_cstring(msg, ext1)) != 0 ||
      (rc = sshbuf_put_cstring(msg, ext2)) != 0) {
    fail(name, "construction failed");
    sshbuf_free(msg);
    return;
  }

  /* Validate type + echo */
  if (validate_ext_response(msg, name, SSH2_AGENT_EXT_RESPONSE_VAL) != 0) {
    sshbuf_free(msg);
    return;
  }

  /* Validate remaining cstrings are parseable */
  char *s = NULL;
  if ((rc = sshbuf_get_cstring(msg, &s, NULL)) != 0) {
    fail(name, "failed to read first extension name");
    sshbuf_free(msg);
    return;
  }
  if (strcmp(s, ext1) != 0) {
    fail(name, "first extension name mismatch");
    free(s);
    sshbuf_free(msg);
    return;
  }
  free(s);

  if ((rc = sshbuf_get_cstring(msg, &s, NULL)) != 0) {
    fail(name, "failed to read second extension name");
    sshbuf_free(msg);
    return;
  }
  if (strcmp(s, ext2) != 0) {
    fail(name, "second extension name mismatch");
    free(s);
    sshbuf_free(msg);
    return;
  }
  free(s);

  if (sshbuf_len(msg) != 0) {
    fail(name, "trailing data in message");
    sshbuf_free(msg);
    return;
  }

  pass(name, "type=29, echo=\"query\", extension names parsed");
  sshbuf_free(msg);
}

/*
 * Test: extension response with a single string payload.
 * Used for ecdh, ecdh-rebox, x509-certs, sign-prehash.
 */
static void test_string_payload(const char *ext_name) {
  struct sshbuf *msg;
  int rc;
  const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};

  msg = sshbuf_new();
  if (msg == NULL) {
    fail(ext_name, "sshbuf_new failed");
    return;
  }

  /* Construct response */
  if ((rc = sshbuf_put_u8(msg, SSH2_AGENT_EXT_RESPONSE_VAL)) != 0 ||
      (rc = sshbuf_put_cstring(msg, ext_name)) != 0 ||
      (rc = sshbuf_put_string(msg, payload, sizeof(payload))) != 0) {
    fail(ext_name, "construction failed");
    sshbuf_free(msg);
    return;
  }

  /* Validate type + echo */
  if (validate_ext_response(msg, ext_name, SSH2_AGENT_EXT_RESPONSE_VAL) != 0) {
    sshbuf_free(msg);
    return;
  }

  /* Validate string payload */
  const uint8_t *data;
  size_t len;
  if ((rc = sshbuf_get_string_direct(msg, &data, &len)) != 0) {
    fail(ext_name, "failed to read string payload");
    sshbuf_free(msg);
    return;
  }
  if (len != sizeof(payload) || memcmp(data, payload, sizeof(payload)) != 0) {
    fail(ext_name, "payload mismatch");
    sshbuf_free(msg);
    return;
  }

  if (sshbuf_len(msg) != 0) {
    fail(ext_name, "trailing data");
    sshbuf_free(msg);
    return;
  }

  char detail[128];
  snprintf(detail, sizeof(detail),
           "type=29, echo=\"%s\", string payload parsed", ext_name);
  pass(ext_name, detail);
  sshbuf_free(msg);
}

/*
 * Test: ykpiv-attest response.
 * Wire format: u8(29) + cstring("ykpiv-attest@joyent.com") + u32(2) +
 *              string(cert) + string(ca_cert)
 */
static void test_attest(void) {
  struct sshbuf *msg;
  int rc;
  const char *name = "ykpiv-attest@joyent.com";
  const uint8_t cert[] = {0x30, 0x82, 0x01, 0x00};
  const uint8_t ca[] = {0x30, 0x82, 0x02, 0x00};

  msg = sshbuf_new();
  if (msg == NULL) {
    fail(name, "sshbuf_new failed");
    return;
  }

  /* Construct response (same as process_ext_attest) */
  if ((rc = sshbuf_put_u8(msg, SSH2_AGENT_EXT_RESPONSE_VAL)) != 0 ||
      (rc = sshbuf_put_cstring(msg, name)) != 0 ||
      (rc = sshbuf_put_u32(msg, 2)) != 0 ||
      (rc = sshbuf_put_string(msg, cert, sizeof(cert))) != 0 ||
      (rc = sshbuf_put_string(msg, ca, sizeof(ca))) != 0) {
    fail(name, "construction failed");
    sshbuf_free(msg);
    return;
  }

  /* Validate type + echo */
  if (validate_ext_response(msg, name, SSH2_AGENT_EXT_RESPONSE_VAL) != 0) {
    sshbuf_free(msg);
    return;
  }

  /* Validate u32 count */
  uint32_t count;
  if ((rc = sshbuf_get_u32(msg, &count)) != 0 || count != 2) {
    fail(name, "count field mismatch");
    sshbuf_free(msg);
    return;
  }

  /* Validate two string payloads */
  const uint8_t *data;
  size_t len;
  if ((rc = sshbuf_get_string_direct(msg, &data, &len)) != 0 ||
      len != sizeof(cert)) {
    fail(name, "first cert parse failed");
    sshbuf_free(msg);
    return;
  }
  if ((rc = sshbuf_get_string_direct(msg, &data, &len)) != 0 ||
      len != sizeof(ca)) {
    fail(name, "second cert parse failed");
    sshbuf_free(msg);
    return;
  }

  if (sshbuf_len(msg) != 0) {
    fail(name, "trailing data");
    sshbuf_free(msg);
    return;
  }

  pass(name, "type=29, echo, u32(2) + 2 certs parsed");
  sshbuf_free(msg);
}

/*
 * Test: pin-status response.
 * Wire format: u8(29) + cstring("pin-status@joyent.com") + u8(has_pin) +
 *              u8(has_card)
 */
static void test_pin_status(void) {
  struct sshbuf *msg;
  int rc;
  const char *name = "pin-status@joyent.com";

  msg = sshbuf_new();
  if (msg == NULL) {
    fail(name, "sshbuf_new failed");
    return;
  }

  /* Construct response (same as process_ext_pin_status) */
  if ((rc = sshbuf_put_u8(msg, SSH2_AGENT_EXT_RESPONSE_VAL)) != 0 ||
      (rc = sshbuf_put_cstring(msg, name)) != 0 ||
      (rc = sshbuf_put_u8(msg, 1)) != 0 || /* has_pin = 1 */
      (rc = sshbuf_put_u8(msg, 0)) != 0) { /* has_card = 0 */
    fail(name, "construction failed");
    sshbuf_free(msg);
    return;
  }

  /* Validate type + echo */
  if (validate_ext_response(msg, name, SSH2_AGENT_EXT_RESPONSE_VAL) != 0) {
    sshbuf_free(msg);
    return;
  }

  /* Validate u8 fields */
  uint8_t has_pin, has_card;
  if ((rc = sshbuf_get_u8(msg, &has_pin)) != 0 ||
      (rc = sshbuf_get_u8(msg, &has_card)) != 0) {
    fail(name, "failed to read status bytes");
    sshbuf_free(msg);
    return;
  }
  if (has_pin != 1 || has_card != 0) {
    fail(name, "status byte mismatch");
    sshbuf_free(msg);
    return;
  }

  if (sshbuf_len(msg) != 0) {
    fail(name, "trailing data");
    sshbuf_free(msg);
    return;
  }

  pass(name, "type=29, echo, has_pin=1 has_card=0");
  sshbuf_free(msg);
}

/*
 * Test: session-bind response uses SSH_AGENT_SUCCESS + u32(2).
 * The u32(2) is required by ssh-agent-mux which parses the response
 * and expects the extra bytes. Removing it crashes pivy-agent (#19).
 * Wire format: u8(6) + u32(2)
 */
static void test_session_bind(void) {
  struct sshbuf *msg;
  int rc;
  const char *name = "session-bind@openssh.com";

  msg = sshbuf_new();
  if (msg == NULL) {
    fail(name, "sshbuf_new failed");
    return;
  }

  /* Construct response (same as process_ext_sessbind) */
  if ((rc = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS_VAL)) != 0 ||
      (rc = sshbuf_put_u32(msg, 2)) != 0) {
    fail(name, "construction failed");
    sshbuf_free(msg);
    return;
  }

  /* Validate type byte (no echo expected for type 6) */
  if (validate_ext_response(msg, name, SSH_AGENT_SUCCESS_VAL) != 0) {
    sshbuf_free(msg);
    return;
  }

  /* Validate u32 payload */
  uint32_t val;
  if ((rc = sshbuf_get_u32(msg, &val)) != 0 || val != 2) {
    fail(name, "u32 payload mismatch");
    sshbuf_free(msg);
    return;
  }

  if (sshbuf_len(msg) != 0) {
    fail(name, "trailing data");
    sshbuf_free(msg);
    return;
  }

  pass(name, "type=6 (no echo), u32(2)");
  sshbuf_free(msg);
}

/*
 * Agent mode: connect to a running agent and validate extension responses.
 */
static int agent_connect(const char *sock_path) {
  int fd;
  struct sockaddr_un addr;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return (-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strlcpy(addr.sun_path, sock_path, sizeof(addr.sun_path));

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect");
    close(fd);
    return (-1);
  }

  return (fd);
}

static int agent_send_recv(int fd, struct sshbuf *req, struct sshbuf *reply) {
  int rc;
  uint32_t msg_len;
  uint8_t *buf = NULL;
  ssize_t n;

  /* Frame the request: u32(len) + payload */
  struct sshbuf *framed = sshbuf_new();
  if (framed == NULL)
    return (-1);
  if ((rc = sshbuf_put_u32(framed, sshbuf_len(req))) != 0 ||
      (rc = sshbuf_putb(framed, req)) != 0) {
    sshbuf_free(framed);
    return (-1);
  }

  /* Send */
  const uint8_t *data = sshbuf_ptr(framed);
  size_t tolen = sshbuf_len(framed);
  while (tolen > 0) {
    n = write(fd, data, tolen);
    if (n <= 0) {
      sshbuf_free(framed);
      return (-1);
    }
    data += n;
    tolen -= n;
  }
  sshbuf_free(framed);

  /* Read response length */
  uint8_t lenbuf[4];
  size_t got = 0;
  while (got < 4) {
    n = read(fd, lenbuf + got, 4 - got);
    if (n <= 0)
      return (-1);
    got += n;
  }
  msg_len = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) |
            ((uint32_t)lenbuf[2] << 8) | (uint32_t)lenbuf[3];

  if (msg_len == 0 || msg_len > 262144)
    return (-1);

  buf = malloc(msg_len);
  if (buf == NULL)
    return (-1);

  /* Read response body */
  got = 0;
  while (got < (size_t)msg_len) {
    size_t remaining = (size_t)msg_len - got;
    n = read(fd, buf + got, remaining);
    if (n <= 0) {
      free(buf);
      return (-1);
    }
    got += n;
  }

  sshbuf_reset(reply);
  rc = sshbuf_put(reply, buf, msg_len);
  free(buf);
  if (rc != 0)
    return (-1);

  return (0);
}

static void test_agent_query(int fd) {
  const char *name = "query";
  struct sshbuf *req, *reply;
  int rc;

  req = sshbuf_new();
  reply = sshbuf_new();
  if (req == NULL || reply == NULL) {
    fail(name, "sshbuf_new failed");
    goto out;
  }

  /* Build request: u8(27) + cstring("query") */
  if ((rc = sshbuf_put_u8(req, SSH_AGENTC_EXTENSION)) != 0 ||
      (rc = sshbuf_put_cstring(req, name)) != 0) {
    fail(name, "request construction failed");
    goto out;
  }

  if (agent_send_recv(fd, req, reply) != 0) {
    fail(name, "send/recv failed");
    goto out;
  }

  if (validate_ext_response(reply, name, SSH2_AGENT_EXT_RESPONSE_VAL) != 0)
    goto out;

  /* Count remaining cstrings */
  int count = 0;
  while (sshbuf_len(reply) > 0) {
    char *s = NULL;
    if ((rc = sshbuf_get_cstring(reply, &s, NULL)) != 0) {
      fail(name, "failed to parse extension name from list");
      free(s);
      goto out;
    }
    free(s);
    count++;
  }

  char detail[128];
  snprintf(detail, sizeof(detail),
           "type=29, echo=\"query\", %d extensions listed", count);
  pass(name, detail);

out:
  sshbuf_free(req);
  sshbuf_free(reply);
}

static void test_agent_pin_status(int fd) {
  const char *name = "pin-status@joyent.com";
  struct sshbuf *req, *reply;
  int rc;

  req = sshbuf_new();
  reply = sshbuf_new();
  if (req == NULL || reply == NULL) {
    fail(name, "sshbuf_new failed");
    goto out;
  }

  /* Build request: u8(27) + cstring("pin-status@joyent.com") */
  if ((rc = sshbuf_put_u8(req, SSH_AGENTC_EXTENSION)) != 0 ||
      (rc = sshbuf_put_cstring(req, name)) != 0) {
    fail(name, "request construction failed");
    goto out;
  }

  if (agent_send_recv(fd, req, reply) != 0) {
    fail(name, "send/recv failed");
    goto out;
  }

  if (validate_ext_response(reply, name, SSH2_AGENT_EXT_RESPONSE_VAL) != 0)
    goto out;

  /* Validate u8 + u8 payload */
  uint8_t has_pin, has_card;
  if ((rc = sshbuf_get_u8(reply, &has_pin)) != 0 ||
      (rc = sshbuf_get_u8(reply, &has_card)) != 0) {
    fail(name, "failed to read status bytes");
    goto out;
  }

  if (sshbuf_len(reply) != 0) {
    fail(name, "trailing data");
    goto out;
  }

  char detail[128];
  snprintf(detail, sizeof(detail), "type=29, echo, has_pin=%d has_card=%d",
           (int)has_pin, (int)has_card);
  pass(name, detail);

out:
  sshbuf_free(req);
  sshbuf_free(reply);
}

static int run_unit_tests(void) {
  printf("Running wire format unit tests...\n\n");

  test_query();
  test_string_payload("ecdh@joyent.com");
  test_string_payload("ecdh-rebox@joyent.com");
  test_string_payload("x509-certs@joyent.com");
  test_attest();
  test_string_payload("sign-prehash@arekinath.github.io");
  test_pin_status();
  test_session_bind();

  printf("\n%d passed, %d failed\n", passes, failures);
  return (failures > 0 ? 1 : 0);
}

static int run_agent_tests(const char *sock_path, const char *ext_name) {
  int fd = agent_connect(sock_path);
  if (fd < 0) {
    fprintf(stderr, "Failed to connect to agent at %s\n", sock_path);
    return (1);
  }

  printf("Running agent wire format tests against %s...\n\n", sock_path);

  if (ext_name == NULL || strcmp(ext_name, "all") == 0) {
    test_agent_query(fd);
    test_agent_pin_status(fd);
  } else if (strcmp(ext_name, "query") == 0) {
    test_agent_query(fd);
  } else if (strcmp(ext_name, "pin-status@joyent.com") == 0) {
    test_agent_pin_status(fd);
  } else {
    fprintf(stderr, "Unknown extension: %s\n", ext_name);
    fprintf(stderr, "Supported: query, pin-status@joyent.com\n");
    close(fd);
    return (1);
  }

  close(fd);

  printf("\n%d passed, %d failed\n", passes, failures);
  return (failures > 0 ? 1 : 0);
}

static void usage(void) {
  fprintf(stderr, "Usage:\n"
                  "  pivy-wire-test unit\n"
                  "  pivy-wire-test agent <socket> [extension]\n");
  exit(2);
}

int main(int argc, char **argv) {
  if (argc < 2)
    usage();

  if (strcmp(argv[1], "unit") == 0) {
    return (run_unit_tests());
  } else if (strcmp(argv[1], "agent") == 0) {
    if (argc < 3)
      usage();
    return (run_agent_tests(argv[2], argc >= 4 ? argv[3] : "all"));
  } else {
    usage();
  }

  return (0);
}
