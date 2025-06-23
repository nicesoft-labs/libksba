#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/ksba.h"
#include "t-common.h"

int
main(void)
{
  gpg_error_t err;
  unsigned char *buf = NULL;
  size_t len = 0;
  char *out = NULL;

  err = ksba_oid_from_str ("1.2.643.2.2.96", &buf, &len);
  fail_if_err (err);
  out = ksba_oid_to_str ((char*)buf, len);
  if (!out || strcmp (out, "1.2.643.2.2.96"))
    {
      fprintf (stderr, "OID roundtrip failed: %s\n", out? out: "(null)");
      return 1;
    }
  ksba_free (buf);
  ksba_free (out);
  return 0;
}
