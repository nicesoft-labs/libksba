#include <stdio.h>
#include <gcrypt.h>
#include "../src/ksba.h"
#include "t-common.h"

static ksba_cert_t
read_pem_cert (const char *fname)
{
  FILE *fp;
  ksba_reader_t r;
  ksba_cert_t c;
  gpg_error_t err;

  fp = fopen (fname, "rb");
  if (!fp)
    fail ("open cert");
  err = ksba_reader_new (&r);
  fail_if_err (err);
  err = ksba_reader_set_file (r, fp);
  fail_if_err (err);
  err = ksba_cert_new (&c);
  fail_if_err (err);
  err = ksba_cert_read_pem (c, r);
  fail_if_err (err);
  fclose (fp);
  ksba_reader_release (r);
  return c;
}

int
main (void)
{
  ksba_cert_t root, sub;
  gpg_error_t err;
  char *fname;

  fname = prepend_srcdir ("samples/russian_trusted/Russian_Trusted_Root_CA.pem");
  root = read_pem_cert (fname);
  xfree (fname);
  fname = prepend_srcdir ("samples/russian_trusted/Russian_Trusted_Sub_CA.pem");
  sub = read_pem_cert (fname);
  xfree (fname);

  err = ksba_check_cert_sig (root, root);
  fail_if_err (err);

  err = ksba_check_cert_sig (root, sub);
  fail_if_err (err);

  ksba_cert_release (root);
  ksba_cert_release (sub);

  return 0;
}
