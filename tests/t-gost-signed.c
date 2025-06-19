#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/ksba.h"
#define KSBA_TESTING
#define _KSBA_VISIBILITY_DEFAULT
#include "../src/keyinfo.h"
#include "t-common.h"

static void dummy_hash (void *opaque, const void *buf, size_t len)
{
  (void)opaque; (void)buf; (void)len;
}

int main (int argc, char **argv)
{
  gpg_error_t err;
  ksba_reader_t r;
  ksba_writer_t w;
  ksba_cms_t cms;
  ksba_stop_reason_t sr;
  char *fname;
  ksba_isotime_t stime;
  int count = 0;
  ksba_sexp_t sigval;
  unsigned char *der = NULL;
  size_t derlen;
  char *oid = NULL;

  (void)argc; (void)argv;

  fname = prepend_srcdir ("samples/gost-signed.cms");
  FILE *fp = fopen (fname, "rb");
  if (!fp)
    {
      perror ("fopen");
      exit (1);
    }

  err = ksba_reader_new (&r);
  fail_if_err (err);
  err = ksba_reader_set_file (r, fp);
  fail_if_err (err);
  err = ksba_writer_new (&w);
  fail_if_err (err);
  err = ksba_writer_set_mem (w, 0);
  fail_if_err (err);
  err = ksba_cms_new (&cms);
  fail_if_err (err);

  err = ksba_cms_set_reader_writer (cms, r, w);
  fail_if_err (err);

  err = ksba_cms_parse (cms, &sr);
  fail_if_err (err);
  err = ksba_cms_parse (cms, &sr);
  fail_if_err (err);
  ksba_cms_set_hash_function (cms, dummy_hash, NULL);
  do
    {
      err = ksba_cms_parse (cms, &sr);
      fail_if_err (err);
    }
  while (sr != KSBA_SR_READY);

  /* Count signers */
  for (int idx = 0; ; idx++)
    {
      char *issuer;
      ksba_sexp_t serial;
      err = ksba_cms_get_issuer_serial (cms, idx, &issuer, &serial);
      if (err == -1)
        break;
      fail_if_err (err);
      ksba_free (issuer);
      ksba_free (serial);
      count++;
    }
  assert (count == 1);

  /* Get signature algorithm */
  sigval = ksba_cms_get_sig_val (cms, 0);
  assert (sigval);
  err = _ksba_keyinfo_from_sexp (sigval, 1, &der, &derlen);
  fail_if_err (err);
  err = _ksba_parse_algorithm_identifier2 (der, derlen, NULL, &oid, NULL, NULL);
  fail_if_err (err);
  assert (oid && !strcmp (oid, "1.2.643.7.1.1.3.2"));

  /* signing time */
  err = ksba_cms_get_signing_time (cms, 0, stime);
  fail_if_err (err);

  printf ("signingTime: %.15s\n", stime);
  printf ("signatureAlgorithm: %s\n", oid);

  ksba_free (oid);
  ksba_free (sigval);
  free (der);
  ksba_cms_release (cms);
  ksba_writer_release (w);
  ksba_reader_release (r);
  fclose (fp);
  free (fname);
  return 0;
}
