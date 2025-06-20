#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <ksba.h>
#include "t-common.h"

static int
sexp_read_len (const unsigned char **s, unsigned long *r_len)
{
  char *endp;

  if (!**s || !isdigit(**s))
    return -1;
  *r_len = strtoul ((const char*)*s, &endp, 10);
  if (*endp != ':')
    return -1;
  *s = endp + 1;
  return 0;
}

static char *
sexp_get_token (const unsigned char **s)
{
  unsigned long len;

  if (sexp_read_len (s, &len))
    return NULL;
  char *buf = malloc (len + 1);
  if (!buf)
    return NULL;
  memcpy (buf, *s, len);
  buf[len] = 0;
  *s += len;
  return buf;
}

static void
parse_sigval_sexp (const unsigned char *sexp, char **r_algo, char **r_curve)
{
  const unsigned char *p = sexp;
  *r_algo = NULL;
  *r_curve = NULL;
  if (!p || *p != '(')
    return;
  p++;
  char *tag = sexp_get_token (&p);
  if (!tag || strcmp (tag, "sig-val"))
    {
      free (tag);
      return;
    }
  free (tag);
  if (*p != '(')
    return;
  p++;
  char *alg = sexp_get_token (&p);
  if (alg && isdigit((unsigned char)alg[0]))
    *r_algo = alg;
  while (*p == '(')
    {
      char *name, *value;
      p++;
      name = sexp_get_token (&p);
      value = sexp_get_token (&p);
      if (*p != ')')
        {
          free (name);
          free (value);
          break;
        }
      p++;
      if (name && !strcmp (name, "curve"))
        *r_curve = value;
      else if (name && !strcmp (name, "algo"))
        {
          if (!*r_algo)
            *r_algo = value;
          else
            free (value);
        }
      else
        free (value);
      free (name);
    }
  if (!*r_algo)
    *r_algo = alg;
  else
    free (alg);
}

struct algomap
{
  const char *oid;
  const char *name;
};

static const struct algomap algo_map[] =
  {
    { "1.2.643.7.1.1.1.1", "GOST R 34.10-2012 (256)" },
    { "1.2.643.7.1.1.1.2", "GOST R 34.10-2012 (512)" },
    { "1.2.643.2.2.19",    "GOST R 34.10-2001" },
    { NULL, NULL }
  };


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
  (void)0; /* no DER needed */
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
  if (!sigval)
    {
      fprintf (stderr, "ksba_cms_get_sig_val returned NULL\n");
      exit (1);
    }
  char *curve = NULL;
  parse_sigval_sexp (sigval, &oid, &curve);
  if (!oid)
    {
      fprintf (stderr, "OID not found in signature value\n");
      exit (1);
    }
  if (!curve)
    {
      fprintf (stderr, "curve OID not found\n");
      exit (1);
    }

  /* signing time */
  err = ksba_cms_get_signing_time (cms, 0, stime);
  fail_if_err (err);

  const char *algoname = "unknown";
  for (int i=0; algo_map[i].oid; i++)
    if (!strcmp (oid, algo_map[i].oid))
      {
        algoname = algo_map[i].name;
        break;
      }

  ksba_cert_t scert = ksba_cms_get_cert (cms, 0);
  char *subject = NULL, *issuer = NULL;
  if (scert)
    {
      subject = ksba_cert_get_subject (scert, 0);
      issuer = ksba_cert_get_issuer (scert, 0);
    }

  printf ("signatureAlgorithm OID: %s (%s)\n", oid, algoname);
  printf ("curve OID: %s\n", curve);
  printf ("signingTime: %.15s\n", stime);
  if (issuer)
    printf ("issuer: %s\n", issuer);
  if (subject)
    printf ("subject: %s\n", subject);

  ksba_free (oid);
  free (curve);
  ksba_free (issuer);
  ksba_free (subject);
  if (scert)
    ksba_cert_release (scert);
  ksba_free (sigval);
  ksba_cms_release (cms);
  ksba_writer_release (w);
  ksba_reader_release (r);
  fclose (fp);
  free (fname);
  return 0;
}
