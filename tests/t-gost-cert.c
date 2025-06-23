/* t-gost-cert.c - verify GOST signed certificate
 * Adapted from example code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <gcrypt.h>
#include <gpg-error.h>

#include "../src/ksba.h"
#include "t-common.h"

#define HASH_FNC ((void (*)(void *, const void*,size_t))gcry_md_write)

/* Print an S-expression to stderr.  */
static void
show_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = gcry_xmalloc (size);
  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}

/* Verify CERT using ISSUER_CERT.  */
static gpg_error_t
check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert)
{
  gpg_error_t err;
  const char *algoid;
  gcry_md_hd_t md;
  int i, algo;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig, s_hash, s_pkey;
  const char *s;
  char algo_name[16+1];
  int digestlen;
  unsigned char *digest;
  int gost_key;

  algoid = ksba_cert_get_digest_algo (cert);
  algo = gcry_md_map_name (algoid);
  if (!algo)
    {
      fprintf (stderr, "unknown hash algorithm `%s'\n", algoid? algoid:"?");
      return gpg_error (GPG_ERR_DIGEST_ALGO);
    }

  gost_key = algoid && !memcmp (algoid, "1.2.643", 7);

  s = gcry_md_algo_name (algo);
  for (i=0; *s && i < (int)sizeof algo_name - 1; s++, i++)
    algo_name[i] = tolower (*s);
  algo_name[i] = 0;

  err = gcry_md_open (&md, algo, 0);
  if (err)
    return err;

  err = ksba_cert_hash (cert, 1, HASH_FNC, md);
  if (err)
    {
      gcry_md_close (md);
      return err;
    }
  gcry_md_final (md);

  p = ksba_cert_get_sig_val (cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      gcry_md_close (md);
      ksba_free (p);
      return gpg_error (GPG_ERR_INV_SEXP);
    }
  err = gcry_sexp_sscan (&s_sig, NULL, p, n);
  ksba_free (p);
  if (err)
    {
      gcry_md_close (md);
      return err;
    }
  show_sexp ("Sig value:\n", s_sig);

  p = ksba_cert_get_public_key (issuer_cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      gcry_md_close (md);
      ksba_free (p);
      gcry_sexp_release (s_sig);
      return gpg_error (GPG_ERR_INV_SEXP);
    }
  err = gcry_sexp_sscan (&s_pkey, NULL, p, n);
  ksba_free (p);
  if (err)
    {
      gcry_md_close (md);
      gcry_sexp_release (s_sig);
      return err;
    }
  show_sexp ("s_pkey:\n", s_pkey);

  digestlen = gcry_md_get_algo_dlen (algo);
  digest = gcry_md_read (md, algo);

  if (gost_key)
    {
      unsigned char *h = digest;
      unsigned char c;
      int len_xy;
      unsigned short arch = 1;
      len_xy = *((unsigned char *)&arch) == 0 ? 0 : gcry_md_get_algo_dlen (algo);
      for (i = 0; i < (len_xy/2); i++)
        {
          c = h[i];
          h[i] = h[len_xy - i - 1];
          h[len_xy - i - 1] = c;
        }
    }

  if (!gost_key)
    err = gcry_sexp_build (&s_hash, NULL,
                           "(data(flags pkcs1)(hash %s %b))",
                           algo_name, (int)digestlen, digest);
  else
    err = gcry_sexp_build (&s_hash, NULL,
                           "(data(flags gost)(value %b))",
                           (int)digestlen, digest);
  if (err)
    {
      gcry_md_close (md);
      gcry_sexp_release (s_sig);
      gcry_sexp_release (s_pkey);
      return err;
    }

  show_sexp ("s_hash:\n", s_hash);

  err = gcry_pk_verify (s_sig, s_hash, s_pkey);

  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return err;
}

int
main (int argc, char **argv)
{
  const char *cert_fname;
  const char *ca_fname;
  char *f1 = NULL, *f2 = NULL;
  FILE *fp, *fp_ca;
  ksba_reader_t r, r_ca;
  ksba_cert_t cert, cert_ca;
  gpg_error_t err;
  unsigned char *sub_dn;

  if (argc == 3)
    {
      cert_fname = argv[1];
      ca_fname = argv[2];
    }
  else if (argc == 1)
    {
      f1 = prepend_srcdir ("samples/user_gost.der");
      f2 = prepend_srcdir ("samples/ca_gost.der");
      cert_fname = f1;
      ca_fname = f2;
    }
  else
    {
      fprintf (stderr, "usage: %s [CERT CA_CERT]\n", argv[0]);
      return 1;
    }

  fp = fopen (cert_fname, "rb");
  if (!fp)
    {
      fprintf (stderr, "can't open `%s'\n", cert_fname);
      return 1;
    }
  err = ksba_reader_new (&r);
  fail_if_err (err);
  err = ksba_reader_set_file (r, fp);
  fail_if_err (err);
  err = ksba_cert_new (&cert);
  fail_if_err (err);
  err = ksba_cert_read_der (cert, r);
  fail_if_err2 (cert_fname, err);
  fclose (fp);
  ksba_reader_release (r);

  fp_ca = fopen (ca_fname, "rb");
  if (!fp_ca)
    {
      fprintf (stderr, "can't open `%s'\n", ca_fname);
      ksba_cert_release (cert);
      if (f1) free (f1);
      if (f2) free (f2);
      return 1;
    }
  err = ksba_reader_new (&r_ca);
  fail_if_err (err);
  err = ksba_reader_set_file (r_ca, fp_ca);
  fail_if_err (err);
  err = ksba_cert_new (&cert_ca);
  fail_if_err (err);
  err = ksba_cert_read_der (cert_ca, r_ca);
  fail_if_err2 (ca_fname, err);
  fclose (fp_ca);
  ksba_reader_release (r_ca);

  sub_dn = ksba_cert_get_subject (cert, 0);
  fprintf (stderr, "Verify %s\n", sub_dn ? (char*)sub_dn : "?");
  ksba_free (sub_dn);

  err = check_cert_sig (cert_ca, cert);
  if (err)
    fprintf (stderr, "verify %s error\n", cert_fname);
  else
    fprintf (stderr, "verify %s Ok\n", cert_fname);

  ksba_cert_release (cert);
  ksba_cert_release (cert_ca);
  if (f1) free (f1);
  if (f2) free (f2);
  return err?1:0;
}
