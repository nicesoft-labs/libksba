#include <config.h>
#include <ctype.h>
#include <string.h>
#include <gcrypt.h>

#include "util.h"
#include "keyinfo.h"
#include "cert.h"
#include "ksba.h"

#define HASH_FNC ((void (*)(void *, const void *, size_t))gcry_md_write)

/* Reverse byte order helper.  */
static void
invert_bytes (unsigned char *dst, const unsigned char *src, size_t len)
{
  for (size_t i = 0; i < len; i++)
    dst[i] = src[len - 1 - i];
}

/* Adjust a GOST signature by inverting R and S values.  */
static gpg_error_t
gost_adjust_signature (gcry_sexp_t *sig)
{
  gcry_sexp_t r = NULL, s = NULL;
  const unsigned char *rbuf, *sbuf;
  size_t rlen, slen;
  unsigned char *rrev = NULL, *srev = NULL;
  gpg_error_t err = 0;

  if (!sig || !*sig)
    return gpg_error (GPG_ERR_INV_VALUE);

  r = gcry_sexp_find_token (*sig, "r", 0);
  s = gcry_sexp_find_token (*sig, "s", 0);
  if (!r || !s)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }

  rbuf = gcry_sexp_nth_buffer (r, 1, &rlen);
  sbuf = gcry_sexp_nth_buffer (s, 1, &slen);
  if (!rbuf || !sbuf || rlen != slen)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }

  rrev = gcry_xmalloc (rlen);
  srev = gcry_xmalloc (slen);
  invert_bytes (rrev, rbuf, rlen);
  invert_bytes (srev, sbuf, slen);

  gcry_sexp_release (*sig);
  err = gcry_sexp_build (sig, NULL,
                         "(sig-val (gost (r %b)(s %b)))",
                         (int)rlen, rrev, (int)slen, srev);

leave:
  gcry_sexp_release (r);
  gcry_sexp_release (s);
  gcry_free (rrev);
  gcry_free (srev);
  return err;
}

/* Wrapper to check keyUsage for GOST certificates.  */
static gpg_error_t
check_key_usage_for_gost (const ksba_cert_t cert, unsigned usage_flag)
{
  return _ksba_check_key_usage_for_gost (cert, usage_flag);
}

/* Verify CERT using ISSUER_CERT.  */
gpg_error_t
_ksba_check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert)
{
  gpg_error_t err;
  const char *algoid;
  gcry_md_hd_t md;
  int algo, i;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  const char *s;
  char algo_name[17];
  int digestlen;
  unsigned char *digest;
  int gost_key;

  algoid = ksba_cert_get_digest_algo (cert);
  algo = gcry_md_map_name (algoid);
  if (!algo)
    return gpg_error (GPG_ERR_DIGEST_ALGO);

  gost_key = algoid && !memcmp (algoid, "1.2.643", 7);

  if (gost_key)
    {
      err = check_key_usage_for_gost (cert,
                                      KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
      if (err)
        return err;
    }

  s = gcry_md_algo_name (algo);
  for (i = 0; *s && i < (int)sizeof algo_name - 1; s++, i++)
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

  err = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (err && gost_key)
    {
      gcry_sexp_t tmp = s_sig;
      if (!gost_adjust_signature (&tmp))
        {
          s_sig = tmp;
          err = gcry_pk_verify (s_sig, s_hash, s_pkey);
        }
      else
        gcry_sexp_release (tmp);
    }

  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return err;
}
