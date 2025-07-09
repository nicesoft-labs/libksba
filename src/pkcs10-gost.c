#include <config.h>
#include <string.h>
#include <gcrypt.h>

#include "util.h"
#include "certreq.h"
#include "keyinfo.h"
#include "ksba.h"

static void
invert_bytes (unsigned char *dst, const unsigned char *src, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    dst[i] = src[len - 1 - i];
}

/* Build and sign a PKCS#10 request for a GOST key.  */
gpg_error_t
_ksba_pkcs10_build_gost (const char *subject,
                         ksba_const_sexp_t pubkey,
                         ksba_const_sexp_t seckey,
                         const char *sig_oid,
                         const char *hash_oid,
                         unsigned char **r_der, size_t *r_derlen)
{
  gpg_error_t err;
  ksba_certreq_t cr = NULL;
  ksba_writer_t wrt = NULL;
  gcry_md_hd_t md = NULL;
  gcry_sexp_t s_skey = NULL, s_sig = NULL, s_hash = NULL;
  ksba_stop_reason_t sr;
  unsigned char *buf = NULL;
  size_t buflen;
  int algo;

  *r_der = NULL;
  *r_derlen = 0;

  if (!subject || !pubkey || !seckey || !sig_oid || !hash_oid)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = ksba_writer_new (&wrt);
  if (err)
    goto leave;
  err = ksba_writer_set_mem (wrt, 4096);
  if (err)
    goto leave;

  err = ksba_certreq_new (&cr);
  if (err)
    goto leave;
  err = ksba_certreq_set_writer (cr, wrt);
  if (err)
    goto leave;
  err = ksba_certreq_add_subject (cr, subject);
  if (err)
    goto leave;
  err = ksba_certreq_set_public_key (cr, pubkey);
  if (err)
    goto leave;

  sr = 0;
  err = ksba_certreq_build (cr, &sr);
  if (err)
    goto leave;
  if (sr != KSBA_SR_NEED_HASH)
    { err = gpg_error (GPG_ERR_INV_STATE); goto leave; }

  algo = gcry_md_map_name (hash_oid);
  if (!algo)
    { err = gpg_error (GPG_ERR_DIGEST_ALGO); goto leave; }
  err = gcry_md_open (&md, algo, 0);
  if (err)
    goto leave;
  ksba_certreq_set_hash_function (cr,
                                  (void (*)(void*,const void*,size_t))gcry_md_write,
                                  md);

  err = ksba_certreq_build (cr, &sr);
  if (err)
    goto leave;
  if (sr != KSBA_SR_NEED_SIG)
    { err = gpg_error (GPG_ERR_INV_STATE); goto leave; }

  gcry_md_final (md);
  {
    size_t dlen = gcry_md_get_algo_dlen (algo);
    unsigned char *digest = gcry_md_read (md, algo);
    {
      size_t i;
      for (i = 0; i < dlen/2; i++)
        {
          unsigned char tmp = digest[i];
          digest[i] = digest[dlen-1-i];
          digest[dlen-1-i] = tmp;
        }
    }
    err = gcry_sexp_build (&s_hash, NULL,
                           "(data(flags gost)(value %b))",
                           (int)dlen, digest);
    if (err)
      goto leave;
  }

  {
    size_t n = gcry_sexp_canon_len (seckey, 0, NULL, NULL);
    if (!n) { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }
    err = gcry_sexp_sscan (&s_skey, NULL, seckey, n);
    if (err)
      goto leave;
  }

  err = gcry_pk_sign (&s_sig, s_hash, s_skey);
  if (err)
    goto leave;

  {
    gcry_sexp_t r = gcry_sexp_find_token (s_sig, "r", 0);
    gcry_sexp_t s = gcry_sexp_find_token (s_sig, "s", 0);
    const unsigned char *rbuf, *sbuf;
    size_t rlen, slen;
    unsigned char *rrev = NULL, *srev = NULL;
    if (!r || !s)
      { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }
    rbuf = gcry_sexp_nth_buffer (r, 1, &rlen);
    sbuf = gcry_sexp_nth_buffer (s, 1, &slen);
    if (!rbuf || !sbuf || rlen != slen)
      { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }
    rrev = gcry_xmalloc (rlen);
    srev = gcry_xmalloc (slen);
    invert_bytes (rrev, rbuf, rlen);
    invert_bytes (srev, sbuf, slen);
    gcry_sexp_release (s_sig);
    s_sig = NULL;
    err = gcry_sexp_build (&s_sig, NULL,
                           "(sig-val (%s (r %b)(s %b)))",
                           sig_oid,
                           (int)rlen, rrev,
                           (int)slen, srev);
    gcry_sexp_release (r);
    gcry_sexp_release (s);
    gcry_free (rrev);
    gcry_free (srev);
    if (err)
      goto leave;
  }

  {
    size_t n = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, NULL, 0);
    char *p = xtrymalloc (n);
    if (!p)
      { err = gpg_error_from_syserror (); goto leave; }
    gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, p, n);
    err = ksba_certreq_set_sig_val (cr, p);
    xfree (p);
    if (err)
      goto leave;
  }

  err = ksba_certreq_build (cr, &sr);
  if (err)
    goto leave;
  if (sr != KSBA_SR_READY)
    { err = gpg_error (GPG_ERR_INV_STATE); goto leave; }

  buf = ksba_writer_snatch_mem (wrt, &buflen);
  if (!buf)
    { err = gpg_error (GPG_ERR_ENOMEM); goto leave; }
  *r_der = buf;
  *r_derlen = buflen;
  buf = NULL;
  err = 0;

leave:
  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_skey);
  ksba_certreq_release (cr);
  ksba_writer_release (wrt);
  xfree (buf);
  return err;
}
