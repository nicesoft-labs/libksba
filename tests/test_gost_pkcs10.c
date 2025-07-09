#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include "../src/ksba.h"
#include "t-common.h"

/*
 * Проверки test_gost_pkcs10.c
 * 1. Формирование PKCS#10 через ksba_pkcs10_build_gost.
 * 2. Проверка ksba_pkcs10_check_gost с валидными расширениями.
 * 3. Ошибка без EKU.
 * 4. Ошибка без политики.
 * 5. Обработка подписи R||S без инверсии.
 */

#define HASH_FNC ((void (*)(void *,const void*,size_t))gcry_md_write)

static gpg_error_t
make_extensions (ksba_certreq_t cr, int add_eku, int add_policy, int add_ku)
{
  gpg_error_t err;
  ksba_der_t dbld;
  unsigned char *der;
  size_t derlen;

  if (add_policy)
    {
      dbld = ksba_der_builder_new (0);
      ksba_der_add_tag (dbld, 0, KSBA_TYPE_SEQUENCE);
      ksba_der_add_tag (dbld, 0, KSBA_TYPE_SEQUENCE);
      ksba_der_add_oid (dbld, "1.2.643.7.1.1.1.1");
      ksba_der_add_end (dbld);
      ksba_der_add_end (dbld);
      err = ksba_der_builder_get (dbld, &der, &derlen);
      ksba_der_release (dbld);
      if (err)
        return err;
      err = ksba_certreq_add_extension (cr, "2.5.29.32", 0, der, derlen);
      ksba_free (der);
      if (err)
        return err;
    }

  if (add_eku)
    {
      dbld = ksba_der_builder_new (0);
      ksba_der_add_tag (dbld, 0, KSBA_TYPE_SEQUENCE);
      ksba_der_add_oid (dbld, "1.3.6.1.5.5.7.3.3");
      ksba_der_add_end (dbld);
      err = ksba_der_builder_get (dbld, &der, &derlen);
      ksba_der_release (dbld);
      if (err)
        return err;
      err = ksba_certreq_add_extension (cr, "2.5.29.37", 0, der, derlen);
      ksba_free (der);
      if (err)
        return err;
    }

  if (add_ku)
    {
      unsigned char ku = 0x80; /* digitalSignature */
      dbld = ksba_der_builder_new (0);
      ksba_der_add_bts (dbld, &ku, 1, 0);
      err = ksba_der_builder_get (dbld, &der, &derlen);
      ksba_der_release (dbld);
      if (err)
        return err;
      err = ksba_certreq_add_extension (cr, "2.5.29.15", 0, der, derlen);
      ksba_free (der);
      if (err)
        return err;
    }
  return 0;
}

static gpg_error_t
build_with_ext (const char *subj, gcry_sexp_t pub, gcry_sexp_t sec,
                int add_eku, int add_policy, int add_ku, int no_invert,
                unsigned char **r_der, size_t *r_derlen)
{
  gpg_error_t err;
  ksba_certreq_t cr = NULL;
  ksba_writer_t wrt = NULL;
  gcry_md_hd_t md = NULL;
  gcry_sexp_t s_skey = NULL, s_sig = NULL, s_hash = NULL;
  unsigned char *pub_canon = NULL, *sec_canon = NULL;
  ksba_stop_reason_t sr;
  unsigned char *buf = NULL;
  size_t buflen;
  int algo;

  *r_der = NULL;
  *r_derlen = 0;

  err = ksba_writer_new (&wrt); if (err) goto leave;
  err = ksba_writer_set_mem (wrt, 4096); if (err) goto leave;
  err = ksba_certreq_new (&cr); if (err) goto leave;
  err = ksba_certreq_set_writer (cr, wrt); if (err) goto leave;
  err = ksba_certreq_add_subject (cr, subj); if (err) goto leave;
  {
    size_t n = gcry_sexp_sprint (pub, GCRYSEXP_FMT_CANON, NULL, 0);
    pub_canon = xmalloc (n);
    gcry_sexp_sprint (pub, GCRYSEXP_FMT_CANON, (char*)pub_canon, n);
    err = ksba_certreq_set_public_key (cr, pub_canon); if (err) goto leave;
  }
  err = make_extensions (cr, add_eku, add_policy, add_ku); if (err) goto leave;

  sr = 0;
  err = ksba_certreq_build (cr, &sr); if (err) goto leave;
  if (sr != KSBA_SR_NEED_HASH) { err = gpg_error (GPG_ERR_INV_STATE); goto leave; }

  algo = gcry_md_map_name ("1.2.643.2.2.9");
  if (!algo) { err = gpg_error (GPG_ERR_DIGEST_ALGO); goto leave; }
  err = gcry_md_open (&md, algo, 0); if (err) goto leave;
  ksba_certreq_set_hash_function (cr, HASH_FNC, md);

  err = ksba_certreq_build (cr, &sr); if (err) goto leave;
  if (sr != KSBA_SR_NEED_SIG) { err = gpg_error (GPG_ERR_INV_STATE); goto leave; }

  gcry_md_final (md);
  {
    size_t dlen = gcry_md_get_algo_dlen (algo);
    unsigned char *digest = gcry_md_read (md, algo);
    {
      size_t i;
      for (i = 0; i < dlen/2; i++)
        {
          unsigned char t = digest[i];
          digest[i] = digest[dlen-1-i];
          digest[dlen-1-i] = t;
        }
    }
    err = gcry_sexp_build (&s_hash, NULL,
                           "(data(flags gost)(value %b))",
                           (int)dlen, digest);
    if (err) goto leave;
  }

  {
    size_t n = gcry_sexp_sprint (sec, GCRYSEXP_FMT_CANON, NULL, 0);
    sec_canon = xmalloc (n);
    gcry_sexp_sprint (sec, GCRYSEXP_FMT_CANON, (char*)sec_canon, n);
    err = gcry_sexp_sscan (&s_skey, NULL, sec_canon, n); if (err) goto leave;
  }

  err = gcry_pk_sign (&s_sig, s_hash, s_skey); if (err) goto leave;

  if (!no_invert)
    {
      gcry_sexp_t r = gcry_sexp_find_token (s_sig, "r", 0);
      gcry_sexp_t s = gcry_sexp_find_token (s_sig, "s", 0);
      const unsigned char *rbuf, *sbuf; size_t rlen, slen; unsigned char *rrev=NULL,*srev=NULL;
      if (!r || !s) { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }
      rbuf = gcry_sexp_nth_buffer (r, 1, &rlen);
      sbuf = gcry_sexp_nth_buffer (s, 1, &slen);
      if (!rbuf || !sbuf || rlen!=slen) { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }
      rrev = gcry_xmalloc (rlen); srev = gcry_xmalloc (slen);
      {
        size_t i;
        for (i = 0; i < rlen; i++)
          rrev[i] = rbuf[rlen-1-i];
        for (i = 0; i < slen; i++)
          srev[i] = sbuf[slen-1-i];
      }
      gcry_sexp_release (s_sig); s_sig=NULL;
      err = gcry_sexp_build (&s_sig, NULL,
                             "(sig-val (1.2.643.2.2.3 (r %b)(s %b)))",
                             (int)rlen,rrev,(int)slen,srev);
      gcry_free (rrev); gcry_free (srev); gcry_sexp_release (r); gcry_sexp_release (s);
      if (err) goto leave;
    }

  {
    size_t n = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, NULL, 0);
    char *p = xmalloc (n);
    gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, p, n);
    err = ksba_certreq_set_sig_val (cr, p);
    xfree (p); if (err) goto leave;
  }

  err = ksba_certreq_build (cr, &sr); if (err) goto leave;
  if (sr != KSBA_SR_READY) { err = gpg_error (GPG_ERR_INV_STATE); goto leave; }

  buf = ksba_writer_snatch_mem (wrt, &buflen);
  if (!buf) { err = gpg_error (GPG_ERR_ENOMEM); goto leave; }
  *r_der = buf; *r_derlen = buflen; buf=NULL;
  err = 0;

leave:
  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_skey);
  ksba_certreq_release (cr);
  ksba_writer_release (wrt);
  xfree (pub_canon);
  xfree (sec_canon);
  ksba_free (buf);
  return err;
}

int main(void)
{
  gpg_error_t err;
  gcry_sexp_t key, pub, sec;
  unsigned char *pub_canon = NULL, *sec_canon = NULL;
  gcry_check_version (NULL);
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  /* Generate GOST key pair. */
  err = gcry_sexp_build (&key, NULL,
                         "(genkey(ecc(curve \"GOST2001-CryptoPro-A\")))");
  fail_if_err (err);
  err = gcry_pk_genkey (&key, key);
  fail_if_err (err);
  pub = gcry_sexp_find_token (key, "public-key", 0);
  sec = gcry_sexp_find_token (key, "private-key", 0);
  /* Convert keys to canonical S-expression strings as required by
     ksba_pkcs10_build_gost.  */
  {
    size_t n;
    n = gcry_sexp_sprint (pub, GCRYSEXP_FMT_CANON, NULL, 0);
    pub_canon = xmalloc (n);
    gcry_sexp_sprint (pub, GCRYSEXP_FMT_CANON, (char*)pub_canon, n);
    n = gcry_sexp_sprint (sec, GCRYSEXP_FMT_CANON, NULL, 0);
    sec_canon = xmalloc (n);
    gcry_sexp_sprint (sec, GCRYSEXP_FMT_CANON, (char*)sec_canon, n);
  }

  /* 1. Build simple request */
  unsigned char *der=NULL; size_t derlen=0;
  err = ksba_pkcs10_build_gost ("CN=Test", pub_canon, sec_canon,
                                 "1.2.643.2.2.3", "1.2.643.2.2.9",
                                 &der, &derlen);
  fail_if_err (err);
  err = ksba_pkcs10_check_gost (der, derlen);
  if (!err)
    fail ("ksba_pkcs10_check_gost should fail without extensions");
  ksba_free (der);

  /* 2. Valid request with extensions */
  err = build_with_ext ("CN=Good", pub, sec, 1,1,1,0, &der, &derlen);
  fail_if_err (err);
  err = ksba_pkcs10_check_gost (der, derlen);
  fail_if_err (err);
  ksba_free (der);

  /* 3. Missing EKU */
  err = build_with_ext ("CN=noEKU", pub, sec, 0,1,1,0, &der, &derlen);
  fail_if_err (err);
  err = ksba_pkcs10_check_gost (der, derlen);
  if (gpg_err_code (err) != GPG_ERR_WRONG_KEY_USAGE)
    fail ("expected WRONG_KEY_USAGE for missing EKU");
  ksba_free (der);

  /* 4. Missing policy */
  err = build_with_ext ("CN=noPol", pub, sec, 1,0,1,0, &der, &derlen);
  fail_if_err (err);
  err = ksba_pkcs10_check_gost (der, derlen);
  if (gpg_err_code (err) != GPG_ERR_NO_POLICY_MATCH)
    fail ("expected NO_POLICY_MATCH");
  ksba_free (der);

  /* 5. Signature without inversion */
  err = build_with_ext ("CN=noInv", pub, sec, 1,1,1,1, &der, &derlen);
  fail_if_err (err);
  err = ksba_pkcs10_check_gost (der, derlen);
  fail_if_err (err);
  ksba_free (der);

  gcry_sexp_release (pub);
  gcry_sexp_release (sec);
  xfree (pub_canon);
  xfree (sec_canon);
  gcry_sexp_release (key);
  return 0;
}
