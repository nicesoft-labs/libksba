/* t-gost-cms.c - verify GOST CMS signature */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <gpg-error.h>
#include <gcrypt.h>

#include "../src/ksba.h"
#include "t-common.h"

#define HASH_FNC ((void (*)(void *, const void *, size_t))gcry_md_write)
#define BUFFER_SIZE 1024

static void
invert_bytes (unsigned char *dst, const unsigned char *src, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    dst[i] = src[len - 1 - i];
}

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
    { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }

  rbuf = gcry_sexp_nth_buffer (r, 1, &rlen);
  sbuf = gcry_sexp_nth_buffer (s, 1, &slen);
  if (!rbuf || !sbuf || rlen != slen)
    { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }

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

static gpg_error_t
check_key_usage_for_gost (const ksba_cert_t cert, unsigned usage_flag)
{
  gpg_error_t err;
  unsigned int usage = 0;

  err = ksba_cert_get_key_usage (cert, &usage);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    return 0;
  if (err)
    return err;

  if (usage_flag == KSBA_KEYUSAGE_DIGITAL_SIGNATURE
      || usage_flag == KSBA_KEYUSAGE_NON_REPUDIATION)
    {
      if (!(usage & (KSBA_KEYUSAGE_DIGITAL_SIGNATURE |
                     KSBA_KEYUSAGE_NON_REPUDIATION)))
        return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }
  else if (usage_flag == KSBA_KEYUSAGE_KEY_ENCIPHERMENT
           || usage_flag == KSBA_KEYUSAGE_DATA_ENCIPHERMENT)
    {
      if (!(usage & (KSBA_KEYUSAGE_KEY_ENCIPHERMENT |
                     KSBA_KEYUSAGE_DATA_ENCIPHERMENT)))
        return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  return 0;
}

static void
noop_hash_fnc (void *arg, const void *data, size_t length)
{
  (void)arg;
  (void)data;
  (void)length;
}

static int
dummy_writer_cb (void *cb_value, const void *buffer, size_t count)
{
  (void)cb_value;
  (void)buffer;
  (void)count;
  return 0;
}

static unsigned char *
file_digest (const char *oid, const char *name, int *digest_len)
{
  gcry_md_hd_t hd;
  int algo = gcry_md_map_name (oid);
  unsigned char *digest, *out;
  FILE *fp;
  unsigned char buf[BUFFER_SIZE];
  size_t n;

  if (!algo)
    return NULL;
  if (gcry_md_open (&hd, algo, 0))
    return NULL;
  fp = fopen (name, "rb");
  if (!fp)
    {
      gcry_md_close (hd);
      return NULL;
    }
  while ((n = fread (buf, 1, BUFFER_SIZE, fp)) > 0)
    gcry_md_write (hd, buf, n);
  fclose (fp);
  digest = gcry_md_read (hd, algo);
  *digest_len = gcry_md_get_algo_dlen (algo);
  out = gcry_xmalloc (*digest_len);
  memcpy (out, digest, *digest_len);
  gcry_md_close (hd);
  return out;
}

int
main (int argc, char **argv)
{
  const char *sig_fname, *content_fname;
  char *s1 = NULL, *s2 = NULL;
  gpg_error_t err;
  FILE *fp = NULL;
  ksba_reader_t reader = NULL;
  ksba_writer_t writer = NULL;
  ksba_cms_t cms = NULL;
  ksba_stop_reason_t stopreason;
  gcry_md_hd_t md = NULL;
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  ksba_cert_t cert;
  ksba_sexp_t serial = NULL;
  unsigned char *issuer_dn = NULL, *subject_dn = NULL;
  ksba_isotime_t sigtime;
  const char *algoid;
  int algo, digest_len;
  unsigned char *digest;
  char *msg_digest = NULL;
  size_t msg_len;
  unsigned char *sig_val;
  int file_digest_len;
  unsigned char *file_digest_val;
  size_t sig_len;

  if (argc == 3)
    {
      sig_fname = argv[1];
      content_fname = argv[2];
    }
  else if (argc == 1)
    {
      s1 = prepend_srcdir ("samples/gost_test.txt.p7s");
      s2 = prepend_srcdir ("samples/gost_test.txt");
      sig_fname = s1;
      content_fname = s2;
    }
  else
    {
      fprintf (stderr, "usage: %s [SIG.p7s CONTENT]\n", argv[0]);
      return 1;
    }

  fp = fopen (sig_fname, "rb");
  if (!fp)
    {
      fprintf (stderr, "can't open `%s': %s\n", sig_fname, strerror (errno));
      goto fail;
    }
  err = ksba_reader_new (&reader);
  if (err)
    goto fail;
  err = ksba_reader_set_file (reader, fp);
  if (err)
    goto fail;
  err = ksba_writer_new (&writer);
  if (err)
    goto fail;
  err = ksba_writer_set_cb (writer, dummy_writer_cb, NULL);
  if (err)
    goto fail;
  err = ksba_cms_new (&cms);
  if (err)
    goto fail;
  err = ksba_cms_set_reader_writer (cms, reader, writer);
  if (err)
    goto fail;
  err = gcry_md_open (&md, 0, 0);
  if (err)
    goto fail;

  err = ksba_cms_parse (cms, &stopreason);
  if (err)
    goto fail;
  ksba_cms_set_hash_function (cms, noop_hash_fnc, NULL);
  while (stopreason != KSBA_SR_READY)
    {
      err = ksba_cms_parse (cms, &stopreason);
      if (err)
        goto fail;
    }

  cert = ksba_cms_get_cert (cms, 0);
  if (cert)
    {
      ksba_sexp_t p;
      size_t n;

      subject_dn = (unsigned char *) ksba_cert_get_subject (cert, 0);
      err = check_key_usage_for_gost (cert, KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
      if (err)
        goto fail;
      p = ksba_cert_get_public_key (cert);
      ksba_cert_release (cert);
      n = gcry_sexp_canon_len (p, 0, NULL, NULL);
      if (!n)
        goto fail;
      err = gcry_sexp_sscan (&s_pkey, NULL, (const char*)p, n);
      ksba_free (p);
      if (err)
        goto fail;
    }

  err = ksba_cms_get_issuer_serial (cms, 0, (char**)&issuer_dn, &serial);
  if (err)
    goto fail;

  algoid = ksba_cms_get_digest_algo (cms, 0);
  algo = gcry_md_map_name (algoid);
  gcry_md_enable (md, algo);
  ksba_cms_set_hash_function (cms, HASH_FNC, md);
  err = ksba_cms_hash_signed_attrs (cms, 0);
  if (err)
    goto fail;
  gcry_md_final (md);
  digest = gcry_md_read (md, algo);
  digest_len = gcry_md_get_algo_dlen (algo);
  if (algoid && !strncmp (algoid, "1.2.643", 7))
    {
      {
        int i;
        for (i = 0; i < digest_len/2; i++)
          {
            unsigned char t = digest[i];
            digest[i] = digest[digest_len-1-i];
            digest[digest_len-1-i] = t;
          }
      }
      err = gcry_sexp_build (&s_hash, NULL,
                             "(data(flags gost)(value %b))",
                             digest_len, digest);
    }
  else
    err = gcry_sexp_build (&s_hash, NULL,
                           "(data(flags pkcs1)(hash %s %b))",
                           algoid, digest_len, digest);
  if (err)
    goto fail;

  err = ksba_cms_get_signing_time (cms, 0, sigtime);
  if (err)
    goto fail;

  err = ksba_cms_get_message_digest (cms, 0, &msg_digest, &msg_len);
  if (err)
    goto fail;

  file_digest_val = file_digest (algoid, content_fname, &file_digest_len);
  if (!file_digest_val ||
      file_digest_len != (int)msg_len ||
      memcmp (file_digest_val, msg_digest, msg_len))
    {
      fprintf (stderr, "message digest mismatch\n");
      gcry_free (file_digest_val);
      goto fail;
    }
  gcry_free (file_digest_val);
  free (msg_digest);

  sig_val = ksba_cms_get_sig_val (cms, 0);
  if (!sig_val)
    goto fail;
  sig_len = gcry_sexp_canon_len (sig_val, 0, NULL, NULL);
  err = gcry_sexp_sscan (&s_sig, NULL, (const char*)sig_val, sig_len);
  ksba_free (sig_val);
  if (err)
    goto fail;

  err = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (err)
    {
      gcry_sexp_t tmp = s_sig;
      if (!gost_adjust_signature (&tmp))
        {
          s_sig = tmp;
          err = gcry_pk_verify (s_sig, s_hash, s_pkey);
        }
      else
        gcry_sexp_release (tmp);
      if (err)
        {
          fprintf (stderr, "gcry_pk_verify failed: %s\n", gpg_strerror (err));
          goto fail;
        }
    }

  /* success */
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  ksba_free (serial);
  gcry_free (issuer_dn);
  gcry_free (subject_dn);
  gcry_md_close (md);
  ksba_cms_release (cms);
  ksba_writer_release (writer);
  ksba_reader_release (reader);
  fclose (fp);
  if (s1) free (s1);
  if (s2) free (s2);
  return 0;

 fail:
  if (fp)
    fclose (fp);
  if (reader)
    ksba_reader_release (reader);
  if (writer)
    ksba_writer_release (writer);
  if (cms)
    ksba_cms_release (cms);
  if (md)
    gcry_md_close (md);
  if (s_sig)
    gcry_sexp_release (s_sig);
  if (s_hash)
    gcry_sexp_release (s_hash);
  if (s_pkey)
    gcry_sexp_release (s_pkey);
  if (serial)
    ksba_free (serial);
  gcry_free (issuer_dn);
  gcry_free (subject_dn);
  if (s1) free (s1);
  if (s2) free (s2);
  return 1;
}
