#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include "../src/ksba.h"
#include "t-common.h"
#include <ctype.h>

#define HASH_FNC ((void (*)(void *, const void*,size_t))gcry_md_write)

/* Simple base64 decoder */
static int
b64val (int c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

static gpg_error_t
base64_decode (const char *in, size_t inlen,
               unsigned char **out, size_t *outlen)
{
  unsigned char *buf;
  size_t size = inlen*3/4 + 4;
  size_t n = 0;
  int val = 0, valb = -8;
  buf = xmalloc (size);
  for (size_t i=0; i < inlen; i++)
    {
      int d = b64val (in[i]);
      if (d >= 0)
        {
          val = (val<<6) + d;
          valb += 6;
          if (valb >= 0)
            {
              buf[n++] = (val >> valb) & 0xFF;
              valb -= 8;
            }
        }
    }
  *out = buf;
  *outlen = n;
  return 0;
}

/* Verify the self-signature of CERT without checking policies.  */
static gpg_error_t
verify_self_sig (ksba_cert_t cert)
{
  gpg_error_t err;
  const char *algoid;
  gcry_md_hd_t md;
  int algo;
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

  s = gcry_md_algo_name (algo);
  int i;
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

  p = ksba_cert_get_public_key (cert);
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

  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return err;
}

/* Read a DER or PEM file into memory.  */
static gpg_error_t
read_der (const char *fname, unsigned char **r_buf, size_t *r_len)
{
  FILE *fp;
  char header[16];
  size_t n;

  fp = fopen (fname, "rb");
  if (!fp)
    return gpg_error (GPG_ERR_ENOENT);
  n = fread (header, 1, sizeof header - 1, fp);
  header[n] = '\0';
  rewind (fp);

  if (n > 10 && !strncmp (header, "-----BEGIN", 10))
    {
      char line[512];
      char *accum = NULL;
      size_t accsize = 0, acclen = 0;
      int inside = 0;

      while (fgets (line, sizeof line, fp))
        {
          if (!inside)
            {
              if (!strncmp (line, "-----BEGIN", 10))
                inside = 1;
            }
          else if (!strncmp (line, "-----END", 8))
            {
              break;
            }
          else
            {
              size_t l = strlen (line);
              while (l && (line[l-1]=='\n' || line[l-1]=='\r'))
                line[--l] = 0;
              if (acclen + l + 1 > accsize)
                {
                  accsize = accsize*2 + l + 1;
                  accum = realloc (accum, accsize);
                }
              memcpy (accum+acclen, line, l);
              acclen += l;
            }
        }
      fclose (fp);
      if (!accum)
        return gpg_error (GPG_ERR_BAD_DATA);
      accum[acclen] = 0;
      gpg_error_t err = base64_decode (accum, acclen, r_buf, r_len);
      free (accum);
      return err;
    }
  else
    {
      fseek (fp, 0, SEEK_END);
      long len = ftell (fp);
      rewind (fp);
      *r_buf = xmalloc (len);
      if (fread (*r_buf, 1, len, fp) != (size_t)len)
        {
          fclose (fp);
          free (*r_buf);
          return gpg_error (GPG_ERR_BAD_DATA);
        }
      fclose (fp);
      *r_len = len;
      return 0;
    }
}

struct sample
{
  const char *name;
  const char *expected_eku; /* substring to match */
  unsigned int expected_ku; /* key usage flags */
  const char *policy_prefix;
};

static struct sample samples[] =
  {
    { "test_without_eku", NULL, 0, NULL },
    { "test_gost_eku_sign", "1.3.6.1.5.5.7.3.3", 0, NULL },
    { "test_gost_eku_ocsp", "1.3.6.1.5.5.7.3.9", 0, NULL },
    { "test_gost_eku_crl", NULL, KSBA_KEYUSAGE_CRL_SIGN, NULL },
    { "test_gost_policy", NULL, 0, "1.2.643." },
    { NULL, NULL, 0, NULL }
  };

int
main (void)
{
  int errors = 0;
  struct sample *s;
  gpg_error_t err;

  for (s = samples; s->name; s++)
    {
      char *dir = prepend_srcdir ("samples/gost_certs/");
      char *crtpath = xmalloc (strlen (dir) + strlen (s->name) + 5);
      sprintf (crtpath, "%s%s.crt", dir, s->name);
      char *keypath = xmalloc (strlen (dir) + strlen (s->name) + 5);
      sprintf (keypath, "%s%s.key", dir, s->name);

      unsigned char *der = NULL; size_t derlen = 0;
      unsigned char *keybuf = NULL; size_t keylen = 0;
      err = read_der (crtpath, &der, &derlen);
      if (err)
        {
          fprintf (stderr, "%s: read failed: %s\n", crtpath, gpg_strerror (err));
          errors++; goto next;
        }
      /* Also load the key just to make sure it is accessible.  */
      if (read_der (keypath, &keybuf, &keylen))
        {
          fprintf (stderr, "%s: read failed\n", keypath);
          errors++; goto next;
        }
      free (keybuf);

      ksba_reader_t reader;
      ksba_cert_t cert;
      err = ksba_reader_new (&reader);
      fail_if_err (err);
      err = ksba_reader_set_mem (reader, der, derlen);
      fail_if_err (err);
      err = ksba_cert_new (&cert);
      fail_if_err (err);
      err = ksba_cert_read_der (cert, reader);
      if (err)
        {
          fprintf (stderr, "%s: parse error: %s\n", crtpath, gpg_strerror (err));
          errors++; ksba_reader_release (reader); ksba_cert_release (cert);
          free (der); goto next;
        }
      ksba_reader_release (reader);
      free (der);

      /* Check EKU */
      char *list = NULL;
      err = ksba_cert_get_ext_key_usages (cert, &list);
      if (s->expected_eku)
        {
          if (err || !list || !strstr (list, s->expected_eku))
            {
              fprintf (stderr, "%s: EKU mismatch\n", s->name);
              errors++;
            }
        }
      else if (gpg_err_code (err) != GPG_ERR_NO_DATA)
        {
          fprintf (stderr, "%s: unexpected EKU\n", s->name);
          errors++;
        }
      ksba_free (list);

      /* Check key usage when requested */
      if (s->expected_ku)
        {
          unsigned int ku = 0;
          err = ksba_cert_get_key_usage (cert, &ku);
          if (err || !(ku & s->expected_ku))
            {
              fprintf (stderr, "%s: keyUsage mismatch\n", s->name);
              errors++;
            }
        }

      /* Check policies */
      list = NULL;
      err = ksba_cert_get_cert_policies (cert, &list);
      if (s->policy_prefix)
        {
          if (err || !list || !strstr (list, s->policy_prefix))
            {
              fprintf (stderr, "%s: policy mismatch\n", s->name);
              errors++;
            }
        }
      else if (gpg_err_code (err) != GPG_ERR_NO_DATA)
        {
          fprintf (stderr, "%s: unexpected policy\n", s->name);
          errors++;
        }
      ksba_free (list);

      /* Verify self-signature */
      err = verify_self_sig (cert);
      if (err)
        {
          fprintf (stderr, "%s: signature bad: %s\n", s->name, gpg_strerror (err));
          errors++;
        }

      ksba_cert_release (cert);
next:
      free (crtpath);
      free (keypath);
      free (dir);
    }

  return errors?1:0;
}
