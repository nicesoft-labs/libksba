#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include "../src/ksba.h"
#include "t-common.h"
/* Map the internal function name to the public one so that we can
   explicitly call _ksba_check_cert_chain_tk26 in the test code.  */
#define _ksba_check_cert_chain_tk26 ksba_check_cert_chain_tk26

/* Simple base64 decoder (taken from test_gost_certs_verify.c).  */
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

/* Read a DER or PEM encoded certificate.  */
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

static ksba_cert_t
read_cert (const char *fname)
{
  ksba_reader_t r;
  ksba_cert_t c;
  gpg_error_t err;
  unsigned char *buf = NULL;
  size_t buflen = 0;

  err = read_der (fname, &buf, &buflen);
  if (err)
    {
      fprintf (stderr, "cannot open %s\n", fname);
      exit (1);
    }

  err = ksba_reader_new (&r);
  fail_if_err (err);
  err = ksba_reader_set_mem (r, buf, buflen);
  fail_if_err (err);
  err = ksba_cert_new (&c);
  fail_if_err (err);
  err = ksba_cert_read_der (c, r);
  fail_if_err (err);
  ksba_reader_release (r);
  free (buf);
  return c;
}

int
main (void)
{
  ksba_cert_t chain[1];
  gpg_error_t err;
  char *fname;

  /* 1. Successful TK-26 chain check.  */
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_policy.crt");
  chain[0] = read_cert (fname);
  xfree (fname);
  err = _ksba_check_cert_chain_tk26 (chain, 1, 0);
  if (err)
    {
      fprintf (stderr, "test1: expected %d got %s (%d)\n", 0,
               gpg_strerror (err), gpg_err_code (err));
      ksba_cert_release (chain[0]);
      return 1;
    }
  ksba_cert_release (chain[0]);

  /* 2. Policy mismatch check.  */
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_no_policy.crt");
  chain[0] = read_cert (fname);
  xfree (fname);
  err = _ksba_check_cert_chain_tk26 (chain, 1, 0);
  if (gpg_err_code (err) != GPG_ERR_NO_POLICY_MATCH)
    {
      fprintf (stderr, "test2: expected %d got %s (%d)\n",
               GPG_ERR_NO_POLICY_MATCH, gpg_strerror (err),
               gpg_err_code (err));
      ksba_cert_release (chain[0]);
      return 1;
    }
  ksba_cert_release (chain[0]);

  /* 3. Missing EKU check.  */
  fname = prepend_srcdir ("samples/gost_certs2/test_without_eku.crt");
  chain[0] = read_cert (fname);
  xfree (fname);
  err = _ksba_check_cert_chain_tk26 (chain, 1, 0);
  if (gpg_err_code (err) != GPG_ERR_WRONG_KEY_USAGE)
    {
      fprintf (stderr, "test3: expected %d got %s (%d)\n",
               GPG_ERR_WRONG_KEY_USAGE, gpg_strerror (err),
               gpg_err_code (err));
      ksba_cert_release (chain[0]);
      return 1;
    }
  ksba_cert_release (chain[0]);

  return 0;
}
