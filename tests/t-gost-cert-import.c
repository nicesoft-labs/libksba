#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "../src/ksba.h"
#include "t-common.h"

static int
b64_val (unsigned char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

static unsigned char *
base64_decode (const char *buf, size_t len, size_t *r_len)
{
  unsigned char *out = xmalloc (len/4*3 + 4);
  size_t outlen = 0;
  int val = 0, valb = -8;
  for (size_t i=0; i < len; i++)
    {
      int c = b64_val (buf[i]);
      if (c < 0)
        continue;
      val = (val << 6) | c;
      valb += 6;
      if (valb >= 0)
        {
          out[outlen++] = (val >> valb) & 0xFF;
          valb -= 8;
        }
    }
  *r_len = outlen;
  return out;
}

static unsigned char *
read_pem_cert (FILE *fp, size_t *r_len)
{
  char line[1024];
  char *buf = NULL;
  size_t buflen = 0;
  int in = 0;

  while (fgets (line, sizeof line, fp))
    {
      if (!in)
        {
          if (strstr (line, "BEGIN CERTIFICATE"))
            in = 1;
          continue;
        }
      if (strstr (line, "END CERTIFICATE"))
        break;
      for (char *p = line; *p; p++)
        if (*p != '\n' && *p != '\r')
          {
            buf = realloc (buf, buflen+1);
            buf[buflen++] = *p;
          }
    }
  if (!buf)
    return NULL;
  unsigned char *der = base64_decode (buf, buflen, r_len);
  free (buf);
  return der;
}

static unsigned char *
read_der_file (const char *fname, size_t *r_len)
{
  FILE *fp = fopen (fname, "rb");
  unsigned char *der;

  if (!fp)
    {
      perror ("fopen");
      exit (1);
    }

  /* Peek first byte to see whether this is PEM or DER.  */
  int c = fgetc (fp);
  if (c == EOF)
    {
      fclose (fp);
      return NULL;
    }
  ungetc (c, fp);

  if (c == 'M' || c == '-')
    der = read_pem_cert (fp, r_len);
  else
    {
      size_t size, got;
      unsigned char *buf;
      fseek (fp, 0, SEEK_END);
      size = ftell (fp);
      fseek (fp, 0, SEEK_SET);
      buf = xmalloc (size);
      got = fread (buf, 1, size, fp);
      if (got != size)
        {
          perror ("fread");
          exit (1);
        }
      *r_len = size;
      der = buf;
    }
  fclose (fp);
  return der;
}

static void
sexp_extract_octets (ksba_const_sexp_t sexp, const unsigned char **r_buf,
                     size_t *r_len)
{
  const unsigned char *p = sexp;
  if (*p != '(')
    fail ("invalid sexp");
  p++;
  if (!digitp (p))
    fail ("invalid sexp");
  unsigned long len = strtoul ((const char*)p, (char**)&p, 10);
  if (*p != ':')
    fail ("invalid sexp");
  p++;
  *r_buf = p;
  *r_len = len;
}

int
main (int argc, char **argv)
{
  gpg_error_t err;
  ksba_cert_t cert;
  const char *oid;
  ksba_sexp_t sigval, serial;
  const unsigned char *serbuf;
  size_t serlen;
  char *issuer;
  int is_ca, pathlen;

  unsigned char *der;
  size_t derlen;
  char *fname = prepend_srcdir ("samples/gost.crt");

  (void)argc; (void)argv;

  der = read_der_file (fname, &derlen);
  free (fname);
  assert (der);

  err = ksba_cert_new (&cert);
  fail_if_err (err);
  err = ksba_cert_init_from_mem (cert, der, derlen);
  fail_if_err (err);
  free (der);

  oid = ksba_cert_get_digest_algo (cert);
  assert (oid && !strcmp (oid, "1.2.643.7.1.1.3.2"));

  sigval = ksba_cert_get_sig_val (cert);
  assert (sigval && *sigval);
  ksba_free (sigval);

  err = ksba_cert_is_ca (cert, &is_ca, &pathlen);
  fail_if_err (err);
  assert (is_ca);

  serial = ksba_cert_get_serial (cert);
  sexp_extract_octets (serial, &serbuf, &serlen);
  assert (serlen == 20);
  const unsigned char expect_serial[20] =
    {0x42,0x85,0xa7,0x88,0x33,0xe0,0xce,0xa2,0xba,0x09,
     0xc5,0x84,0xbd,0x5b,0x2d,0x69,0x2f,0xd0,0xe4,0x48};
  assert (!memcmp (serbuf, expect_serial, 20));
  ksba_free (serial);

  issuer = ksba_cert_get_issuer (cert, 0);
  assert (issuer && *issuer);
  ksba_free (issuer);

  ksba_cert_release (cert);
  return 0;
}
