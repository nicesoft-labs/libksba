#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "ksba.h"
#include "reader.h"

/* Simple base64 decoder.  */
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
  for (size_t i = 0; i < inlen; i++)
    {
      int d = b64val (in[i]);
      if (d >= 0)
        {
          val = (val << 6) + d;
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

/* Extract the binary certificate from a PEM buffer.  */
static gpg_error_t
pem_to_der (const char *buffer, size_t length,
            unsigned char **r_der, size_t *r_derlen)
{
  const char *p = buffer;
  const char *end = buffer + length;
  int inside = 0;
  char *accum = NULL;
  size_t acclen = 0, accsize = 0;

  while (p < end)
    {
      const char *lineend = memchr (p, '\n', end - p);
      size_t linelen = lineend? (lineend - p) : (end - p);
      const char *line = p;
      while (linelen && (line[linelen-1] == '\r' || line[linelen-1] == '\n'))
        linelen--;

      if (!inside)
        {
          if (linelen >= 10 && !strncmp (line, "-----BEGIN", 10))
            inside = 1;
        }
      else if (linelen >= 8 && !strncmp (line, "-----END", 8))
        {
          break;
        }
      else
        {
          if (acclen + linelen + 1 > accsize)
            {
              accsize = accsize*2 + linelen + 1;
              accum = xrealloc (accum, accsize);
            }
          memcpy (accum+acclen, line, linelen);
          acclen += linelen;
        }

      if (!lineend)
        break;
      p = lineend + 1;
    }

  if (!accum)
    return gpg_error (GPG_ERR_BAD_DATA);
  accum[acclen] = 0;
  gpg_error_t err = base64_decode (accum, acclen, r_der, r_derlen);
  xfree (accum);
  return err;
}

/* Read a PEM encoded certificate from READER into CERT.  */
gpg_error_t
ksba_cert_read_pem (ksba_cert_t cert, ksba_reader_t reader)
{
  gpg_error_t err;
  char tmpbuf[1024];
  char *data = NULL;
  size_t datalen = 0, datasize = 0;
  size_t nread;

  if (!cert || !reader)
    return gpg_error (GPG_ERR_INV_VALUE);

  for (;;)
    {
      err = ksba_reader_read (reader, tmpbuf, sizeof tmpbuf, &nread);
      if (err && gpg_err_code (err) != GPG_ERR_EOF)
        {
          xfree (data);
          return err;
        }
      if (nread)
        {
          if (datalen + nread > datasize)
            {
              datasize = datasize*2 + nread + 1024;
              data = xrealloc (data, datasize);
            }
          memcpy (data+datalen, tmpbuf, nread);
          datalen += nread;
        }
      if (gpg_err_code (err) == GPG_ERR_EOF)
        break;
    }

  unsigned char *der = NULL;
  size_t derlen = 0;
  err = pem_to_der (data, datalen, &der, &derlen);
  xfree (data);
  if (err)
    return err;

  ksba_reader_t memr;
  err = ksba_reader_new (&memr);
  if (err)
    {
      xfree (der);
      return err;
    }
  err = ksba_reader_set_mem (memr, der, derlen);
  if (err)
    {
      ksba_reader_release (memr);
      xfree (der);
      return err;
    }
  err = ksba_cert_read_der (cert, memr);
  ksba_reader_release (memr);
  xfree (der);
  return err;
}

/* Convenience function initializing CERT from a PEM buffer.  */
gpg_error_t
ksba_cert_init_from_pem (ksba_cert_t cert, const void *buffer, size_t length)
{
  gpg_error_t err;
  ksba_reader_t r;

  err = ksba_reader_new (&r);
  if (err)
    return err;
  err = ksba_reader_set_mem (r, buffer, length);
  if (err)
    {
      ksba_reader_release (r);
      return err;
    }
  err = ksba_cert_read_pem (cert, r);
  ksba_reader_release (r);
  return err;
}
