#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/ksba.h"
#define KSBA_TESTING
#define _KSBA_VISIBILITY_DEFAULT
#include "../src/keyinfo.h"
#include "t-common.h"

static int b64_val(unsigned char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

static unsigned char *
base64_decode(const char *buf, size_t len, size_t *r_len)
{
  unsigned char *out = xmalloc(len/4*3 + 4);
  size_t outlen = 0;
  int val = 0, valb = -8;
  for (size_t i=0; i < len; i++)
    {
      int c = b64_val(buf[i]);
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
read_pem_cert(FILE *fp, size_t *r_len)
{
  char line[1024];
  char *buf = NULL;
  size_t buflen = 0;
  int in = 0;
  while (fgets(line, sizeof line, fp))
    {
      if (!in)
        {
          if (strstr(line, "BEGIN CERTIFICATE"))
            in = 1;
          continue;
        }
      if (strstr(line, "END CERTIFICATE"))
        break;
      for (char *p = line; *p; p++)
        if (*p != '\n' && *p != '\r')
          {
            buf = realloc(buf, buflen+1);
            buf[buflen++] = *p;
          }
    }
  if (!buf)
    return NULL;
  unsigned char *der = base64_decode(buf, buflen, r_len);
  free(buf);
  return der;
}

static int
sexp_read_len(const unsigned char **s, unsigned long *r_len)
{
  char *endp;
  if (!**s || !isdigit(**s))
    return -1;
  *r_len = strtoul((const char*)*s, &endp, 10);
  if (*endp != ':')
    return -1;
  *s = endp + 1;
  return 0;
}

static char *
sexp_get_token(const unsigned char **s)
{
  unsigned long len;
  if (sexp_read_len(s, &len))
    return NULL;
  char *buf = xmalloc(len + 1);
  memcpy(buf, *s, len);
  buf[len] = 0;
  *s += len;
  return buf;
}

static void
parse_pubkey_sexp(const unsigned char *sexp, char **r_algo, char **r_curve)
{
  const unsigned char *p = sexp;
  *r_algo = NULL;
  *r_curve = NULL;
  if (*p != '(')
    return;
  p++;
  char *tag = sexp_get_token(&p);
  if (!tag || strcmp(tag, "public-key"))
    {
      xfree(tag);
      return;
    }
  xfree(tag);
  if (*p != '(')
    return;
  p++;
  *r_algo = sexp_get_token(&p);
  while (*p == '(')
    {
      char *name, *value;
      p++;
      name = sexp_get_token(&p);
      value = sexp_get_token(&p);
      if (*p != ')')
        {
          xfree(name); xfree(value);
          break;
        }
      p++;
      if (name && !strcmp(name, "curve"))
        {
          *r_curve = value;
        }
      else
        xfree(value);
      xfree(name);
    }
}

int
main(int argc, char **argv)
{
  gpg_error_t err;
  char *fname = prepend_srcdir("samples/gost.crt");
  FILE *fp = fopen(fname, "r");
  if (!fp)
    {
      perror("fopen");
      return 1;
    }
  size_t derlen;
  unsigned char *der = read_pem_cert(fp, &derlen);
  fclose(fp);
  if (!der)
    {
      fprintf(stderr, "failed to decode PEM\n");
      return 1;
    }
  char tmpname[] = "/tmp/gostXXXXXX";
  int tfd = mkstemp(tmpname);
  if (tfd == -1)
    {
      perror("mkstemp");
      return 1;
    }
  FILE *tfp = fdopen(tfd, "wb+");
  fwrite(der, derlen, 1, tfp);
  fflush(tfp);
  rewind(tfp);

  ksba_reader_t reader;
  err = ksba_reader_new(&reader);
  fail_if_err(err);
  err = ksba_reader_set_file(reader, tfp);
  fail_if_err(err);

  ksba_cert_t cert;
  err = ksba_cert_new(&cert);
  fail_if_err(err);

  /* No ksba_cert_set_reader/ksba_cert_parse in this version; use read_der */
  err = ksba_cert_read_der(cert, reader);
  fail_if_err(err);

  char *subject = ksba_cert_get_subject(cert, 0);
  char *issuer = ksba_cert_get_issuer(cert, 0);
  ksba_sexp_t pub = ksba_cert_get_public_key(cert);

  char *algo = NULL, *curve = NULL;
  if (pub)
    parse_pubkey_sexp(pub, &algo, &curve);

  assert(algo && !strcmp(algo, "1.2.643.7.1.1.1.1"));
  assert(curve && !strncmp(curve, "1.2.643.7.1.2.1", 14));

  printf("subject: %s\n", subject);
  printf("issuer: %s\n", issuer);
  printf("algorithm: %s\n", algo);
  printf("curve: %s\n", curve);
  if (pub)
    {
      printf("public key: ");
      print_sexp_hex(pub);
      putchar('\n');
    }

  ksba_free(pub);
  ksba_free(subject);
  ksba_free(issuer);
  xfree(algo);
  xfree(curve);

  ksba_cert_release(cert);
  ksba_reader_release(reader);
  fclose(tfp);
  unlink(tmpname);
  free(der);
  free(fname);
  return 0;
}
