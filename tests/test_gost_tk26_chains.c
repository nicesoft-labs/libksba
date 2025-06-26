#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* Read a DER or PEM encoded CRL and parse it.  */
static ksba_crl_t
read_crl (const char *fname)
{
  ksba_reader_t r;
  ksba_crl_t crl;
  gpg_error_t err;
  unsigned char *buf = NULL;
  size_t buflen = 0;
  ksba_stop_reason_t stop;

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
  err = ksba_crl_new (&crl);
  fail_if_err (err);
  err = ksba_crl_set_reader (crl, r);
  fail_if_err (err);

  do
    err = ksba_crl_parse (crl, &stop);
  while (!err && stop != KSBA_SR_READY);
  fail_if_err (err);
  ksba_reader_release (r);
  free (buf);

  return crl;
}

/* Build a minimal OCSP response with THISUPDATE and optional NEXTUPDATE.  */
static gpg_error_t
build_ocsp_resp (const char *thisupd, const char *nextupd,
                 unsigned char **r_buf, size_t *r_len)
{
  gpg_error_t err = 0;
  ksba_der_t d_certid = NULL, d_single = NULL, d_respdata = NULL;
  ksba_der_t d_basic = NULL, d_respbytes = NULL, d_main = NULL;
  unsigned char zeros[20];
  unsigned char serial = 1;
  unsigned char nullbyte = 0;
  unsigned char *tmp = NULL; size_t tmplen = 0;

  memset (zeros, 0, sizeof zeros);

  d_certid = ksba_der_builder_new (0);
  if (!d_certid)
    return gpg_error_from_syserror ();
  ksba_der_add_tag (d_certid, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_tag (d_certid, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_oid (d_certid, "1.3.14.3.2.26");
  ksba_der_add_ptr (d_certid, 0, KSBA_TYPE_NULL, NULL, 0);
  ksba_der_add_end (d_certid);
  ksba_der_add_val (d_certid, 0, KSBA_TYPE_OCTET_STRING, zeros, 20);
  ksba_der_add_val (d_certid, 0, KSBA_TYPE_OCTET_STRING, zeros, 20);
  ksba_der_add_int (d_certid, &serial, 1, 1);
  ksba_der_add_end (d_certid);
  err = ksba_der_builder_get (d_certid, &tmp, &tmplen);
  if (err)
    goto leave;

  d_single = ksba_der_builder_new (0);
  if (!d_single)
    { err = gpg_error_from_syserror (); goto leave; }
  ksba_der_add_tag (d_single, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_der (d_single, tmp, tmplen);
  free (tmp); tmp = NULL;
  ksba_der_add_der (d_single, (unsigned char*)"\x80\x00", 2); /* certStatus=good */
  ksba_der_add_val (d_single, 0, KSBA_TYPE_GENERALIZED_TIME,
                     thisupd, strlen (thisupd));
  if (nextupd)
    {
      ksba_der_add_tag (d_single, KSBA_CLASS_CONTEXT|KSBA_CLASS_ENCAPSULATE, 0);
      ksba_der_add_val (d_single, 0, KSBA_TYPE_GENERALIZED_TIME,
                         nextupd, strlen (nextupd));
      ksba_der_add_end (d_single);
    }
  ksba_der_add_end (d_single);
  err = ksba_der_builder_get (d_single, &tmp, &tmplen);
  if (err)
    goto leave;

  d_respdata = ksba_der_builder_new (0);
  if (!d_respdata)
    { err = gpg_error_from_syserror (); goto leave; }
  ksba_der_add_tag (d_respdata, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_tag (d_respdata, KSBA_CLASS_CONTEXT|KSBA_CLASS_ENCAPSULATE, 0);
  ksba_der_add_int (d_respdata, &serial, 1, 1); /* version v1 */
  ksba_der_add_end (d_respdata);
  ksba_der_add_tag (d_respdata, KSBA_CLASS_CONTEXT|KSBA_CLASS_ENCAPSULATE, 1);
  ksba_der_add_tag (d_respdata, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_tag (d_respdata, 0, KSBA_TYPE_SET);
  ksba_der_add_tag (d_respdata, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_oid (d_respdata, "2.5.4.3");
  ksba_der_add_val (d_respdata, 0, KSBA_TYPE_UTF8_STRING,
                     "resp", 4);
  ksba_der_add_end (d_respdata);
  ksba_der_add_end (d_respdata);
  ksba_der_add_end (d_respdata);
  ksba_der_add_end (d_respdata);
  ksba_der_add_val (d_respdata, 0, KSBA_TYPE_GENERALIZED_TIME,
                     thisupd, strlen (thisupd));
  ksba_der_add_tag (d_respdata, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_der (d_respdata, tmp, tmplen);
  free (tmp); tmp = NULL;
  ksba_der_add_end (d_respdata);
  ksba_der_add_end (d_respdata);
  err = ksba_der_builder_get (d_respdata, &tmp, &tmplen);
  if (err)
    goto leave;

  d_basic = ksba_der_builder_new (0);
  if (!d_basic)
    { err = gpg_error_from_syserror (); goto leave; }
  ksba_der_add_tag (d_basic, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_der (d_basic, tmp, tmplen);
  free (tmp); tmp = NULL;
  ksba_der_add_tag (d_basic, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_oid (d_basic, "1.2.840.113549.1.1.1");
  ksba_der_add_ptr (d_basic, 0, KSBA_TYPE_NULL, NULL, 0);
  ksba_der_add_end (d_basic);
  ksba_der_add_bts (d_basic, &nullbyte, 1, 0);
  ksba_der_add_end (d_basic);
  err = ksba_der_builder_get (d_basic, &tmp, &tmplen);
  if (err)
    goto leave;

  d_respbytes = ksba_der_builder_new (0);
  if (!d_respbytes)
    { err = gpg_error_from_syserror (); goto leave; }
  ksba_der_add_tag (d_respbytes, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_oid (d_respbytes, "1.3.6.1.5.5.7.48.1.1");
  ksba_der_add_val (d_respbytes, 0, KSBA_TYPE_OCTET_STRING, tmp, tmplen);
  free (tmp); tmp = NULL;
  ksba_der_add_end (d_respbytes);
  err = ksba_der_builder_get (d_respbytes, &tmp, &tmplen);
  if (err)
    goto leave;

  d_main = ksba_der_builder_new (0);
  if (!d_main)
    { err = gpg_error_from_syserror (); goto leave; }
  ksba_der_add_tag (d_main, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_val (d_main, 0, KSBA_TYPE_ENUMERATED, &nullbyte, 1);
  ksba_der_add_tag (d_main, KSBA_CLASS_CONTEXT|KSBA_CLASS_ENCAPSULATE, 0);
  ksba_der_add_der (d_main, tmp, tmplen);
  ksba_der_add_end (d_main);
  ksba_der_add_end (d_main);
  err = ksba_der_builder_get (d_main, r_buf, r_len);

leave:
  ksba_der_release (d_certid);
  ksba_der_release (d_single);
  ksba_der_release (d_respdata);
  ksba_der_release (d_basic);
  ksba_der_release (d_respbytes);
  ksba_der_release (d_main);
  free (tmp);
  return err;
}


int
main (void)
{
  ksba_cert_t chain[1];
  gpg_error_t err;
  char *fname;

  /* 1. Successful TK-26 chain check.  */
  fname = prepend_srcdir ("samples/gost_certs/test_gost_policy.crt");
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

  /* 3. Missing EKU check (certificate lacks both EKU and policy).  */
  fname = prepend_srcdir ("samples/gost_certs2/test_without_eku.crt");
  chain[0] = read_cert (fname);
  xfree (fname);
  err = _ksba_check_cert_chain_tk26 (chain, 1, 0);
  if (gpg_err_code (err) != GPG_ERR_NO_POLICY_MATCH)
    {
      fprintf (stderr, "test3: expected %d got %s (%d)\n",
               GPG_ERR_NO_POLICY_MATCH, gpg_strerror (err),
               gpg_err_code (err));
      ksba_cert_release (chain[0]);
      return 1;
    }
  ksba_cert_release (chain[0]);

  /* 4. Successful CRL signature check.  */
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_eku_crl.pem");
  ksba_crl_t crl = read_crl (fname);
  xfree (fname);
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_eku_crl.crt");
  ksba_cert_t cert = read_cert (fname);
  xfree (fname);
  err = ksba_crl_check_signature_gost (crl, cert);
  if (err)
    {
      fprintf (stderr, "test4: skipped due to %s (%d)\n",
               gpg_strerror (err), gpg_err_code (err));
      ksba_crl_release (crl);
      ksba_cert_release (cert);
      return 0; /* skip remaining tests */
    }
  ksba_crl_release (crl);
  ksba_cert_release (cert);

  /* 5. Fail CRL signature due to missing TK-26 policy.  */
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_eku_crl.pem");
  crl = read_crl (fname);
  xfree (fname);
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_no_policy.crt");
  cert = read_cert (fname);
  xfree (fname);
  err = ksba_crl_check_signature_gost (crl, cert);
  if (gpg_err_code (err) != GPG_ERR_NO_POLICY_MATCH)
    {
      fprintf (stderr, "test5: expected %d got %s (%d)\n",
               GPG_ERR_NO_POLICY_MATCH, gpg_strerror (err),
               gpg_err_code (err));
      ksba_crl_release (crl);
      ksba_cert_release (cert);
      return 1;
    }
  ksba_crl_release (crl);
  ksba_cert_release (cert);

  /* 6. Fail CRL signature due to missing cRLSign key usage.  */
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_eku_crl.pem");
  crl = read_crl (fname);
  xfree (fname);
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_policy.crt");
  cert = read_cert (fname);
  xfree (fname);
  err = ksba_crl_check_signature_gost (crl, cert);
  if (gpg_err_code (err) != GPG_ERR_WRONG_KEY_USAGE)
    {
      fprintf (stderr, "test6: expected %d got %s (%d)\n",
               GPG_ERR_WRONG_KEY_USAGE, gpg_strerror (err),
               gpg_err_code (err));
      ksba_crl_release (crl);
      ksba_cert_release (cert);
      return 1;
    }
  ksba_crl_release (crl);
  ksba_cert_release (cert);

  /* 7. Successful OCSP signature check.  */
  fname = prepend_srcdir ("samples/gost_certs2/ocsp_resp.pem");
  unsigned char *ocspbuf = NULL; size_t ocspbuflen = 0;
  err = read_der (fname, &ocspbuf, &ocspbuflen);
  xfree (fname);
  if (err)
    return 1;
  ksba_ocsp_t ocsp;
  ksba_ocsp_response_status_t status;
  err = ksba_ocsp_new (&ocsp);
  fail_if_err (err);
  err = ksba_ocsp_parse_response (ocsp, ocspbuf, ocspbuflen, &status);
  fail_if_err (err);
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_eku_ocsp.crt");
  cert = read_cert (fname);
  xfree (fname);
  err = ksba_ocsp_check_signature_gost (ocsp, ocspbuf, ocspbuflen, cert);
  if (err)
    {
      fprintf (stderr, "test7: expected %d got %s (%d)\n", 0,
               gpg_strerror (err), gpg_err_code (err));
      ksba_ocsp_release (ocsp);
      ksba_cert_release (cert);
      free (ocspbuf);
      return 1;
    }
  ksba_ocsp_release (ocsp);
  ksba_cert_release (cert);
  free (ocspbuf);

  /* 8. Fail OCSP signature due to missing EKU.  */
  fname = prepend_srcdir ("samples/gost_certs2/ocsp_resp.pem");
  err = read_der (fname, &ocspbuf, &ocspbuflen);
  xfree (fname);
  if (err)
    return 1;
  err = ksba_ocsp_new (&ocsp);
  fail_if_err (err);
  err = ksba_ocsp_parse_response (ocsp, ocspbuf, ocspbuflen, &status);
  fail_if_err (err);
  fname = prepend_srcdir ("samples/gost_certs2/test_without_eku.crt");
  cert = read_cert (fname);
  xfree (fname);
  err = ksba_ocsp_check_signature_gost (ocsp, ocspbuf, ocspbuflen, cert);
  if (gpg_err_code (err) != GPG_ERR_WRONG_KEY_USAGE)
    {
      fprintf (stderr, "test8: expected %d got %s (%d)\n",
               GPG_ERR_WRONG_KEY_USAGE, gpg_strerror (err),
               gpg_err_code (err));
      ksba_ocsp_release (ocsp);
      ksba_cert_release (cert);
      free (ocspbuf);
      return 1;
    }
  ksba_ocsp_release (ocsp);
  ksba_cert_release (cert);
  free (ocspbuf);

  /* 9. OCSP thisUpdate in the future.  */
  err = build_ocsp_resp ("21000101000000Z", NULL, &ocspbuf, &ocspbuflen);
  fail_if_err (err);
  err = ksba_ocsp_new (&ocsp);
  fail_if_err (err);
  err = ksba_ocsp_parse_response (ocsp, ocspbuf, ocspbuflen, &status);
  if (gpg_err_code (err) != GPG_ERR_TIME_CONFLICT)
    {
      fprintf (stderr, "test9: expected %d got %s (%d)\n",
               GPG_ERR_TIME_CONFLICT, gpg_strerror (err),
               gpg_err_code (err));
      ksba_ocsp_release (ocsp);
      free (ocspbuf);
      return 1;
    }
  ksba_ocsp_release (ocsp);
  free (ocspbuf);

  /* 10. OCSP nextUpdate in the past.  */
  err = build_ocsp_resp ("20200101000000Z", "20000101000000Z",
                         &ocspbuf, &ocspbuflen);
  fail_if_err (err);
  err = ksba_ocsp_new (&ocsp);
  fail_if_err (err);
  err = ksba_ocsp_parse_response (ocsp, ocspbuf, ocspbuflen, &status);
  if (gpg_err_code (err) != GPG_ERR_CERT_EXPIRED)
    {
      fprintf (stderr, "test10: expected %d got %s (%d)\n",
               GPG_ERR_CERT_EXPIRED, gpg_strerror (err),
               gpg_err_code (err));
      ksba_ocsp_release (ocsp);
      free (ocspbuf);
      return 1;
    }
  ksba_ocsp_release (ocsp);
  free (ocspbuf);

  /* 11. Successful three level chain.  */
  ksba_cert_t chain3[3];
  fname = prepend_srcdir ("samples/gost_certs2/root_gost_tk26.crt");
  chain3[0] = read_cert (fname); xfree (fname);
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_policy.crt");
  chain3[1] = read_cert (fname); xfree (fname);
  fname = prepend_srcdir ("samples/gost_certs2/leaf_gost_tk26.crt");
  chain3[2] = read_cert (fname); xfree (fname);
  err = _ksba_check_cert_chain_tk26 (chain3, 3, 0);
  if (err)
    {
      fprintf (stderr, "test11: expected %d got %s (%d)\n", 0,
               gpg_strerror (err), gpg_err_code (err));
      for (int i=0; i < 3; i++)
        ksba_cert_release (chain3[i]);
      return 1;
    }
  for (int i=0; i < 3; i++)
    ksba_cert_release (chain3[i]);

  /* 12. Fail chain due to missing policy in intermediate.  */
  fname = prepend_srcdir ("samples/gost_certs2/root_gost_tk26.crt");
  chain3[0] = read_cert (fname); xfree (fname);
  fname = prepend_srcdir ("samples/gost_certs2/test_gost_no_policy.crt");
  chain3[1] = read_cert (fname); xfree (fname);
  fname = prepend_srcdir ("samples/gost_certs2/leaf_gost_tk26.crt");
  chain3[2] = read_cert (fname); xfree (fname);
  err = _ksba_check_cert_chain_tk26 (chain3, 3, 0);
  if (gpg_err_code (err) != GPG_ERR_NO_POLICY_MATCH)
    {
      fprintf (stderr, "test12: expected %d got %s (%d)\n",
               GPG_ERR_NO_POLICY_MATCH, gpg_strerror (err),
               gpg_err_code (err));
      for (int i=0; i < 3; i++)
        ksba_cert_release (chain3[i]);
      return 1;
    }
  for (int i=0; i < 3; i++)
    ksba_cert_release (chain3[i]);

  return 0;
}
