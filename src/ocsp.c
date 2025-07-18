/* ocsp.c - OCSP (rfc2560)
 * Copyright (C) 2003, 2004, 2005, 2006, 2012 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * KSBA is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gcrypt.h>
#include <ctype.h>

#include "util.h"

#include "cert.h"
#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "ocsp.h"

/* Reverse byte order helper.  */
static void
invert_bytes (unsigned char *dst, const unsigned char *src, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
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


static const char oidstr_sha1[] = "1.3.14.3.2.26";
static const char oidstr_ocsp_basic[] = "1.3.6.1.5.5.7.48.1.1";
static const char oidstr_ocsp_nonce[] = "1.3.6.1.5.5.7.48.1.2";

/* Check for the presence of a TK-26 policy in CERT.  */
static gpg_error_t
check_policy_tk26 (ksba_cert_t cert)
{
  gpg_error_t err;
  char *pols = NULL;
  int ok = 0;

  err = ksba_cert_get_cert_policies (cert, &pols);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    return 0;
  if (err)
    return err;

  for (char *line = pols; line && *line; )
    {
      char *end = strchr (line, '\n');
      if (!end)
        end = line + strlen (line);
      if (end - line >= 7 && !memcmp (line, "1.2.643", 7))
        {
          ok = 1;
          break;
        }
      if (*end)
        line = end + 1;
      else
        break;
    }
  xfree (pols);

  return ok? 0 : gpg_error (GPG_ERR_NO_POLICY_MATCH);
}

/* Verify that CERT carries the OCSP signing extended key usage.  */
static gpg_error_t
check_ocsp_signing_eku (ksba_cert_t cert)
{
  gpg_error_t err;
  char *usages = NULL;
  int ok = 0;

  err = ksba_cert_get_ext_key_usages (cert, &usages);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
  if (err)
    return err;

  for (char *line = usages; line && *line; )
    {
      char *end = strchr (line, '\n');
      if (!end)
        end = line + strlen (line);
      if (end - line == 19 && !memcmp (line, "1.3.6.1.5.5.7.3.9", 19))
        {
          ok = 1;
          break;
        }
      if (*end)
        line = end + 1;
      else
        break;
    }
  xfree (usages);

  return ok? 0 : gpg_error (GPG_ERR_WRONG_KEY_USAGE);
}


#if 0
static void
dump_hex (const unsigned char *p, size_t n)
{
  if (!p)
    fputs ("none", stderr);
  else
    {
      for (; n; n--, p++)
        fprintf (stderr, " %02X", *p);
    }
}
#endif


/* Create a new OCSP object and retrun it in R_OCSP.  Return 0 on
   success or an error code.
 */
gpg_error_t
ksba_ocsp_new (ksba_ocsp_t *r_ocsp)
{
  *r_ocsp = xtrycalloc (1, sizeof **r_ocsp);
  if (!*r_ocsp)
    return gpg_error_from_syserror ();
  return 0;
}


static void
release_ocsp_certlist (struct ocsp_certlist_s *cl)
{
  while (cl)
    {
      struct ocsp_certlist_s *tmp = cl->next;
      ksba_cert_release (cl->cert);
      xfree (cl);
      cl = tmp;
    }
}


static void
release_ocsp_extensions (struct ocsp_extension_s *ex)
{
  while (ex)
    {
      struct ocsp_extension_s *tmp = ex->next;
      xfree (ex);
      ex = tmp;
    }
}


/* Release the OCSP object and all its resources. Passing NULL for
   OCSP is a valid nop. */
void
ksba_ocsp_release (ksba_ocsp_t ocsp)
{
  struct ocsp_reqitem_s *ri;

  if (!ocsp)
    return;
  xfree (ocsp->digest_oid);
  xfree (ocsp->sig_oid);
  xfree (ocsp->request_buffer);
  for (; (ri=ocsp->requestlist); ri = ocsp->requestlist )
    {
      ocsp->requestlist = ri->next;
      ksba_cert_release (ri->cert);
      ksba_cert_release (ri->issuer_cert);
      release_ocsp_extensions (ri->single_extensions);
      xfree (ri->serialno);
    }
  xfree (ocsp->sigval);
  xfree (ocsp->responder_id.name);
  xfree (ocsp->responder_id.keyid);
  release_ocsp_certlist (ocsp->received_certs);
  release_ocsp_extensions (ocsp->response_extensions);
  xfree (ocsp);
}



/* Set the hash algorithm to be used for signing the request to OID.
   Using this function will force the creation of a signed
   request.  */
gpg_error_t
ksba_ocsp_set_digest_algo (ksba_ocsp_t ocsp, const char *oid)
{
  if (!ocsp || !oid || !*oid)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (ocsp->digest_oid)
    xfree (ocsp->digest_oid);
  ocsp->digest_oid = xtrystrdup (oid);
  if (!ocsp->digest_oid)
    return gpg_error_from_syserror ();
  return 0;
}


gpg_error_t
ksba_ocsp_set_requestor (ksba_ocsp_t ocsp, ksba_cert_t cert)
{
  (void)ocsp;
  (void)cert;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


/* Add the certificate CERT for which the status is to be requested
   and it's issuer certificate ISSUER_CERT to the context.  This
   function may be called multiple time to create a list of targets to
   get combined into one actual request. */
gpg_error_t
ksba_ocsp_add_target (ksba_ocsp_t ocsp,
                      ksba_cert_t cert, ksba_cert_t issuer_cert)
{
  struct ocsp_reqitem_s *ri;

  if (!ocsp || !cert || !issuer_cert)
    return gpg_error (GPG_ERR_INV_VALUE);

  ri = xtrycalloc (1, sizeof *ri);
  if (!ri)
    return gpg_error_from_syserror ();
  ksba_cert_ref (cert);
  ri->cert = cert;
  ksba_cert_ref (issuer_cert);
  ri->issuer_cert = issuer_cert;

  ri->next = ocsp->requestlist;
  ocsp->requestlist = ri;

  return 0;
}


/* Set the nonce to be used for the request to the content of the
   buffer NONCE of size NONCELEN.  Libksba may have an upper limit of
   the allowed size of the nonce; if the supplied nonce is larger it
   will be truncated and the actual used length of the nonce returned.
   To detect the implementation limit (which should be considered as a
   good suggestion), the function may be called with NULL for NONCE,
   in which case the maximal usable noncelength is returned. The
   function returns the length of the nonce which will be used. */
size_t
ksba_ocsp_set_nonce (ksba_ocsp_t ocsp, unsigned char *nonce, size_t noncelen)
{
  if (!ocsp)
    return 0;
  if (!nonce)
    return sizeof ocsp->nonce;
  if (noncelen > sizeof ocsp->nonce)
    noncelen = sizeof ocsp->nonce;
  if (noncelen)
    {
      memcpy (ocsp->nonce, nonce, noncelen);
    }
  ocsp->noncelen = noncelen;
  return noncelen;
}


/* Compute the SHA-1 nameHash for the certificate CERT and put it in
   the buffer SHA1_BUFFER which must have been allocated to at least
   20 bytes. */
static gpg_error_t
issuer_name_hash (ksba_cert_t cert, unsigned char *sha1_buffer)
{
  gpg_error_t err;
  const unsigned char *ptr;
  size_t length, dummy;

  err = _ksba_cert_get_subject_dn_ptr (cert, &ptr, &length);
  if (!err)
    {
      err = _ksba_hash_buffer (NULL, ptr, length, 20, sha1_buffer, &dummy);
      if (!err && dummy != 20)
        err = gpg_error (GPG_ERR_BUG);
    }
  return err;
}

/* Compute the SHA-1 hash of the public key of CERT and put it in teh
   buffer SHA1_BUFFER which must have been allocated with at least 20
   bytes. */
static gpg_error_t
issuer_key_hash (ksba_cert_t cert, unsigned char *sha1_buffer)
{
  gpg_error_t err;
  const unsigned char *ptr;
  size_t length, dummy;

  err = _ksba_cert_get_public_key_ptr (cert, &ptr, &length);
  if (!err)
    {
      err = _ksba_hash_buffer (NULL, ptr, length, 20, sha1_buffer, &dummy);
      if (!err && dummy != 20)
        err = gpg_error (GPG_ERR_BUG);
    }
  return err;
}


/* Write the extensions for a request to WOUT. */
static gpg_error_t
write_request_extensions (ksba_ocsp_t ocsp, ksba_writer_t wout)
{
  gpg_error_t err;
  unsigned char *buf;
  size_t buflen;
  unsigned char *p;
  size_t derlen;
  ksba_writer_t w1 = NULL;
  ksba_writer_t w2 = NULL;

  if (!ocsp->noncelen)
    return 0; /* We do only support the nonce extension.  */

  /* Create writer objects for construction of the extension. */
  err = ksba_writer_new (&w2);
  if (!err)
    err = ksba_writer_set_mem (w2, 256);
  if (!err)
    err = ksba_writer_new (&w1);
  if (!err)
    err = ksba_writer_set_mem (w1, 256);
  if (err)
    goto leave;

  /* Write OID and nonce.  */
  err = ksba_oid_from_str (oidstr_ocsp_nonce, &buf, &buflen);
  if (err)
    goto leave;
  err = _ksba_ber_write_tl (w1, TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, buflen);
  if (!err)
    err = ksba_writer_write (w1, buf, buflen);
  xfree (buf); buf = NULL;
  /* We known that the nonce is short enough to put the tag into 2 bytes, thus
     we write the encapsulating octet string directly with a fixed length. */
  if (!err)
    err = _ksba_ber_write_tl (w1, TYPE_OCTET_STRING, CLASS_UNIVERSAL, 0,
                              2+ocsp->noncelen);
  if (!err)
    err = _ksba_ber_write_tl (w1, TYPE_OCTET_STRING, CLASS_UNIVERSAL, 0,
                              ocsp->noncelen);
  if (!err)
    err = ksba_writer_write (w1, ocsp->nonce, ocsp->noncelen);

  /* Put a sequence around. */
  p = ksba_writer_snatch_mem (w1, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w1);
      goto leave;
    }
  err = _ksba_ber_write_tl (w2, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, derlen);
  if (!err)
    err = ksba_writer_write (w2, p, derlen);
  xfree (p); p = NULL;

  /* Put the sequence around all extensions.  */
  err = ksba_writer_set_mem (w1, 256);
  if (err)
    goto leave;
  p = ksba_writer_snatch_mem (w2, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w2);
      goto leave;
    }
  err = _ksba_ber_write_tl (w1, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, derlen);
  if (!err)
    err = ksba_writer_write (w1, p, derlen);
  xfree (p); p = NULL;

  /* And put a context tag around everything.  */
  p = ksba_writer_snatch_mem (w1, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w1);
      goto leave;
    }
  err = _ksba_ber_write_tl (wout, 2, CLASS_CONTEXT, 1, derlen);
  if (!err)
    err = ksba_writer_write (wout, p, derlen);
  xfree (p); p = NULL;


 leave:
  ksba_writer_release (w2);
  ksba_writer_release (w1);
  return err;
}


/* Build a request from the current context.  The function checks that
   all necessary information have been set and stores the prepared
   request in the context.  A subsequent ksba_ocsp_build_request may
   then be used to retrieve this request.  Optional the requestmay be
   signed beofre calling ksba_ocsp_build_request.
 */
gpg_error_t
ksba_ocsp_prepare_request (ksba_ocsp_t ocsp)
{
  gpg_error_t err;
  struct ocsp_reqitem_s *ri;
  unsigned char *p;
  const unsigned char *der;
  size_t derlen;
  struct tag_info ti;
  ksba_writer_t w1 = NULL;
  ksba_writer_t w2 = NULL;
  ksba_writer_t w3 = NULL;
  ksba_writer_t w4, w5, w6, w7; /* Used as aliases. */

  if (!ocsp)
    return gpg_error (GPG_ERR_INV_VALUE);

  xfree (ocsp->request_buffer);
  ocsp->request_buffer = NULL;
  ocsp->request_buflen = 0;

  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);

  /* Create three writer objects for construction of the request. */
  err = ksba_writer_new (&w3);
  if (!err)
    err = ksba_writer_set_mem (w3, 2048);
  if (!err)
    err = ksba_writer_new (&w2);
  if (!err)
    err = ksba_writer_new (&w1);
  if (err)
    goto leave;


  /* Loop over all single requests. */
  for (ri=ocsp->requestlist; ri; ri = ri->next)
    {
      err = ksba_writer_set_mem (w2, 256);
      if (!err)
        err = ksba_writer_set_mem (w1, 256);
      if (err)
        goto leave;

      /* Write the AlgorithmIdentifier. */
      err = _ksba_der_write_algorithm_identifier (w1, oidstr_sha1, NULL, 0);
      if (err)
        goto leave;

      /* Compute the issuerNameHash and write it into the CertID object. */
      err = issuer_name_hash (ri->issuer_cert, ri->issuer_name_hash);
      if (!err)
        err = _ksba_ber_write_tl (w1, TYPE_OCTET_STRING, CLASS_UNIVERSAL, 0,20);
      if (!err)
        err = ksba_writer_write (w1, ri->issuer_name_hash, 20);
      if(err)
        goto leave;

      /* Compute the issuerKeyHash and write it. */
      err = issuer_key_hash (ri->issuer_cert, ri->issuer_key_hash);
      if (!err)
        err = _ksba_ber_write_tl (w1, TYPE_OCTET_STRING, CLASS_UNIVERSAL, 0,20);
      if (!err)
        err = ksba_writer_write (w1, ri->issuer_key_hash, 20);
      if (err)
        goto leave;

      /* Write the serialNumber of the certificate to be checked. */
      err = _ksba_cert_get_serial_ptr (ri->cert, &der, &derlen);
      if (!err)
        err = ksba_writer_write (w1, der, derlen);
      if (err)
        goto leave;
      /* Store the integer value.  */
      {
        const unsigned char *tmpder = der;
        size_t tmpderlen = derlen;

        err = parse_integer (&tmpder, &tmpderlen, &ti);
        if (err)
          goto leave;
        xfree (ri->serialno);
        ri->serialno = xtrymalloc (tmpderlen);
        if (!ri->serialno)
          {
            err = gpg_error_from_syserror ();
            goto leave;
          }
        memcpy (ri->serialno, tmpder, tmpderlen);
        ri->serialnolen = tmpderlen;
      }

      /* Now write it out as a sequence to the outer certID object. */
      p = ksba_writer_snatch_mem (w1, &derlen);
      if (!p)
        {
          err = ksba_writer_error (w1);
          goto leave;
        }
      err = _ksba_ber_write_tl (w2, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                                1, derlen);
      if (!err)
        err = ksba_writer_write (w2, p, derlen);
      xfree (p); p = NULL;
      if (err)
        goto leave;

      /* Here we would write singleRequestExtensions. */

      /* Now write it out as a sequence to the outer Request object. */
      p = ksba_writer_snatch_mem (w2, &derlen);
      if (!p)
        {
          err = ksba_writer_error (w2);
          goto leave;
        }
      err = _ksba_ber_write_tl (w3, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                                1, derlen);
      if (!err)
        err = ksba_writer_write (w3, p, derlen);
      xfree (p); p = NULL;
      if (err)
        goto leave;

    } /* End of looping over single requests. */

  /* Reuse writers; for clarity, use new names. */
  w4 = w1;
  w5 = w2;
  err = ksba_writer_set_mem (w4, 2048);
  if (!err)
    err = ksba_writer_set_mem (w5, 2048);
  if (err)
    goto leave;

  /* Put a sequence tag before the requestList. */
  p = ksba_writer_snatch_mem (w3, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w3);
      goto leave;
    }
  err = _ksba_ber_write_tl (w4, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, derlen);
  if (!err)
    err = ksba_writer_write (w4, p, derlen);
  xfree (p); p = NULL;
  if (err)
    goto leave;

  /* The requestExtensions go here. */
  err = write_request_extensions (ocsp, w4);

  /* Write the tbsRequest. */

  /* The version is default, thus we don't write it. */

  /* The requesterName would go here. */

  /* Write the requestList. */
  p = ksba_writer_snatch_mem (w4, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w4);
      goto leave;
    }
  err = _ksba_ber_write_tl (w5, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, derlen);
  if (!err)
    err = ksba_writer_write (w5, p, derlen);
  xfree (p); p = NULL;
  if (err)
    goto leave;

  /* Reuse writers; for clarity, use new names. */
  w6 = w3;
  w7 = w4;
  err = ksba_writer_set_mem (w6, 2048);
  if (!err)
    err = ksba_writer_set_mem (w7, 2048);
  if (err)
    goto leave;

  /* Prepend a sequence tag. */
  p = ksba_writer_snatch_mem (w5, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w5);
      goto leave;
    }
  err = _ksba_ber_write_tl (w6, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, derlen);
  if (!err)
    err = ksba_writer_write (w6, p, derlen);
  xfree (p); p = NULL;
  if (err)
    goto leave;

  /* Write the ocspRequest. */

  /* Note that we do not support the optional signature, because this
     saves us one writer object. */

  /* Prepend a sequence tag. */
/*   p = ksba_writer_snatch_mem (w6, &derlen); */
/*   if (!p) */
/*     { */
/*       err = ksba_writer_error (w6); */
/*       goto leave; */
/*     } */
/*   err = _ksba_ber_write_tl (w7, TYPE_SEQUENCE, CLASS_UNIVERSAL, */
/*                             1, derlen); */
/*   if (!err) */
/*     err = ksba_writer_write (w7, p, derlen); */
/*   xfree (p); p = NULL; */
/*   if (err) */
/*     goto leave; */


  /* Read out the entire request. */
  p = ksba_writer_snatch_mem (w6, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w6);
      goto leave;
    }
  ocsp->request_buffer = p;
  ocsp->request_buflen = derlen;
  /* Ready. */

 leave:
  ksba_writer_release (w3);
  ksba_writer_release (w2);
  ksba_writer_release (w1);
  return err;
}


gpg_error_t
ksba_ocsp_hash_request (ksba_ocsp_t ocsp,
                        void (*hasher)(void *, const void *,
                                       size_t length),
                        void *hasher_arg)
{
  (void)ocsp;
  (void)hasher;
  (void)hasher_arg;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


gpg_error_t
ksba_ocsp_set_sig_val (ksba_ocsp_t ocsp,
                       ksba_const_sexp_t sigval)
{
  (void)ocsp;
  (void)sigval;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


gpg_error_t
ksba_ocsp_add_cert (ksba_ocsp_t ocsp, ksba_cert_t cert)
{
  (void)ocsp;
  (void)cert;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}



/* Build a request from the current context.  The function checks that
   all necessary information have been set and then returns an
   allocated buffer with the resulting request.
 */
gpg_error_t
ksba_ocsp_build_request (ksba_ocsp_t ocsp,
                         unsigned char **r_buffer, size_t *r_buflen)
{
  gpg_error_t err;

  if (!ocsp || !r_buffer || !r_buflen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *r_buffer = NULL;
  *r_buflen = 0;

  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (!ocsp->request_buffer)
    {
      /* No prepare done, do it now. */
      err = ksba_ocsp_prepare_request (ocsp);
      if (err)
        return err;
      assert (ocsp->request_buffer);
    }
  *r_buffer = ocsp->request_buffer;
  *r_buflen = ocsp->request_buflen;
  ocsp->request_buffer = NULL;
  ocsp->request_buflen = 0;
  return 0;
}



/*
   Parse the response extensions and store them aways.  While doing
   this we also check the nonce extension.  A typical data ASN.1 blob
   with only the nonce extension as passed to this function is:

    SEQUENCE {
      SEQUENCE {
        OBJECT IDENTIFIER ocspNonce (1 3 6 1 5 5 7 48 1 2)
        OCTET STRING, encapsulates {
            INTEGER
              41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50
            }
        }
      }
*/

static int
parse_response_extensions (ksba_ocsp_t ocsp,
                          const unsigned char *data, size_t datalen)
{
  gpg_error_t err;
  struct tag_info ti;
  size_t length;
  char *oid = NULL;

  assert (!ocsp->response_extensions);
  err = parse_sequence (&data, &datalen, &ti);
  if (err)
    goto leave;
  length = ti.length;
  while (length)
    {
      struct ocsp_extension_s *ex;
      int is_crit;

      err = parse_sequence (&data, &datalen, &ti);
      if (err)
        goto leave;
      if (length < ti.nhdr + ti.length)
        {
          err = gpg_error (GPG_ERR_BAD_BER);
          goto leave;
        }
      length -= ti.nhdr + ti.length;

      xfree (oid);
      err = parse_object_id_into_str (&data, &datalen, &oid);
      if (err)
        goto leave;
      is_crit = 0;
      err = parse_optional_boolean (&data, &datalen, &is_crit);
      if (err)
        goto leave;
      err = parse_octet_string (&data, &datalen, &ti);
      if (err)
        goto leave;
      if (!strcmp (oid, oidstr_ocsp_nonce))
        {
          err = parse_octet_string (&data, &datalen, &ti);
          if (err)
            goto leave;
          if (ocsp->noncelen != ti.length
              || memcmp (ocsp->nonce, data, ti.length))
            ocsp->bad_nonce = 1;
        }
      if (ti.length > (1<<24))
        {
          /* Bail out on much too large objects.  */
          err = gpg_error (GPG_ERR_BAD_BER);
          goto leave;
        }
      ex = xtrymalloc (sizeof *ex + strlen (oid) + ti.length);
      if (!ex)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      ex->crit = is_crit;
      strcpy (ex->data, oid);
      ex->data[strlen (oid)] = 0;
      ex->off = strlen (oid) + 1;
      ex->len = ti.length;
      memcpy (ex->data + ex->off, data, ti.length);
      ex->next = ocsp->response_extensions;
      ocsp->response_extensions = ex;

      parse_skip (&data, &datalen, &ti); /* Skip the octet string / integer. */
    }

 leave:
  xfree (oid);
  return err;
}


/*
   Parse single extensions and store them away.
*/
static int
parse_single_extensions (struct ocsp_reqitem_s *ri,
                         const unsigned char *data, size_t datalen)
{
  gpg_error_t err;
  struct tag_info ti;
  size_t length;
  char *oid = NULL;

  assert (ri && !ri->single_extensions);
  err = parse_sequence (&data, &datalen, &ti);
  if (err)
    goto leave;
  length = ti.length;
  while (length)
    {
      struct ocsp_extension_s *ex;
      int is_crit;

      err = parse_sequence (&data, &datalen, &ti);
      if (err)
        goto leave;
      if (length < ti.nhdr + ti.length)
        {
          err = gpg_error (GPG_ERR_BAD_BER);
          goto leave;
        }
      length -= ti.nhdr + ti.length;

      xfree (oid);
      err = parse_object_id_into_str (&data, &datalen, &oid);
      if (err)
        goto leave;
      is_crit = 0;
      err = parse_optional_boolean (&data, &datalen, &is_crit);
      if (err)
        goto leave;
      err = parse_octet_string (&data, &datalen, &ti);
      if (err)
        goto leave;
      if (ti.length > (1<<24))
        {
          /* Bail out on much too large objects.  */
          err = gpg_error (GPG_ERR_BAD_BER);
          goto leave;
        }
      ex = xtrymalloc (sizeof *ex + strlen (oid) + ti.length);
      if (!ex)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      ex->crit = is_crit;
      strcpy (ex->data, oid);
      ex->data[strlen (oid)] = 0;
      ex->off = strlen (oid) + 1;
      ex->len = ti.length;
      memcpy (ex->data + ex->off, data, ti.length);
      ex->next = ri->single_extensions;
      ri->single_extensions = ex;

      parse_skip (&data, &datalen, &ti); /* Skip the octet string / integer. */
    }

 leave:
  xfree (oid);
  return err;
}


/* Parse the first part of a response:

     OCSPResponse ::= SEQUENCE {
        responseStatus         OCSPResponseStatus,
        responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }

     OCSPResponseStatus ::= ENUMERATED {
         successful            (0),  --Response has valid confirmations
         malformedRequest      (1),  --Illegal confirmation request
         internalError         (2),  --Internal error in issuer
         tryLater              (3),  --Try again later
                                     --(4) is not used
         sigRequired           (5),  --Must sign the request
         unauthorized          (6)   --Request unauthorized
     }

     ResponseBytes ::=       SEQUENCE {
         responseType   OBJECT IDENTIFIER,
         response       OCTET STRING }

   On success the RESPONSE_STATUS field of OCSP will be set to the
   response status and DATA will now point to the first byte in the
   octet string of the response; RLEN will be set to the length of
   this octet string.  Note thate DATALEN is also updated but might
   point to a value larger than RLEN points to, if the provided data
   is a part of a larger image. */
static gpg_error_t
parse_response_status (ksba_ocsp_t ocsp,
                       unsigned char const **data, size_t *datalen,
                       size_t *rlength)
{
  gpg_error_t err;
  struct tag_info ti;
  char *oid;

  *rlength = 0;
  /* Parse the OCSPResponse sequence. */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  /* Parse the OCSPResponseStatus. */
  err = parse_enumerated (data, datalen, &ti, 1);
  if (err)
    return err;
  switch (**data)
    {
    case 0:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_SUCCESS; break;
    case 1:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_MALFORMED; break;
    case 2:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_INTERNAL; break;
    case 3:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_TRYLATER; break;
    case 5:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_SIGREQUIRED; break;
    case 6:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_UNAUTHORIZED; break;
    default: ocsp->response_status = KSBA_OCSP_RSPSTATUS_OTHER; break;
    }
  parse_skip (data, datalen, &ti);

  if (ocsp->response_status)
      return 0; /* This is an error reponse; we have to stop here. */

  /* We have a successful reponse status, thus we check that
     ResponseBytes are actually available. */
  err = parse_context_tag (data, datalen, &ti, 0);
  if (err)
    return err;
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  err = parse_object_id_into_str (data, datalen, &oid);
  if (err)
    return err;
  if (strcmp (oid, oidstr_ocsp_basic))
    {
      xfree (oid);
      return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);
    }
  xfree (oid);

  /* Check that the next field is an octet string. */
  err = parse_octet_string (data, datalen, &ti);
  if (err)
    return err;
  *rlength = ti.length;
  return 0;
}

/* Parse the object:

     SingleResponse ::= SEQUENCE {
      certID                       CertID,
      certStatus                   CertStatus,
      thisUpdate                   GeneralizedTime,
      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }

     CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }

     RevokedInfo ::= SEQUENCE {
       revocationTime              GeneralizedTime,
       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }

     UnknownInfo ::= NULL -- this can be replaced with an enumeration

*/

static gpg_error_t
parse_single_response (ksba_ocsp_t ocsp,
                       unsigned char const **data, size_t *datalen)
{
  gpg_error_t err;
  struct tag_info ti;
  const unsigned char *savedata;
  const unsigned char *endptr;
  size_t savedatalen;
  size_t n;
  char *oid;
  ksba_isotime_t this_update, next_update, revocation_time;
  ksba_isotime_t now;
  int look_for_request;
  const unsigned char *name_hash;
  const unsigned char *key_hash;
  const unsigned char *serialno;
  size_t serialnolen;
  struct ocsp_reqitem_s *request_item = NULL;

  /* The SingeResponse sequence. */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  endptr = *data + ti.length;

  /* The CertID is
       SEQUENCE {
         hashAlgorithm       AlgorithmIdentifier,
         issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
         issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
         serialNumber        CertificateSerialNumber }
  */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  err = _ksba_parse_algorithm_identifier (*data, *datalen, &n, &oid);
  if (err)
    return err;
  assert (n <= *datalen);
  *data += n;
  *datalen -= n;
  /* gpgrt_log_debug ("algorithmIdentifier is `%s'\n", oid); */
  look_for_request = !strcmp (oid, oidstr_sha1);
  xfree (oid);

  err = parse_octet_string (data, datalen, &ti);
  if (err)
    return err;
  name_hash = *data;
/*   fprintf (stderr, "issuerNameHash=");  */
/*   dump_hex (*data, ti.length); */
/*   putc ('\n', stderr); */
  if (ti.length != 20)
    look_for_request = 0; /* Can't be a SHA-1 digest. */
  parse_skip (data, datalen, &ti);

  err = parse_octet_string (data, datalen, &ti);
  if (err)
    return err;
  key_hash = *data;
/*   fprintf (stderr, "issuerKeyHash=");  */
/*   dump_hex (*data, ti.length); */
/*   putc ('\n', stderr); */
  if (ti.length != 20)
    look_for_request = 0; /* Can't be a SHA-1 digest. */
  parse_skip (data, datalen, &ti);

  err= parse_integer (data, datalen, &ti);
  if (err)
    return err;
  serialno = *data;
  serialnolen = ti.length;
/*   fprintf (stderr, "serialNumber=");  */
/*   dump_hex (*data, ti.length); */
/*   putc ('\n', stderr); */
  parse_skip (data, datalen, &ti);

  if (look_for_request)
    {
      for (request_item = ocsp->requestlist;
           request_item; request_item = request_item->next)
        if (!memcmp (request_item->issuer_name_hash, name_hash, 20)
            && !memcmp (request_item->issuer_key_hash, key_hash, 20)
            && request_item->serialnolen == serialnolen
            && !memcmp (request_item->serialno, serialno, serialnolen))
            break; /* Got it. */
    }


  /*
     CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }
  */
  *revocation_time = 0;
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  else if (ti.class == CLASS_CONTEXT && ti.tag == 0  && !ti.is_constructed)
    { /* good */
      if (!ti.length)
        ; /* Cope with zero length objects. */
      else if (*datalen && !**data)
        { /* Skip the NULL. */
          (*datalen)--;
          (*data)++;
        }
      else
        return gpg_error (GPG_ERR_INV_OBJ);

      if (request_item)
        request_item->status = KSBA_STATUS_GOOD;
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    { /* revoked */
      ksba_crl_reason_t reason = KSBA_CRLREASON_UNSPECIFIED;

      err = parse_asntime_into_isotime (data, datalen, revocation_time);
      if (err)
        return err;
/*       fprintf (stderr, "revocationTime=%s\n", revocation_time); */
      savedata = *data;
      savedatalen = *datalen;
      err = parse_context_tag (data, datalen, &ti, 0);
      if (err)
        {
          *data = savedata;
          *datalen = savedatalen;
        }
      else
        { /* Got a revocationReason. */
          err = parse_enumerated (data, datalen, &ti, 1);
          if (err)
            return err;
          switch (**data)
            {
            case  0: reason = KSBA_CRLREASON_UNSPECIFIED; break;
            case  1: reason = KSBA_CRLREASON_KEY_COMPROMISE; break;
            case  2: reason = KSBA_CRLREASON_CA_COMPROMISE; break;
            case  3: reason = KSBA_CRLREASON_AFFILIATION_CHANGED; break;
            case  4: reason = KSBA_CRLREASON_SUPERSEDED; break;
            case  5: reason = KSBA_CRLREASON_CESSATION_OF_OPERATION; break;
            case  6: reason = KSBA_CRLREASON_CERTIFICATE_HOLD; break;
            case  8: reason = KSBA_CRLREASON_REMOVE_FROM_CRL; break;
            case  9: reason = KSBA_CRLREASON_PRIVILEGE_WITHDRAWN; break;
            case 10: reason = KSBA_CRLREASON_AA_COMPROMISE; break;
            default: reason = KSBA_CRLREASON_OTHER; break;
            }
          parse_skip (data, datalen, &ti);
        }
/*       fprintf (stderr, "revocationReason=%04x\n", reason); */
      if (request_item)
        {
          request_item->status = KSBA_STATUS_REVOKED;
          _ksba_copy_time (request_item->revocation_time, revocation_time);
          request_item->revocation_reason = reason;
        }
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 2 && !ti.is_constructed
           && *datalen)
    { /* unknown */
      if (!ti.length)
        ; /* Cope with zero length objects. */
      else if (!**data)
        { /* Skip the NULL. */
          (*datalen)--;
          (*data)++;
        }
      else /* The comment indicates that an enumeration may come here. */
        {
          err = parse_enumerated (data, datalen, &ti, 0);
          if (err)
            return err;
          fprintf (stderr, "libksba: unknownReason with an enum of "
                   "length %u detected\n",
                   (unsigned int)ti.length);
          parse_skip (data, datalen, &ti);
        }
      if (request_item)
        request_item->status = KSBA_STATUS_UNKNOWN;
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  /* thisUpdate. */
  err = parse_asntime_into_isotime (data, datalen, this_update);
  if (err)
    return err;
  if (request_item)
    _ksba_copy_time (request_item->this_update, this_update);

  _ksba_current_time (now);
  if (*this_update && _ksba_cmp_time (now, this_update) < 0)
    return gpg_error (GPG_ERR_TIME_CONFLICT);

  /* nextUpdate is optional. */
  if (*data >= endptr)
    return 0;
  *next_update = 0;
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  else if (ti.class == CLASS_CONTEXT && ti.tag == 0  && ti.is_constructed)
    { /* have nextUpdate */
      err = parse_asntime_into_isotime (data, datalen, next_update);
      if (err)
        return err;
      if (request_item)
        _ksba_copy_time (request_item->next_update, next_update);
      if (*next_update && _ksba_cmp_time (now, next_update) > 0)
        return gpg_error (GPG_ERR_CERT_EXPIRED);
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    { /* Undo that read. */
      *data -= ti.nhdr;
      *datalen += ti.nhdr;
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  /* singleExtensions is optional */
  if (*data >= endptr)
    return 0;
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    {
      if (request_item)
        {
          err = parse_single_extensions (request_item, *data, ti.length);
          if (err)
            return err;
        }
      parse_skip (data, datalen, &ti);
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  return 0;
}

/* Parse the object:

        ResponseData ::= SEQUENCE {
           version              [0] EXPLICIT Version DEFAULT v1,
           responderID              ResponderID,
           producedAt               GeneralizedTime,
           responses                SEQUENCE OF SingleResponse,
           responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

        ResponderID ::= CHOICE {
           byName               [1] Name,
           byKey                [2] KeyHash }


*/
static gpg_error_t
parse_response_data (ksba_ocsp_t ocsp,
                     unsigned char const **data, size_t *datalen)
{
  gpg_error_t err;
  struct tag_info ti;
  const unsigned char *savedata;
  size_t savedatalen;
  size_t responses_length;

  /* The out er sequence. */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;

  /* The optional version field. */
  savedata = *data;
  savedatalen = *datalen;
  err = parse_context_tag (data, datalen, &ti, 0);
  if (err)
    {
      *data = savedata;
      *datalen = savedatalen;
    }
  else
    {
      /* FIXME: check that the version matches. */
      parse_skip (data, datalen, &ti);
    }

  /* The responderID field. */
  assert (!ocsp->responder_id.name);
  assert (!ocsp->responder_id.keyid);
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  else if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    { /* byName. */
      err = _ksba_derdn_to_str (*data, ti.length, &ocsp->responder_id.name);
      if (err)
        return err;
      parse_skip (data, datalen, &ti);
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 2  && ti.is_constructed)
    { /* byKey. */
      err = parse_octet_string (data, datalen, &ti);
      if (err)
        return err;
      if (!ti.length)
        return gpg_error (GPG_ERR_INV_OBJ); /* Zero length key id.  */
      ocsp->responder_id.keyid = xtrymalloc (ti.length);
      if (!ocsp->responder_id.keyid)
        return gpg_error_from_syserror ();
      memcpy (ocsp->responder_id.keyid, *data, ti.length);
      ocsp->responder_id.keyidlen = ti.length;
      parse_skip (data, datalen, &ti);
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  /* The producedAt field. */
  err = parse_asntime_into_isotime (data, datalen, ocsp->produced_at);
  if (err)
    return err;

  /* The responses field set. */
  err = parse_sequence (data, datalen, &ti);
  if (err )
    return err;
  responses_length = ti.length;
  while (responses_length)
    {
      savedatalen = *datalen;
      err = parse_single_response (ocsp, data, datalen);
      if (err)
        return err;
      assert (responses_length >= savedatalen - *datalen);
      responses_length -= savedatalen - *datalen;
    }

  /* The optional responseExtensions set. */
  savedata = *data;
  savedatalen = *datalen;
  err = parse_context_tag (data, datalen, &ti, 1);
  if (!err)
    {
      err = parse_response_extensions (ocsp, *data, ti.length);
      if (err)
        return err;
      parse_skip (data, datalen, &ti);
    }
  else if (gpg_err_code (err) == GPG_ERR_INV_OBJ)
    {
      *data = savedata;
      *datalen = savedatalen;
    }
  else
    return err;

  return 0;
}


/* Parse the entire response message pointed to by MSG of length
   MSGLEN. */
static gpg_error_t
parse_response (ksba_ocsp_t ocsp, const unsigned char *msg, size_t msglen)
{
  gpg_error_t err;
  struct tag_info ti;
  const unsigned char *msgstart;
  const unsigned char *endptr;
  const char *s;
  size_t len;


  msgstart = msg;
  err = parse_response_status (ocsp, &msg, &msglen, &len);
  if (err)
    return err;
  msglen = len; /* We don't care about any extra bytes provided to us. */
  if (ocsp->response_status)
    {
/*       fprintf (stderr,"response status found to be %d - stop\n", */
/*                ocsp->response_status); */
      return 0;
    }

  /* Now that we are sure that it is a BasicOCSPResponse, we can parse
     the really important things:

     BasicOCSPResponse       ::= SEQUENCE {
     tbsResponseData      ResponseData,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING,
     certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
  */
  err = parse_sequence (&msg, &msglen, &ti);
  if (err)
    return err;
  endptr = msg + ti.length;

  ocsp->hash_offset = msg - msgstart;
  err = parse_response_data (ocsp, &msg, &msglen);
  if (err)
    return err;
  ocsp->hash_length = msg - msgstart - ocsp->hash_offset;

  /* The signatureAlgorithm and the signature. We only need to get the
     length of both objects and let a specialized function do the
     actual parsing. */
  s = msg;
  len = msglen;
  err = parse_sequence (&msg, &msglen, &ti);
  if (err)
    return err;
  xfree (ocsp->sig_oid); ocsp->sig_oid = NULL;
  {
    size_t nread;
    err = _ksba_parse_algorithm_identifier (s, ti.nhdr + ti.length,
                                            &nread, &ocsp->sig_oid);
    if (err)
      return err;
  }
  parse_skip (&msg, &msglen, &ti);
  err= _ksba_ber_parse_tl (&msg, &msglen, &ti);
  if (err)
    return err;
  if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_BIT_STRING
        && !ti.is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (!ti.length)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else if (ti.length > msglen)
    err = gpg_error (GPG_ERR_BAD_BER);
  parse_skip (&msg, &msglen, &ti);
  len = len - msglen;
  xfree (ocsp->sigval); ocsp->sigval = NULL;
  err =  _ksba_sigval_to_sexp (s, len, &ocsp->sigval);
  if (err)
    return err;

  /* Parse the optional sequence of certificates. */
  if (msg >= endptr)
    return 0; /* It's optional, so stop now. */
  err = parse_context_tag (&msg, &msglen, &ti, 0);
  if (gpg_err_code (err) == GPG_ERR_INV_OBJ)
    return 0; /* Not the right tag. Stop here. */
  if (err)
    return err;
  err = parse_sequence (&msg, &msglen, &ti);
  if (err)
    return err;
  if (ti.ndef)
    return gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);

  {
    ksba_cert_t cert;
    struct ocsp_certlist_s *cl, **cl_tail;

    assert (!ocsp->received_certs);
    cl_tail = &ocsp->received_certs;
    endptr = msg + ti.length;
    while (msg < endptr)
      {
        /* Find the length of the certificate. */
        s = msg;
        err = parse_sequence (&msg, &msglen, &ti);
        if (err)
          return err;
        err = ksba_cert_new (&cert);
        if (err)
          return err;
        err = ksba_cert_init_from_mem (cert, msg - ti.nhdr,
                                       ti.nhdr + ti.length);
        if (err)
          {
            ksba_cert_release (cert);
            return err;
          }
        parse_skip (&msg, &msglen, &ti);
        cl = xtrycalloc (1, sizeof *cl);
        if (!cl)
          {
            err = gpg_error_from_syserror ();
            ksba_cert_release (cert);
            return err;
          }

        cl->cert = cert;

        *cl_tail = cl;
        cl_tail = &cl->next;
      }
  }

  return 0;
}


/* Given the OCSP context and a binary reponse message of MSGLEN bytes
   in MSG, this fucntion parses the response and prepares it for
   signature verification.  The status from the server is returned in
   RESPONSE_STATUS and must be checked even if the function returns
   without an error. */
gpg_error_t
ksba_ocsp_parse_response (ksba_ocsp_t ocsp,
                          const unsigned char *msg, size_t msglen,
                          ksba_ocsp_response_status_t *response_status)
{
  gpg_error_t err;
  struct ocsp_reqitem_s *ri;

  if (!ocsp || !msg || !msglen || !response_status)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);

  /* Reset the fields used to track the response.  This is so that we
     can use the parse function a second time for the same
     request. This is useful in case of a TryLater response status. */
  ocsp->response_status = KSBA_OCSP_RSPSTATUS_NONE;
  release_ocsp_certlist (ocsp->received_certs);
  release_ocsp_extensions (ocsp->response_extensions);
  ocsp->received_certs = NULL;
  ocsp->hash_length = 0;
  ocsp->bad_nonce = 0;
  xfree (ocsp->responder_id.name);
  ocsp->responder_id.name = NULL;
  xfree (ocsp->responder_id.keyid);
  ocsp->responder_id.keyid = NULL;
  for (ri=ocsp->requestlist; ri; ri = ri->next)
    {
      ri->status = KSBA_STATUS_NONE;
      *ri->this_update = 0;
      *ri->next_update = 0;
      *ri->revocation_time = 0;
      ri->revocation_reason = 0;
      release_ocsp_extensions (ri->single_extensions);
    }

  /* Run the actual parser.  */
  err = parse_response (ocsp, msg, msglen);
  *response_status = ocsp->response_status;

  /* FIXME: find duplicates in the request list and set them to the
     same status. */

  /* We used to assume that the server needs to return a nonce, but
   * that is not true (see for example RFC-8954).  Thus we do not
   * check the former good_nonce flag anymore.  */
  if (*response_status == KSBA_OCSP_RSPSTATUS_SUCCESS
      && ocsp->bad_nonce)
    *response_status = KSBA_OCSP_RSPSTATUS_REPLAYED;

  return err;
}


/* Return the digest algorithm to be used for the signature or NULL in
   case of an error.  The returned pointer is valid as long as the
   context is valid and no other ksba_ocsp_parse_response or
   ksba_ocsp_build_request has been used. */
const char *
ksba_ocsp_get_digest_algo (ksba_ocsp_t ocsp)
{
  return ocsp? ocsp->digest_oid : NULL;
}


/* Hash the data of the response using the hash function HASHER which
   will be passed HASHER_ARG as its first argument and a pointer and a
   length of the data to be hashed. This hash function might be called
   several times and should update the hash context.  The algorithm to
   be used for the hashing can be retrieved using
   ksba_ocsp_get_digest_algo. Note that MSG and MSGLEN should be
   indentical to the values passed to ksba_ocsp_parse_response. */
gpg_error_t
ksba_ocsp_hash_response (ksba_ocsp_t ocsp,
                         const unsigned char *msg, size_t msglen,
                         void (*hasher)(void *, const void *, size_t length),
                         void *hasher_arg)

{
  if (!ocsp || !msg || !hasher)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!ocsp->hash_length)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (ocsp->hash_offset + ocsp->hash_length >= msglen)
    return gpg_error (GPG_ERR_CONFLICT);

  hasher (hasher_arg, msg + ocsp->hash_offset, ocsp->hash_length);
  return 0;
}


/* Return the actual signature in a format suitable to be used as
   input to Libgcrypt's verification function.  The caller must free
   the returned string and that function may be called only once after
   a successful ksba_ocsp_parse_response. Returns NULL for an invalid
   handle or if no signature is available. If PRODUCED_AT is not NULL,
   it will receive the time the response was signed. */
ksba_sexp_t
ksba_ocsp_get_sig_val (ksba_ocsp_t ocsp, ksba_isotime_t produced_at)
{
  ksba_sexp_t p;

  if (produced_at)
    *produced_at = 0;
  if (!ocsp || !ocsp->sigval )
    return NULL;

  if (produced_at)
    _ksba_copy_time (produced_at, ocsp->produced_at);

  p = ocsp->sigval;
  ocsp->sigval = NULL;
  return p;
}


/* Return the responder ID for the current response into R_NAME or
   into R_KEYID.  On sucess either R_NAME or R_KEYID will receive an
   allocated object.  If R_NAME or R_KEYID has been passed as NULL but
   a value is available the errorcode GPG_ERR_NO_DATA is returned.
   Caller must release the values stored at R_NAME or R_KEYID; the
   function stores NULL tehre in case of an error.  */
gpg_error_t
ksba_ocsp_get_responder_id (ksba_ocsp_t ocsp,
                            char **r_name, ksba_sexp_t *r_keyid)
{
  if (r_name)
    *r_name = NULL;
  if (r_keyid)
    *r_keyid = NULL;

  if (!ocsp)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (ocsp->responder_id.name && r_name)
    {
      *r_name = xtrystrdup (ocsp->responder_id.name);
      if (!*r_name)
        return gpg_error_from_syserror ();
    }
  else if (ocsp->responder_id.keyid && r_keyid)
    {
      char numbuf[50];
      size_t numbuflen;

      sprintf (numbuf,"(%lu:", (unsigned long)ocsp->responder_id.keyidlen);
      numbuflen = strlen (numbuf);
      *r_keyid = xtrymalloc (numbuflen + ocsp->responder_id.keyidlen + 2);
      if (!*r_keyid)
        return gpg_error_from_syserror ();
      strcpy (*r_keyid, numbuf);
      memcpy (*r_keyid+numbuflen,
              ocsp->responder_id.keyid, ocsp->responder_id.keyidlen);
      (*r_keyid)[numbuflen + ocsp->responder_id.keyidlen] = ')';
      (*r_keyid)[numbuflen + ocsp->responder_id.keyidlen + 1] = 0;
    }
  else
    return gpg_error (GPG_ERR_NO_DATA);

  return 0;
}


/* Get optional certificates out of a response.  The caller may use
 * this in a loop to get all certificates.  The returned certificate
 * is a shallow copy of the original one; the caller must still use
 * ksba_cert_release() to free it. Returns: A certificate object or
 * NULL for end of list or error. */
ksba_cert_t
ksba_ocsp_get_cert (ksba_ocsp_t ocsp, int idx)
{
  struct ocsp_certlist_s *cl;

  if (!ocsp || idx < 0)
    return NULL;

  for (cl=ocsp->received_certs; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return NULL;
  ksba_cert_ref (cl->cert);
  return cl->cert;
}




/* Return the status of the certificate CERT for the last response
   done on the context OCSP.  CERT must be the same certificate as
   used for the request; only a shallow compare is done (i.e. the
   pointers are compared).  R_STATUS returns the status value,
   R_THIS_UPDATE and R_NEXT_UPDATE are the corresponding OCSP response
   values, R_REVOCATION_TIME is only set to the revocation time if the
   indicated status is revoked, R_REASON will be set to the reason
   given for a revocation.  All the R_* arguments may be given as NULL
   if the value is not required.  The function return 0 on success,
   GPG_ERR_NOT_FOUND if CERT was not used in the request or any other
   error code.  Note that the caller should have checked the signature
   of the entire reponse to be good before using the stati retruned by
   this function. */
gpg_error_t
ksba_ocsp_get_status (ksba_ocsp_t ocsp, ksba_cert_t cert,
                      ksba_status_t *r_status,
                      ksba_isotime_t r_this_update,
                      ksba_isotime_t r_next_update,
                      ksba_isotime_t r_revocation_time,
                      ksba_crl_reason_t *r_reason)
{
  struct ocsp_reqitem_s *ri;

  if (!ocsp || !cert || !r_status)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);

  /* Find the certificate.  We don't care about the issuer certificate
     and stop at the first match.  The implementation may be optimized
     by keeping track of the last certificate found to start with the
     next one then.  Given that a usual request consists only of a few
     certificates, this does not make much sense in reality. */
  for (ri=ocsp->requestlist; ri; ri = ri->next)
    if (ri->cert == cert)
      break;
  if (!ri)
    return gpg_error (GPG_ERR_NOT_FOUND);
  if (r_status)
    *r_status = ri->status;
  if (r_this_update)
    _ksba_copy_time (r_this_update, ri->this_update);
  if (r_next_update)
    _ksba_copy_time (r_next_update, ri->next_update);
  if (r_revocation_time)
    _ksba_copy_time (r_revocation_time, ri->revocation_time);
  if (r_reason)
    *r_reason = ri->revocation_reason;
  return 0;
}


/* WARNING: The returned values ares only valid as long as no other
   ocsp function is called on the same context.  */
gpg_error_t
ksba_ocsp_get_extension (ksba_ocsp_t ocsp, ksba_cert_t cert, int idx,
                         char const **r_oid, int *r_crit,
                         unsigned char const **r_der, size_t *r_derlen)
{
  struct ocsp_extension_s *ex;

  if (!ocsp)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  if (cert)
    {
      /* Return extensions for the certificate (singleExtensions).  */
      struct ocsp_reqitem_s *ri;

      for (ri=ocsp->requestlist; ri; ri = ri->next)
        if (ri->cert == cert)
          break;
      if (!ri)
        return gpg_error (GPG_ERR_NOT_FOUND);

      for (ex=ri->single_extensions; ex && idx; ex = ex->next, idx--)
        ;
      if (!ex)
        return gpg_error (GPG_ERR_EOF); /* No more extensions. */
    }
  else
    {
      /* Return extensions for the response (responseExtensions).  */
      for (ex=ocsp->response_extensions; ex && idx; ex = ex->next, idx--)
        ;
      if (!ex)
        return gpg_error (GPG_ERR_EOF); /* No more extensions. */
    }

  if (r_oid)
    *r_oid = ex->data;
  if (r_crit)
    *r_crit = ex->crit;
  if (r_der)
    *r_der = ex->data + ex->off;
  if (r_derlen)
    *r_derlen = ex->len;

  return 0;
}

/* Verify an OCSP response signed with a GOST key.  MSG and MSGLEN must
   be the same values as used with ksba_ocsp_parse_response.  */
gpg_error_t
ksba_ocsp_check_signature_gost (ksba_ocsp_t ocsp,
                                const unsigned char *msg, size_t msglen,
                                ksba_cert_t cert)
{
  gpg_error_t err;
  int algo, i;
  gcry_md_hd_t md;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  const char *s;
  char algo_name[17];
  int digestlen;
  unsigned char *digest;

  if (!ocsp || !msg || !cert)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!ocsp->sigval || !ocsp->sig_oid || !ocsp->hash_length)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (strncmp (ocsp->sig_oid, "1.2.643", 7))
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  err = _ksba_check_key_usage_for_gost (cert, KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
  if (!err)
    err = check_ocsp_signing_eku (cert);
  if (!err)
    /* TK-26: The responder certificate must carry an appropriate policy.  */
    err = check_policy_tk26 (cert);
  if (err)
    return err;

  algo = gcry_md_map_name (ocsp->sig_oid);
  if (!algo)
    return gpg_error (GPG_ERR_DIGEST_ALGO);

  err = gcry_md_open (&md, algo, 0);
  if (err)
    return err;
  if (ocsp->hash_offset + ocsp->hash_length > msglen)
    {
      gcry_md_close (md);
      return gpg_error (GPG_ERR_BAD_BER);
    }
  gcry_md_write (md, msg + ocsp->hash_offset, ocsp->hash_length);
  gcry_md_final (md);

  digestlen = gcry_md_get_algo_dlen (algo);
  digest = gcry_md_read (md, algo);

  {
    unsigned char *h = digest;
    unsigned char c;
    int len_xy;
    unsigned short arch = 1;
    len_xy = *((unsigned char *)&arch) == 0 ? 0 : digestlen;
    for (i = 0; i < (len_xy/2); i++)
      {
        c = h[i];
        h[i] = h[len_xy - i - 1];
        h[len_xy - i - 1] = c;
      }
  }

  s = gcry_md_algo_name (algo);
  for (i = 0; *s && i < (int)sizeof algo_name - 1; s++, i++)
    algo_name[i] = tolower (*s);
  algo_name[i] = 0;

  err = gcry_sexp_build (&s_hash, NULL,
                         "(data(flags gost)(value %b))",
                         (int)digestlen, digest);
  if (err)
    {
      gcry_md_close (md);
      return err;
    }

  p = ocsp->sigval;
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      gcry_md_close (md);
      gcry_sexp_release (s_hash);
      return gpg_error (GPG_ERR_INV_SEXP);
    }
  err = gcry_sexp_sscan (&s_sig, NULL, p, n);
  if (err)
    {
      gcry_md_close (md);
      gcry_sexp_release (s_hash);
      return err;
    }

  p = ksba_cert_get_public_key (cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      gcry_md_close (md);
      ksba_free (p);
      gcry_sexp_release (s_sig);
      gcry_sexp_release (s_hash);
      return gpg_error (GPG_ERR_INV_SEXP);
    }
  err = gcry_sexp_sscan (&s_pkey, NULL, p, n);
  ksba_free (p);
  if (err)
    {
      gcry_md_close (md);
      gcry_sexp_release (s_sig);
      gcry_sexp_release (s_hash);
      return err;
    }

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
          unsigned char *d2 = xtrymalloc (digestlen);
          if (d2)
            {
              for (i = 0; i < digestlen; i++)
                d2[i] = digest[digestlen - 1 - i];
              gcry_sexp_release (s_hash);
              if (!gcry_sexp_build (&s_hash, NULL,
                                    "(data(flags gost)(value %b))",
                                    (int)digestlen, d2))
                err = gcry_pk_verify (s_sig, s_hash, s_pkey);
              gcry_free (d2);
            }
        }
    }

  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return err;
}
