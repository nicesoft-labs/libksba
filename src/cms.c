/* cms.c - cryptographic message syntax main functions
 * Copyright (C) 2001, 2003, 2004, 2008, 2012, 2020 g10 Code GmbH
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

/* References:
 * RFC-5083 := CMS - Authenticated-Enveloped-Data
 * RFC-5084 := CMS - AES-GCM
 * RFC-5652 := Cryptographic Message Syntax (CMS) (aka STD0070)
 * SPHINX   := CMS profile developed by the German BSI.
 *             (see also https://lwn.net/2001/1011/a/german-smime.php3)
 * PKCS#7   := Original specification of CMS
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "util.h"

#include "cms.h"
#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "sexp-parse.h"
#include "cert.h"
#include "der-builder.h"
#include "stringbuf.h"

/* Helper used for GOST signature handling: reverse byte order.  */
static void
invert_bytes (unsigned char *dst, const unsigned char *src, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    dst[i] = src[len - 1 - i];
}
/* Return true if ALGO specifies a GOST signature algorithm.  */
static int
is_gost_algo (const char *algo)
{
  return (algo
          && (!strcmp (algo, "gost") || !strncmp (algo, "1.2.643", 7)));
}

/* Check whether OID describes a GOST algorithm.  */
static int
is_gost_oid (const char *oid)
{
  return is_gost_algo (oid);
}

/* Helper to walk up the ASN tree.  */
static AsnNode
find_up (AsnNode node)
{
  AsnNode p;

  if (!node)
    return NULL;

  p = node;
  while (p->left && p->left->right == p)
    p = p->left;
  return p->left;
}


/* Check for the presence of a TK-26 policy in CERT.  The policy is
   considered valid if any policyIdentifier OID starts with "1.2.643".
   Return 0 on success or an error code.  */
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

/* Extract the subjectKeyIdentifier from CERT into a newly allocated
   buffer.  */
static gpg_error_t
get_subject_key_id (ksba_cert_t cert, unsigned char **r_buf, size_t *r_len)
{
  gpg_error_t err;
  ksba_sexp_t keyid = NULL;
  const unsigned char *s;
  size_t n;

  *r_buf = NULL;
  *r_len = 0;
  err = ksba_cert_get_subj_key_id (cert, NULL, &keyid);
  if (err)
    return err;

  s = (const unsigned char *)keyid;
  if (*s != '(')
    {
      err = gpg_error (GPG_ERR_INV_CERT_OBJ);
      goto leave;
    }
  s++;
  n = snext (&s);
  if (!n || s[n] != ')')
    {
      err = gpg_error (GPG_ERR_INV_CERT_OBJ);
      goto leave;
    }
  *r_buf = xtrymalloc (n);
  if (!*r_buf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  memcpy (*r_buf, s, n);
  *r_len = n;
  err = 0;

leave:
  xfree (keyid);
  return err;
}


static gpg_error_t ct_parse_data (ksba_cms_t cms);
static gpg_error_t ct_parse_signed_data (ksba_cms_t cms);
static gpg_error_t ct_parse_enveloped_data (ksba_cms_t cms);
static gpg_error_t ct_parse_digested_data (ksba_cms_t cms);
static gpg_error_t ct_parse_encrypted_data (ksba_cms_t cms);
static gpg_error_t ct_build_data (ksba_cms_t cms);
static gpg_error_t ct_build_signed_data (ksba_cms_t cms);
static gpg_error_t ct_build_enveloped_data (ksba_cms_t cms);
static gpg_error_t ct_build_digested_data (ksba_cms_t cms);
static gpg_error_t ct_build_encrypted_data (ksba_cms_t cms);

static struct {
  const char *oid;
  ksba_content_type_t ct;
  gpg_error_t (*parse_handler)(ksba_cms_t);
  gpg_error_t (*build_handler)(ksba_cms_t);
} content_handlers[] = {
  {  "1.2.840.113549.1.7.1", KSBA_CT_DATA,
     ct_parse_data   , ct_build_data                  },
  {  "1.2.840.113549.1.7.2", KSBA_CT_SIGNED_DATA,
     ct_parse_signed_data   , ct_build_signed_data    },
  {  "1.2.840.113549.1.7.3", KSBA_CT_ENVELOPED_DATA,
     ct_parse_enveloped_data, ct_build_enveloped_data },
  {  "1.2.840.113549.1.9.16.1.23", KSBA_CT_AUTHENVELOPED_DATA,
     ct_parse_enveloped_data, ct_build_enveloped_data },
  {  "1.2.840.113549.1.7.5", KSBA_CT_DIGESTED_DATA,
     ct_parse_digested_data , ct_build_digested_data  },
  {  "1.2.840.113549.1.7.6", KSBA_CT_ENCRYPTED_DATA,
     ct_parse_encrypted_data, ct_build_encrypted_data },
  {  "1.2.840.113549.1.9.16.1.2", KSBA_CT_AUTH_DATA   },
  {  "1.3.6.1.4.1.311.2.1.4", KSBA_CT_SPC_IND_DATA_CTX,
     ct_parse_data   , ct_build_data                  },
  {  "1.3.6.1.4.1.11591.2.3.1", KSBA_CT_OPENPGP_KEYBLOCK,
     ct_parse_data   , ct_build_data                  },
  { NULL }
};

static const char oidstr_contentType[] = "1.2.840.113549.1.9.3";
/*static char oid_contentType[9] = "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03";*/

static const char oidstr_messageDigest[] = "1.2.840.113549.1.9.4";
_KSBA_NONSTRING
static const char oid_messageDigest[9] ="\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04";

static const char oidstr_signingTime[] = "1.2.840.113549.1.9.5";
_KSBA_NONSTRING
static const char oid_signingTime[9] = "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05";

static const char oidstr_smimeCapabilities[] = "1.2.840.113549.1.9.15";



#if 0 /* Set to 1 to use this debug helper.  */
static void
log_sexp (const char *text, ksba_const_sexp_t p)
{
  int level = 0;

  gpgrt_log_debug ("%s: ", text);
  if (!p)
    gpgrt_log_printf ("[none]");
  else
    {
      for (;;)
        {
          if (*p == '(')
            {
              gpgrt_log_printf ("%c", *p);
              p++;
              level++;
            }
          else if (*p == ')')
            {
              gpgrt_log_printf ("%c", *p);
              p++;
              if (--level <= 0 )
                return;
            }
          else if (!digitp (p))
            {
              gpgrt_log_printf ("[invalid s-exp]");
              return;
            }
          else
            {
              char *endp;
              const unsigned char *s;
              unsigned long len, n;

              len = strtoul (p, &endp, 10);
              p = endp;
              if (*p != ':')
                {
                  gpgrt_log_printf ("[invalid s-exp]");
                  return;
                }
              p++;
              for (s=p,n=0; n < len; n++, s++)
                if ( !((*s >= 'a' && *s <= 'z')
                       || (*s >= 'A' && *s <= 'Z')
                       || (*s >= '0' && *s <= '9')
                       || *s == '-' || *s == '.'))
                  break;
              if (n < len)
                {
                  gpgrt_log_printf ("#");
                  for (n=0; n < len; n++, p++)
                    gpgrt_log_printf ("%02X", *p);
                  gpgrt_log_printf ("#");
                }
              else
                {
                  for (n=0; n < len; n++, p++)
                    gpgrt_log_printf ("%c", *p);
                }
            }
        }
    }
  gpgrt_log_printf ("\n");
}
#endif /* debug helper */


/* Helper for read_and_hash_cont().  */
static gpg_error_t
read_hash_block (ksba_cms_t cms, unsigned long nleft)
{
  gpg_error_t err;
  char buffer[4096];
  size_t n, nread;

  while (nleft)
    {
      n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
      err = ksba_reader_read (cms->reader, buffer, n, &nread);
      if (err)
        return err;
      nleft -= nread;
      if (cms->hash_fnc)
        cms->hash_fnc (cms->hash_fnc_arg, buffer, nread);
      if (cms->writer)
        err = ksba_writer_write (cms->writer, buffer, nread);
      if (err)
        return err;
    }
  return 0;
}


/* Copy all the bytes from the reader to the writer and hash them if a
   a hash function has been set.  The writer may be NULL to just do
   the hashing */
static gpg_error_t
read_and_hash_cont (ksba_cms_t cms)
{
  gpg_error_t err = 0;
  unsigned long nleft;
  struct tag_info ti;

  if (cms->inner_cont_ndef)
    {
      for (;;)
        {
          err = _ksba_ber_read_tl (cms->reader, &ti);
          if (err)
            return err;

          if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
              && !ti.is_constructed)
            { /* next chunk */
              nleft = ti.length;
              err = read_hash_block (cms, nleft);
              if (err)
                return err;
            }
          else if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
                   && ti.is_constructed)
            { /* next chunk is constructed */
              for (;;)
                {
                  err = _ksba_ber_read_tl (cms->reader, &ti);
                  if (err)
                    return err;
                  if (ti.class == CLASS_UNIVERSAL
                      && ti.tag == TYPE_OCTET_STRING
                      && !ti.is_constructed)
                    {
                      nleft = ti.length;
                      err = read_hash_block (cms, nleft);
                      if (err)
                        return err;
                    }
                  else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                           && !ti.is_constructed)
                    break; /* ready with this chunk */
                  else
                    return gpg_error (GPG_ERR_ENCODING_PROBLEM);
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                   && !ti.is_constructed)
            return 0; /* ready */
          else
            return gpg_error (GPG_ERR_ENCODING_PROBLEM);
        }
    }
  else
    {
      /* This is basically the same as above but we allow for
         arbitrary types.  Not sure whether it is really needed but
         right in the beginning of gnupg 1.9 we had at least one
         message with didn't used octet strings.  Not ethat we don't
         do proper NLEFT checking but well why should we validate
         these things?  Well, it might be nice to have such a feature
         but then we should write a more general mechanism to do
         that.  */
      nleft = cms->inner_cont_len;
      /* First read the octet string but allow all types here */
      err = _ksba_ber_read_tl (cms->reader, &ti);
      if (err)
        return err;
      if (nleft < ti.nhdr)
        return gpg_error (GPG_ERR_ENCODING_PROBLEM);
      nleft -= ti.nhdr;

      if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
          && ti.is_constructed)
        { /* Next chunk is constructed */
          for (;;)
            {
              err = _ksba_ber_read_tl (cms->reader, &ti);
              if (err)
                return err;
              if (ti.class == CLASS_UNIVERSAL
                  && ti.tag == TYPE_OCTET_STRING
                  && !ti.is_constructed)
                {
                  nleft = ti.length;
                  err = read_hash_block (cms, nleft);
                  if (err)
                    return err;
                }
              else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                       && !ti.is_constructed)
                break; /* Ready with this chunk */
              else
                return gpg_error (GPG_ERR_ENCODING_PROBLEM);
            }
        }
      else if (ti.class == CLASS_UNIVERSAL && !ti.tag
               && !ti.is_constructed)
        return 0; /* ready */
      else
        {
          err = read_hash_block (cms, nleft);
          if (err)
            return err;
        }
    }
  return 0;
}



/* Copy all the encrypted bytes from the reader to the writer.
   Handles indefinite length encoding */
static gpg_error_t
read_encrypted_cont (ksba_cms_t cms)
{
  gpg_error_t err = 0;
  unsigned long nleft;
  char buffer[4096];
  size_t n, nread;

  if (cms->inner_cont_ndef)
    {
      struct tag_info ti;

      /* fixme: this ist mostly a duplicate of the code in
         read_and_hash_cont(). */
      for (;;)
        {
          err = _ksba_ber_read_tl (cms->reader, &ti);
          if (err)
            return err;

          if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
              && !ti.is_constructed)
            { /* next chunk */
              nleft = ti.length;
              while (nleft)
                {
                  n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
                  err = ksba_reader_read (cms->reader, buffer, n, &nread);
                  if (err)
                    return err;
                  nleft -= nread;
                  err = ksba_writer_write (cms->writer, buffer, nread);
                  if (err)
                    return err;
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
                   && ti.is_constructed)
            { /* next chunk is constructed */
              for (;;)
                {
                  err = _ksba_ber_read_tl (cms->reader, &ti);
                  if (err)
                    return err;
                  if (ti.class == CLASS_UNIVERSAL
                      && ti.tag == TYPE_OCTET_STRING
                      && !ti.is_constructed)
                    {
                      nleft = ti.length;
                      while (nleft)
                        {
                          n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
                          err = ksba_reader_read (cms->reader, buffer, n, &nread);
                          if (err)
                            return err;
                          nleft -= nread;
                          if (cms->writer)
                            err = ksba_writer_write (cms->writer, buffer, nread);
                          if (err)
                            return err;
                        }
                    }
                  else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                           && !ti.is_constructed)
                    break; /* ready with this chunk */
                  else
                    return gpg_error (GPG_ERR_ENCODING_PROBLEM);
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                   && !ti.is_constructed)
            return 0; /* ready */
          else
            return gpg_error (GPG_ERR_ENCODING_PROBLEM);
        }
    }
  else
    {
      nleft = cms->inner_cont_len;
      while (nleft)
        {
          n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
          err = ksba_reader_read (cms->reader, buffer, n, &nread);
          if (err)
            return err;
          nleft -= nread;
          err = ksba_writer_write (cms->writer, buffer, nread);
          if (err)
            return err;
        }
    }
  return 0;
}

/* copy data from reader to writer.  Assume that it is an octet string
   and insert undefinite length headers where needed */
static gpg_error_t
write_encrypted_cont (ksba_cms_t cms)
{
  gpg_error_t err = 0;
  char buffer[4096];
  size_t nread;

  /* we do it the simple way: the parts are made up from the chunks we
     got from the read function.

     Fixme: We should write the tag here, and write a definite length
     header if everything fits into our local buffer.  Actually pretty
     simple to do, but I am too lazy right now. */
  while (!err && !(err = ksba_reader_read (cms->reader, buffer,
                                           sizeof buffer, &nread)) )
    {
      err = _ksba_ber_write_tl (cms->writer, TYPE_OCTET_STRING,
                                CLASS_UNIVERSAL, 0, nread);
      if (!err)
        err = ksba_writer_write (cms->writer, buffer, nread);
    }
  if (gpg_err_code (err) == GPG_ERR_EOF) /* write the end tag */
      err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);

  return err;
}


/* Figure out whether the data read from READER is a CMS object and
   return its content type.  This function does only peek at the
   READER and tries to identify the type with best effort.  Because of
   the ubiquity of the stupid and insecure pkcs#12 format, the
   function will also identify those files and return KSBA_CT_PKCS12;
   there is and will be no other pkcs#12 support in this library. */
ksba_content_type_t
ksba_cms_identify (ksba_reader_t reader)
{
  struct tag_info ti;
  unsigned char buffer[24];
  const unsigned char*p;
  size_t n, count;
  char *oid;
  int i;
  int maybe_p12 = 0;

  if (!reader)
    return KSBA_CT_NONE; /* oops */

  /* This is a common example of a CMS object - it is obvious that we
     only need to read a few bytes to get to the OID:
  30 82 0B 59 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 0B 4A 30 82 0B 46 02
  ----------- ++++++++++++++++++++++++++++++++
  SEQUENCE    OID (signedData)
  (2 byte len)

     For a pkcs12 message we have this:

  30 82 08 59 02 01 03 30 82 08 1F 06 09 2A 86 48 86 F7 0D 01 07 01 A0 82
  ----------- ++++++++ ----------- ++++++++++++++++++++++++++++++++
  SEQUENCE    INTEGER  SEQUENCE    OID (data)

    This we need to read at least 22 bytes, we add 2 bytes to cope with
    length headers store with 4 bytes.
  */

  for (count = sizeof buffer; count; count -= n)
    {
      if (ksba_reader_read (reader, buffer+sizeof (buffer)-count, count, &n))
        return KSBA_CT_NONE; /* too short */
    }
  n = sizeof buffer;
  if (ksba_reader_unread (reader, buffer, n))
    return KSBA_CT_NONE; /* oops */

  p = buffer;
  if (_ksba_ber_parse_tl (&p, &n, &ti))
    return KSBA_CT_NONE;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_CT_NONE;
  if (_ksba_ber_parse_tl (&p, &n, &ti))
    return KSBA_CT_NONE;
  if ( ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_INTEGER
       && !ti.is_constructed && ti.length == 1 && n && *p == 3)
    {
      maybe_p12 = 1;
      p++;
      n--;
      if (_ksba_ber_parse_tl (&p, &n, &ti))
        return KSBA_CT_NONE;
      if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
             && ti.is_constructed) )
        return KSBA_CT_NONE;
      if (_ksba_ber_parse_tl (&p, &n, &ti))
        return KSBA_CT_NONE;
    }
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OBJECT_ID
         && !ti.is_constructed && ti.length) || ti.length > n)
    return KSBA_CT_NONE;
  oid = ksba_oid_to_str (p, ti.length);
  if (!oid)
    return KSBA_CT_NONE; /* out of core */
  for (i=0; content_handlers[i].oid; i++)
    {
      if (!strcmp (content_handlers[i].oid, oid))
        break;
    }
  ksba_free(oid);
  if (!content_handlers[i].oid)
    return KSBA_CT_NONE; /* unknown */
  if (maybe_p12 && (content_handlers[i].ct == KSBA_CT_DATA
                    || content_handlers[i].ct == KSBA_CT_SIGNED_DATA))
      return KSBA_CT_PKCS12;
  return content_handlers[i].ct;
}



/**
 * ksba_cms_new:
 *
 * Create a new and empty CMS object
 *
 * Return value: A CMS object or an error code.
 **/
gpg_error_t
ksba_cms_new (ksba_cms_t *r_cms)
{
  *r_cms = xtrycalloc (1, sizeof **r_cms);
  if (!*r_cms)
    return gpg_error_from_errno (errno);
  return 0;
}

/* Release a list of value trees. */
static void
release_value_tree (struct value_tree_s *tree)
{
  while (tree)
    {
      struct value_tree_s *tmp = tree->next;
      _ksba_asn_release_nodes (tree->root);
      xfree (tree->image);
      xfree (tree);
      tree = tmp;
    }
}

/**
 * ksba_cms_release:
 * @cms: A CMS object
 *
 * Release a CMS object.
 **/
void
ksba_cms_release (ksba_cms_t cms)
{
  if (!cms)
    return;
  xfree (cms->content.oid);
  while (cms->digest_algos)
    {
      struct oidlist_s *ol = cms->digest_algos->next;
      xfree (cms->digest_algos->oid);
      xfree (cms->digest_algos);
      cms->digest_algos = ol;
    }
  while (cms->cert_list)
    {
      struct certlist_s *cl = cms->cert_list->next;
      ksba_cert_release (cms->cert_list->cert);
      xfree (cms->cert_list->enc_val.algo);
      xfree (cms->cert_list->enc_val.value);
      xfree (cms->cert_list->enc_val.ecdh.e);
      xfree (cms->cert_list->enc_val.ecdh.wrap_algo);
      xfree (cms->cert_list->enc_val.ecdh.encr_algo);
      xfree (cms->cert_list->enc_val.ecdh.ukm);
      xfree (cms->cert_list);
      cms->cert_list = cl;
    }
  while (cms->cert_info_list)
    {
      struct certlist_s *cl = cms->cert_info_list->next;
      ksba_cert_release (cms->cert_info_list->cert);
      xfree (cms->cert_info_list->enc_val.algo);
      xfree (cms->cert_info_list->enc_val.value);
      xfree (cms->cert_info_list->enc_val.ecdh.e);
      xfree (cms->cert_info_list->enc_val.ecdh.wrap_algo);
      xfree (cms->cert_info_list->enc_val.ecdh.encr_algo);
      xfree (cms->cert_info_list->enc_val.ecdh.ukm);
      xfree (cms->cert_info_list);
      cms->cert_info_list = cl;
    }
  xfree (cms->inner_cont_oid);
  xfree (cms->encr_algo_oid);
  xfree (cms->encr_iv);
  xfree (cms->authdata.mac);
  xfree (cms->authdata.attr);
  while (cms->signer_info)
    {
      struct signer_info_s *tmp = cms->signer_info->next;
      _ksba_asn_release_nodes (cms->signer_info->root);
      xfree (cms->signer_info->image);
      xfree (cms->signer_info->cache.digest_algo);
      xfree (cms->signer_info);
      cms->signer_info = tmp;
    }
  release_value_tree (cms->recp_info);
  while (cms->sig_val)
    {
      struct sig_val_s *tmp = cms->sig_val->next;
      xfree (cms->sig_val->algo);
      xfree (cms->sig_val->value);
      xfree (cms->sig_val->ecc.r);
      xfree (cms->sig_val);
      cms->sig_val = tmp;
    }
  while (cms->capability_list)
    {
      struct oidparmlist_s *tmp = cms->capability_list->next;
      xfree (cms->capability_list->oid);
      xfree (cms->capability_list);
      cms->capability_list = tmp;
    }

  xfree (cms);
}


gpg_error_t
ksba_cms_set_reader_writer (ksba_cms_t cms, ksba_reader_t r, ksba_writer_t w)
{
  if (!cms || !(r || w))
    return gpg_error (GPG_ERR_INV_VALUE);
  if ((r && cms->reader) || (w && cms->writer) )
    return gpg_error (GPG_ERR_CONFLICT); /* already set */

  cms->reader = r;
  cms->writer = w;
  return 0;
}



gpg_error_t
ksba_cms_parse (ksba_cms_t cms, ksba_stop_reason_t *r_stopreason)
{
  gpg_error_t err;
  int i;

  if (!cms || !r_stopreason)
    return gpg_error (GPG_ERR_INV_VALUE);

  *r_stopreason = KSBA_SR_RUNNING;
  if (!cms->stop_reason)
    { /* Initial state: start parsing */
      err = _ksba_cms_parse_content_info (cms);
      if (err)
        return err;
      for (i=0; content_handlers[i].oid; i++)
        {
          if (!strcmp (content_handlers[i].oid, cms->content.oid))
            break;
        }
      if (!content_handlers[i].oid)
        return gpg_error (GPG_ERR_UNKNOWN_CMS_OBJ);
      if (!content_handlers[i].parse_handler)
        return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);
      cms->content.ct      = content_handlers[i].ct;
      cms->content.handler = content_handlers[i].parse_handler;
      cms->stop_reason = KSBA_SR_GOT_CONTENT;
    }
  else if (cms->content.handler)
    {
      err = cms->content.handler (cms);
      if (err)
        return err;
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);

  *r_stopreason = cms->stop_reason;
  return 0;
}

gpg_error_t
ksba_cms_build (ksba_cms_t cms, ksba_stop_reason_t *r_stopreason)
{
  gpg_error_t err;

  if (!cms || !r_stopreason)
    return gpg_error (GPG_ERR_INV_VALUE);

  *r_stopreason = KSBA_SR_RUNNING;
  if (!cms->stop_reason)
    { /* Initial state: check that the content handler is known */
      if (!cms->writer)
        return gpg_error (GPG_ERR_MISSING_ACTION);
      if (!cms->content.handler)
        return gpg_error (GPG_ERR_MISSING_ACTION);
      if (!cms->inner_cont_oid)
        return gpg_error (GPG_ERR_MISSING_ACTION);
      cms->stop_reason = KSBA_SR_GOT_CONTENT;
    }
  else if (cms->content.handler)
    {
      err = cms->content.handler (cms);
      if (err)
        return err;
    }
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);

  *r_stopreason = cms->stop_reason;
  return 0;
}




/* Return the content type.  A WHAT of 0 returns the real content type
   whereas a 1 returns the inner content type.
*/
ksba_content_type_t
ksba_cms_get_content_type (ksba_cms_t cms, int what)
{
  int i;

  if (!cms)
    return 0;
  if (!what)
    return cms->content.ct;

  if (what == 1 && cms->inner_cont_oid)
    {
      for (i=0; content_handlers[i].oid; i++)
        {
          if (!strcmp (content_handlers[i].oid, cms->inner_cont_oid))
            return content_handlers[i].ct;
        }
    }
  return 0;
}


/* Return the object ID of the current cms.  This is a constant string
   valid as long as the context is valid and no new parse is
   started. */
const char *
ksba_cms_get_content_oid (ksba_cms_t cms, int what)
{
  if (!cms)
    return NULL;
  if (!what)
    return cms->content.oid;
  if (what == 1)
    return cms->inner_cont_oid;
  if (what == 2)
    return cms->encr_algo_oid;
  return NULL;
}


/* Copy the initialization vector into iv and its len into ivlen.
   The caller should proncrvide a suitable large buffer */
gpg_error_t
ksba_cms_get_content_enc_iv (ksba_cms_t cms, void *iv,
                             size_t maxivlen, size_t *ivlen)
{
  if (!cms || !iv || !ivlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->encr_ivlen)
    return gpg_error (GPG_ERR_NO_DATA);
  if (cms->encr_ivlen > maxivlen)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
  memcpy (iv, cms->encr_iv, cms->encr_ivlen);
  *ivlen = cms->encr_ivlen;
  return 0;
}


/**
 * ksba_cert_get_digest_algo_list:
 * @cms: CMS object
 * @idx: enumerator
 *
 * Figure out the the digest algorithm used for the signature and
 * return its OID.  Note that the algos returned are just hints on
 * what to hash.
 *
 * Return value: NULL for no more algorithms or a string valid as long
 * as the the cms object is valid.
 **/
const char *
ksba_cms_get_digest_algo_list (ksba_cms_t cms, int idx)
{
  struct oidlist_s *ol;

  if (!cms)
    return NULL;

  for (ol=cms->digest_algos; ol && idx; ol = ol->next, idx-- )
    ;
  if (!ol)
    return NULL;
  return ol->oid;
}


/**
 * ksba_cms_get_issuer_serial:
 * @cms: CMS object
 * @idx: index number
 * @r_issuer: returns the issuer
 * @r_serial: returns the serial number
 *
 * This functions returns the issuer and serial number either from the
 * sid or the rid elements of a CMS object.
 *
 * Return value: 0 on success or an error code.  An error code of -1
 * is returned to indicate that there is no issuer with that idx,
 * GPG_ERR_NO_DATA is returned to indicate that there is no issuer at
 * all.
 **/
gpg_error_t
ksba_cms_get_issuer_serial (ksba_cms_t cms, int idx,
                            char **r_issuer, ksba_sexp_t *r_serial)
{
  gpg_error_t err;
  const char *issuer_path, *serial_path;
  AsnNode root;
  const unsigned char *image;
  AsnNode n;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  if (cms->signer_info)
    {
      struct signer_info_s *si;

      for (si=cms->signer_info; si && idx; si = si->next, idx-- )
        ;
      if (!si)
        return -1;

      root = si->root;
      image = si->image;
    }
  else if (cms->recp_info)
    {
      struct value_tree_s *tmp;

      for (tmp=cms->recp_info; tmp && idx; tmp=tmp->next, idx-- )
        ;
      if (!tmp)
        return -1;
      root = tmp->root;
      image = tmp->image;
    }
  else
    return gpg_error (GPG_ERR_NO_DATA);


  if (cms->signer_info)
    {
      issuer_path = "SignerInfo.sid.issuerAndSerialNumber.issuer";
      serial_path = "SignerInfo.sid.issuerAndSerialNumber.serialNumber";
    }
  else if (cms->recp_info)
    {
      /* Find the choice to use.  */
      n = _ksba_asn_find_node (root, "RecipientInfo.+");
      if (!n || !n->name)
        return gpg_error (GPG_ERR_NO_VALUE);

      if (!strcmp (n->name, "ktri"))
        {
          issuer_path = "ktri.rid.issuerAndSerialNumber.issuer";
          serial_path = "ktri.rid.issuerAndSerialNumber.serialNumber";
        }
      else if (!strcmp (n->name, "kari"))
        {
          issuer_path = ("kari..recipientEncryptedKeys"
                         "..rid.issuerAndSerialNumber.issuer");
          serial_path = ("kari..recipientEncryptedKeys"
                         "..rid.issuerAndSerialNumber.serialNumber");
        }
      else if (!strcmp (n->name, "kekri"))
        return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);
      else if (!strcmp (n->name, "pwri"))
        return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);
      else
        return gpg_error (GPG_ERR_INV_CMS_OBJ);
      root = n;
    }

  if (r_issuer)
    {
      n = _ksba_asn_find_node (root, issuer_path);
      if (!n || !n->down)
        return gpg_error (GPG_ERR_NO_VALUE);
      n = n->down; /* dereference the choice node */

      if (n->off == -1)
        {
/*            fputs ("get_issuer problem at node:\n", stderr); */
/*            _ksba_asn_node_dump_all (n, stderr); */
          return gpg_error (GPG_ERR_GENERAL);
        }
      err = _ksba_dn_to_str (image, n, r_issuer);
      if (err)
        return err;
    }

  if (r_serial)
    {
      char numbuf[22];
      int numbuflen;
      unsigned char *p;

      /* fixme: we do not release the r_issuer stuff on error */
      n = _ksba_asn_find_node (root, serial_path);
      if (!n)
        return gpg_error (GPG_ERR_NO_VALUE);

      if (n->off == -1)
        {
/*            fputs ("get_serial problem at node:\n", stderr); */
/*            _ksba_asn_node_dump_all (n, stderr); */
          return gpg_error (GPG_ERR_GENERAL);
        }

      sprintf (numbuf,"(%u:", (unsigned int)n->len);
      numbuflen = strlen (numbuf);
      p = xtrymalloc (numbuflen + n->len + 2);
      if (!p)
        return gpg_error (GPG_ERR_ENOMEM);
      strcpy (p, numbuf);
      memcpy (p+numbuflen, image + n->off + n->nhdr, n->len);
      p[numbuflen + n->len] = ')';
      p[numbuflen + n->len + 1] = 0;
      *r_serial = p;
    }

  return 0;
}



/**
 * ksba_cms_get_digest_algo:
 * @cms: CMS object
 * @idx: index of signer
 *
 * Figure out the the digest algorithm used by the signer @idx return
 * its OID.  This is the algorithm acually used to calculate the
 * signature.
 *
 * Return value: NULL for no such signer or a constn string valid as
 * long as the CMS object lives.
 **/
const char *
ksba_cms_get_digest_algo (ksba_cms_t cms, int idx)
{
  AsnNode n;
  char *algo;
  struct signer_info_s *si;

  if (!cms)
    return NULL;
  if (!cms->signer_info)
    return NULL;
  if (idx < 0)
    return NULL;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return NULL;

  if (si->cache.digest_algo)
    return si->cache.digest_algo;

  n = _ksba_asn_find_node (si->root, "SignerInfo.digestAlgorithm.algorithm");
  algo = _ksba_oid_node_to_str (si->image, n);
  if (algo)
    {
      si->cache.digest_algo = algo;
    }
  return algo;
}


/**
 * ksba_cms_get_cert:
 * @cms: CMS object
 * @idx: enumerator
 *
 * Get the certificate out of a CMS.  The caller should use this in a
 * loop to get all certificates.  The returned certificate is a
 * shallow copy of the original one; the caller must still use
 * ksba_cert_release() to free it.
 *
 * Return value: A Certificate object or NULL for end of list or error
 **/
ksba_cert_t
ksba_cms_get_cert (ksba_cms_t cms, int idx)
{
  struct certlist_s *cl;

  if (!cms || idx < 0)
    return NULL;

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return NULL;
  ksba_cert_ref (cl->cert);
  return cl->cert;
}


/*
 * Return the extension attribute messageDigest
 * or for authenvelopeddata the MAC.
 */
gpg_error_t
ksba_cms_get_message_digest (ksba_cms_t cms, int idx,
                             char **r_digest, size_t *r_digest_len)
{
  AsnNode nsiginfo, n;
  struct signer_info_s *si;

  if (!cms || !r_digest || !r_digest_len)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Hack to return the MAC/authtag value or the authAttr.  */
  if (cms->content.ct == KSBA_CT_AUTHENVELOPED_DATA)
    {
      if (!idx) /* Return authtag.  */
        {
          if (!cms->authdata.mac || !cms->authdata.mac_len)
            return gpg_error (GPG_ERR_NO_DATA);

          *r_digest = xtrymalloc (cms->authdata.mac_len);
          if (!*r_digest)
            return gpg_error_from_syserror ();
          memcpy (*r_digest, cms->authdata.mac, cms->authdata.mac_len);
          *r_digest_len = cms->authdata.mac_len;
        }
      else if (idx == 1) /* Return authAttr.  */
        {
          if (!cms->authdata.attr || !cms->authdata.attr_len)
            return gpg_error (GPG_ERR_NO_DATA);

          *r_digest = xtrymalloc (cms->authdata.attr_len);
          if (!*r_digest)
            return gpg_error_from_syserror ();
          memcpy (*r_digest, cms->authdata.attr, cms->authdata.attr_len);
          *r_digest_len = cms->authdata.attr_len;
        }
      else
        return gpg_error (GPG_ERR_INV_INDEX);

      return 0;
    }


  if (!cms->signer_info)
    return gpg_error (GPG_ERR_NO_DATA);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1;


  *r_digest = NULL;
  *r_digest_len = 0;
  nsiginfo = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!nsiginfo)
    return gpg_error (GPG_ERR_BUG);

  n = _ksba_asn_find_type_value (si->image, nsiginfo, 0,
                                 oid_messageDigest, DIM(oid_messageDigest));
  if (!n)
    return 0; /* this is okay, because the element is optional */

  /* check that there is only one */
  if (_ksba_asn_find_type_value (si->image, nsiginfo, 1,
                                 oid_messageDigest, DIM(oid_messageDigest)))
    return gpg_error (GPG_ERR_DUP_VALUE);

  /* the value is is a SET OF OCTECT STRING but the set must have
     excactly one OCTECT STRING.  (rfc2630 11.2) */
  if ( !(n->type == TYPE_SET_OF && n->down
         && n->down->type == TYPE_OCTET_STRING && !n->down->right))
    return gpg_error (GPG_ERR_INV_CMS_OBJ);
  n = n->down;
  if (n->off == -1)
    return gpg_error (GPG_ERR_BUG);

  *r_digest_len = n->len;
  *r_digest = xtrymalloc (n->len);
  if (!*r_digest)
    return gpg_error (GPG_ERR_ENOMEM);
  memcpy (*r_digest, si->image + n->off + n->nhdr, n->len);
  return 0;
}


/* Return the extension attribute signing time, which may be empty for no
   signing time available. */
gpg_error_t
ksba_cms_get_signing_time (ksba_cms_t cms, int idx, ksba_isotime_t r_sigtime)
{
  AsnNode nsiginfo, n;
  struct signer_info_s *si;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  *r_sigtime = 0;
  if (!cms->signer_info)
    return gpg_error (GPG_ERR_NO_DATA);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1;

  *r_sigtime = 0;
  nsiginfo = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!nsiginfo)
    return 0; /* This is okay because signedAttribs are optional. */

  n = _ksba_asn_find_type_value (si->image, nsiginfo, 0,
                                 oid_signingTime, DIM(oid_signingTime));
  if (!n)
    return 0; /* This is okay because signing time is optional. */

  /* check that there is only one */
  if (_ksba_asn_find_type_value (si->image, nsiginfo, 1,
                                 oid_signingTime, DIM(oid_signingTime)))
    return gpg_error (GPG_ERR_DUP_VALUE);

  /* the value is is a SET OF CHOICE but the set must have
     excactly one CHOICE of generalized or utctime.  (rfc2630 11.3) */
  if ( !(n->type == TYPE_SET_OF && n->down
         && (n->down->type == TYPE_GENERALIZED_TIME
             || n->down->type == TYPE_UTC_TIME)
         && !n->down->right))
    return gpg_error (GPG_ERR_INV_CMS_OBJ);
  n = n->down;
  if (n->off == -1)
    return gpg_error (GPG_ERR_BUG);

  return _ksba_asntime_to_iso (si->image + n->off + n->nhdr, n->len,
                               n->type == TYPE_UTC_TIME, r_sigtime);
}


/* Return a list of OIDs stored as signed attributes for the signature
   number IDX.  All the values (OIDs) for the the requested OID REQOID
   are returned delimited by a linefeed.  Caller must free that
   list. -1 is returned when IDX is larger than the number of
   signatures, GPG_ERR_No_Data is returned when there is no such
   attribute for the given signer. */
gpg_error_t
ksba_cms_get_sigattr_oids (ksba_cms_t cms, int idx,
                           const char *reqoid, char **r_value)
{
  gpg_error_t err;
  AsnNode nsiginfo, n;
  struct signer_info_s *si;
  unsigned char *reqoidbuf;
  size_t reqoidlen;
  char *retstr = NULL;
  int i;

  if (!cms || !r_value)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->signer_info)
    return gpg_error (GPG_ERR_NO_DATA);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);
  *r_value = NULL;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1; /* no more signers */

  nsiginfo = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!nsiginfo)
    return -1; /* this is okay, because signedAttribs are optional */

  err = ksba_oid_from_str (reqoid, &reqoidbuf, &reqoidlen);
  if(err)
    return err;

  for (i=0; (n = _ksba_asn_find_type_value (si->image, nsiginfo,
                                            i, reqoidbuf, reqoidlen)); i++)
    {
      char *line, *p;

      /* the value is is a SET OF OBJECT ID but the set must have
         excactly one OBJECT ID.  (rfc2630 11.1) */
      if ( !(n->type == TYPE_SET_OF && n->down
             && n->down->type == TYPE_OBJECT_ID && !n->down->right))
        {
          xfree (reqoidbuf);
          xfree (retstr);
          return gpg_error (GPG_ERR_INV_CMS_OBJ);
        }
      n = n->down;
      if (n->off == -1)
        {
          xfree (reqoidbuf);
          xfree (retstr);
          return gpg_error (GPG_ERR_BUG);
        }

      p = _ksba_oid_node_to_str (si->image, n);
      if (!p)
        {
          xfree (reqoidbuf);
          xfree (retstr);
          return gpg_error (GPG_ERR_INV_CMS_OBJ);
        }

      if (!retstr)
        line = retstr = xtrymalloc (strlen (p) + 2);
      else
        {
          char *tmp = xtryrealloc (retstr,
                                   strlen (retstr) + 1 + strlen (p) + 2);
          if (!tmp)
            line = NULL;
          else
            {
              retstr = tmp;
              line = stpcpy (retstr + strlen (retstr), "\n");
            }
        }
      if (!line)
        {
          xfree (reqoidbuf);
          xfree (retstr);
          xfree (p);
          return gpg_error (GPG_ERR_ENOMEM);
        }
      strcpy (line, p);
      xfree (p);
    }
  xfree (reqoidbuf);
  if (!n && !i)
    return -1; /* no such attribute */
  *r_value = retstr;
  return 0;
}


/**
 * ksba_cms_get_sig_val:
 * @cms: CMS object
 * @idx: index of signer
 *
 * Return the actual signature of signer @idx in a format suitable to
 * be used as input to Libgcrypt's verification function.  The caller
 * must free the returned string.
 *
 * Return value: NULL or a string with a S-Exp.
 **/
ksba_sexp_t
ksba_cms_get_sig_val (ksba_cms_t cms, int idx)
{
  AsnNode n, n2;
  gpg_error_t err;
  ksba_sexp_t string;
  struct signer_info_s *si;

  if (!cms)
    return NULL;
  if (!cms->signer_info)
    return NULL;
  if (idx < 0)
    return NULL;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return NULL;

  n = _ksba_asn_find_node (si->root, "SignerInfo.signatureAlgorithm");
  if (!n)
      return NULL;
  if (n->off == -1)
    {
/*        fputs ("ksba_cms_get_sig_val problem at node:\n", stderr); */
/*        _ksba_asn_node_dump_all (n, stderr); */
      return NULL;
    }

  n2 = n->right; /* point to the actual value */
  err = _ksba_sigval_to_sexp (si->image + n->off,
                              n->nhdr + n->len
                              + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
                              &string);
  if (err)
      return NULL;

  return string;
}


/* Helper to dump a S-expression. */
#if 0
static void
dbg_print_sexp (ksba_const_sexp_t p)
{
  int level = 0;

  if (!p)
    fputs ("[none]", stdout);
  else
    {
      for (;;)
        {
          if (*p == '(')
            {
              putchar (*p);
              p++;
              level++;
            }
          else if (*p == ')')
            {
              putchar (*p);
              p++;
              if (--level <= 0 )
                {
                  putchar ('\n');
                  return;
                }
            }
          else if (!digitp (p))
            {
              fputs ("[invalid s-exp]\n", stdout);
              return;
            }
          else
            {
              const unsigned char *s;
              char *endp;
              unsigned long len, n;

              len = strtoul (p, &endp, 10);
              p = endp;
              if (*p != ':')
                {
                  fputs ("[invalid s-exp]\n", stdout);
                  return;
                }
              p++;
              for (s=p,n=0; n < len; n++, s++)
                if ( !((*s >= 'a' && *s <= 'z')
                       || (*s >= 'A' && *s <= 'Z')
                       || (*s >= '0' && *s <= '9')
                       || *s == '-' || *s == '.'))
                  break;
              if (n < len)
                {
                  putchar('#');
                  for (n=0; n < len; n++, p++)
                    printf ("%02X", *p);
                  putchar('#');
                }
              else
                {
                  for (n=0; n < len; n++, p++)
                    putchar (*p);
                }
            }
        }
    }
  putchar ('\n');
}
#endif /* 0 */



/**
 * ksba_cms_get_enc_val:
 * @cms: CMS object
 * @idx: index of recipient info
 *
 * Return the encrypted value (the session key) of recipient @idx in a
 * format suitable to be used as input to Libgcrypt's decryption
 * function.  The caller must free the returned string.
 *
 * Return value: NULL or a string with a S-Exp.
 **/
ksba_sexp_t
ksba_cms_get_enc_val (ksba_cms_t cms, int idx)
{
  AsnNode root, n, n2;
  gpg_error_t err;
  ksba_sexp_t string = NULL;
  struct value_tree_s *vt;
  char *keyencralgo = NULL; /* Key encryption algo.  */
  char *parm = NULL;        /* Helper to get the parms of kencralgo.  */
  size_t parmlen;
  char *parm2 = NULL;
  size_t parm2len;
  char *parm3 = NULL;
  size_t parm3len;
  char *keywrapalgo = NULL; /* Key wrap algo.  */
  char *keyderivealgo = NULL; /* Key derive algo.  */
  struct tag_info ti;
  const unsigned char *der;
  size_t derlen;

  if (!cms)
    return NULL;
  if (!cms->recp_info)
    return NULL;
  if (idx < 0)
    return NULL;

  for (vt=cms->recp_info; vt && idx; vt=vt->next, idx--)
    ;
  if (!vt)
    return NULL; /* No value at this IDX */

  /* Find the choice to use.  */
  root = _ksba_asn_find_node (vt->root, "RecipientInfo.+");
  if (!root || !root->name)
    return NULL;

  if (!strcmp (root->name, "ktri"))
    {
      char *algoid = NULL;
      n = _ksba_asn_find_node (root, "ktri.keyEncryptionAlgorithm");
      if (!n || n->off == -1)
        return NULL;
      n2 = n->right; /* point to the actual value */
      err = _ksba_encval_to_sexp
        (vt->image + n->off,
         n->nhdr + n->len + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
         &string);
      if (err)
        goto leave;

      n = _ksba_asn_find_node (root,
                               "ktri.keyEncryptionAlgorithm.algorithm");
      if (n)
        algoid = _ksba_oid_node_to_str (vt->image, n);
      if (algoid && !strncmp (algoid, "1.2.643", 7))
        {
          ksba_cert_t cert = ksba_cms_get_cert (cms, idx);
          if (cert)
            {
              err = _ksba_check_key_usage_for_gost (cert,
                                                    KSBA_KEYUSAGE_KEY_ENCIPHERMENT);
              if (!err)
                err = check_policy_tk26 (cert);
              ksba_cert_release (cert);
              if (err)
                goto leave;
            }
        }
      xfree (algoid);
    }
  else if (!strcmp (root->name, "kari"))
    {
      char *algoid = NULL;
      /* _ksba_asn_node_dump_all (root, stderr); */

      /* Get the encrypted key.  Result is in (DER,DERLEN)  */
      n = _ksba_asn_find_node (root, ("kari..recipientEncryptedKeys"
                                      "..encryptedKey"));
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }

      der = vt->image + n->off;
      derlen = n->nhdr + n->len;
      err = parse_octet_string (&der, &derlen, &ti);
      if (err)
        goto leave;
      derlen = ti.length;
      /* gpgrt_log_printhex (der, derlen, "%s: encryptedKey", __func__); */

      /* Get the KEK algos.  */
      n = _ksba_asn_find_node (root, "kari..keyEncryptionAlgorithm");
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      err = _ksba_parse_algorithm_identifier2 (vt->image + n->off,
                                               n->nhdr + n->len, NULL,
                                               &keyencralgo, &parm, &parmlen);
      if (err)
        goto leave;
      if (!parm)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      err = _ksba_parse_algorithm_identifier (parm, parmlen,NULL, &keywrapalgo);
      if (err)
        goto leave;

      /* gpgrt_log_debug ("%s: keyencralgo='%s'\n", __func__, keyencralgo); */
      /* gpgrt_log_debug ("%s: keywrapalgo='%s'\n", __func__, keywrapalgo); */

      /* Get the ephemeral public key.  */
      n = _ksba_asn_find_node (root, "kari..originator..originatorKey");
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      err = _ksba_encval_kari_to_sexp (vt->image + n->off, n->nhdr + n->len,
                                       keyencralgo, keywrapalgo, der, derlen,
                                       &string);
      if (err)
        goto leave;
      algoid = keyencralgo;
      if (algoid && !strncmp (algoid, "1.2.643", 7))
        {
          ksba_cert_t cert = ksba_cms_get_cert (cms, idx);
          if (cert)
            {
              err = _ksba_check_key_usage_for_gost (cert,
                                                    KSBA_KEYUSAGE_KEY_ENCIPHERMENT);
              if (!err)
                err = check_policy_tk26 (cert);
              ksba_cert_release (cert);
              if (err)
                goto leave;
            }
        }

      /* gpgrt_log_debug ("%s: encryptedKey:\n", __func__); */
      /* dbg_print_sexp (string); */
    }
  else if (!strcmp (root->name, "kekri"))
    {
      char *algoid = NULL;

      n = _ksba_asn_find_node (root, "kekri.keyEncryptionAlgorithm");
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      n2 = n->right;
      err = _ksba_encval_to_sexp (vt->image + n->off,
                                  n->nhdr + n->len
                                  + ((!n2||n2->off == -1)?0:(n2->nhdr+n2->len)),
                                  &string);
      if (err)
        goto leave;

      n = _ksba_asn_find_node (root,
                               "kekri.keyEncryptionAlgorithm.algorithm");
      if (n)
        algoid = _ksba_oid_node_to_str (vt->image, n);

      if (algoid && !strncmp (algoid, "1.2.643", 7))
        {
          ksba_cert_t cert = ksba_cms_get_cert (cms, idx);
          if (cert)
            {
              err = _ksba_check_key_usage_for_gost (cert,
                                                    KSBA_KEYUSAGE_KEY_ENCIPHERMENT);
              if (!err)
                err = check_policy_tk26 (cert);
              ksba_cert_release (cert);
              if (err)
                goto leave;
            }
        }
      xfree (algoid);
    }
  else if (!strcmp (root->name, "pwri"))
    {
      /* _ksba_asn_node_dump_all (root, stderr); */

      n = _ksba_asn_find_node (root, "pwri..keyEncryptionAlgorithm");
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      err = _ksba_parse_algorithm_identifier2 (vt->image + n->off,
                                               n->nhdr + n->len, NULL,
                                               &keyencralgo, &parm, &parmlen);
      if (err)
        goto leave;
      if (strcmp (keyencralgo, "1.2.840.113549.1.9.16.3.9"))
        {
          /* pwri requires this and only this OID.  */
          err = gpg_error (GPG_ERR_INV_CMS_OBJ);
          goto leave;
        }
      if (!parm)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      /* gpgrt_log_printhex (parm, parmlen, "parms"); */
      err = _ksba_parse_algorithm_identifier2 (parm, parmlen, NULL,
                                               &keywrapalgo, &parm2, &parm2len);
      if (err)
        goto leave;

      /* gpgrt_log_debug ("%s: keywrapalgo='%s'\n", __func__, keywrapalgo); */
      /* gpgrt_log_printhex (parm2, parm2len, "parm:"); */

      n = _ksba_asn_find_node (root, "pwri..keyDerivationAlgorithm");
      if (!n || n->off == -1)
        {
          /* Not found but that is okay becuase it is optional.  */
        }
      else
        {
          err = _ksba_parse_algorithm_identifier3 (vt->image + n->off,
                                                   n->nhdr + n->len, 0xa0, NULL,
                                                   &keyderivealgo,
                                                   &parm3, &parm3len, NULL);
          if (err)
            goto leave;
        }

      n = _ksba_asn_find_node (root, "pwri..encryptedKey");
      if (!n || n->off == -1)
        {
          err = gpg_error (GPG_ERR_INV_KEYINFO);
          goto leave;
        }
      der = vt->image + n->off;
      derlen = n->nhdr + n->len;
      err = parse_octet_string (&der, &derlen, &ti);
      if (err)
        goto leave;
      derlen = ti.length;
      /* gpgrt_log_printhex (der, derlen, "encryptedKey:"); */

      /* Build the s-expression:
       *  (enc-val
       *    (pwri
       *      (derive-algo <oid>) --| both are optional
       *      (derive-parm <der>) --|
       *      (encr-algo <oid>)
       *      (encr-parm <iv>)
       *      (encr-key <key>)))  -- this is the encrypted session key
       */
      {
        struct stringbuf sb;

        init_stringbuf (&sb, 200);
        put_stringbuf (&sb, "(7:enc-val(4:pwri");
        if (keyderivealgo && parm3)
          {
            put_stringbuf (&sb, "(11:derive-algo");
            put_stringbuf_sexp (&sb, keyderivealgo);
            put_stringbuf (&sb, ")(11:derive-parm");
            put_stringbuf_mem_sexp (&sb, parm3, parm3len);
            put_stringbuf (&sb, ")");
          }
        put_stringbuf (&sb, "(9:encr-algo");
        put_stringbuf_sexp (&sb, keywrapalgo);
        put_stringbuf (&sb, ")(9:encr-parm");
        put_stringbuf_mem_sexp (&sb, parm2, parm2len);
        put_stringbuf (&sb, ")(8:encr-key");
        put_stringbuf_mem_sexp (&sb, der, derlen);
        put_stringbuf (&sb, ")))");

        string = get_stringbuf (&sb);
        if (!string)
          err = gpg_error_from_syserror ();
      }

    }
  else
    return NULL; /*GPG_ERR_INV_CMS_OBJ*/

 leave:
  xfree (keyencralgo);
  xfree (keywrapalgo);
  xfree (keyderivealgo);
  xfree (parm);
  xfree (parm2);
  xfree (parm3);
  if (err)
    {
      /* gpgrt_log_debug ("%s: error: %s\n", __func__, gpg_strerror (err)); */
      return NULL;
    }

  return string;
}





/* Provide a hash function so that we are able to hash the data */
void
ksba_cms_set_hash_function (ksba_cms_t cms,
                            void (*hash_fnc)(void *, const void *, size_t),
                            void *hash_fnc_arg)
{
  if (cms)
    {
      cms->hash_fnc = hash_fnc;
      cms->hash_fnc_arg = hash_fnc_arg;
    }
}


/* hash the signed attributes of the given signer */
gpg_error_t
ksba_cms_hash_signed_attrs (ksba_cms_t cms, int idx)
{
  AsnNode n;
  struct signer_info_s *si;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->hash_fnc)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (idx < 0)
    return -1;

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1;

  n = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!n || n->off == -1)
    return gpg_error (GPG_ERR_NO_VALUE);

  /* We don't hash the implicit tag [0] but a SET tag */
  cms->hash_fnc (cms->hash_fnc_arg, "\x31", 1);
  cms->hash_fnc (cms->hash_fnc_arg,
                 si->image + n->off + 1, n->nhdr + n->len - 1);

  return 0;
}

/*
 * Check signed attributes for GOST signatures.  This verifies that the
 * content-type attribute matches CONTENT_OID and that the message-digest
 * attribute equals DIGEST.
 */
gpg_error_t
ksba_cms_check_signed_attrs_gost (ksba_cms_t cms, int idx,
                                  const char *content_oid,
                                  const unsigned char *digest,
                                  size_t digest_len)
{
  gpg_error_t err;
  AsnNode nsiginfo, n;
  AsnNode seq_ct = NULL;
  AsnNode seq_md = NULL;
  struct signer_info_s *si;
  unsigned char *oidbuf = NULL;
  size_t oidlen;

  if (!cms || !content_oid || !digest)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (si=cms->signer_info; si && idx; si = si->next, idx-- )
    ;
  if (!si)
    return -1;

  {
    ksba_cert_t cert = ksba_cms_get_cert (cms, idx);
    if (cert)
      {
        err = _ksba_check_key_usage_for_gost (cert,
                                              KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
        if (!err)
          err = check_policy_tk26 (cert);
        ksba_cert_release (cert);
        if (err)
          return err;
      }
  }

  nsiginfo = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
  if (!nsiginfo)
    return gpg_error (GPG_ERR_NO_DATA);

  /* Check for the content-type attribute and remember its location.  */
  err = ksba_oid_from_str (content_oid, &oidbuf, &oidlen);
  if (err)
    return err;
  n = _ksba_asn_find_type_value (si->image, nsiginfo, 0, oidbuf, oidlen);
  if (!n)
    {
      xfree (oidbuf);
      return gpg_error (GPG_ERR_BAD_SIGNATURE);
    }
  if (_ksba_asn_find_type_value (si->image, nsiginfo, 1, oidbuf, oidlen))
    {
      xfree (oidbuf);
      return gpg_error (GPG_ERR_DUP_VALUE);
    }
  seq_ct = find_up (n);
  xfree (oidbuf);

  /* Locate the message-digest attribute and verify the order.  */
  n = _ksba_asn_find_type_value (si->image, nsiginfo, 0,
                                 oid_messageDigest, DIM (oid_messageDigest));
  if (!n || _ksba_asn_find_type_value (si->image, nsiginfo, 1,
                                       oid_messageDigest,
                                       DIM (oid_messageDigest)))
    return gpg_error (GPG_ERR_BAD_SIGNATURE);
  seq_md = find_up (n);
  if (!seq_ct || !seq_md || seq_ct->off == -1 || seq_md->off == -1)
    return gpg_error (GPG_ERR_BUG);
  if (seq_ct->off > seq_md->off)
    return gpg_error (GPG_ERR_BAD_SIGNATURE);
  /* The value is is a SET OF OCTET STRING but the set must have exactly
     one OCTET STRING.  (rfc2630 11.2)  */
  if (!(n->type == TYPE_SET_OF && n->down
        && n->down->type == TYPE_OCTET_STRING && !n->down->right))
    return gpg_error (GPG_ERR_INV_CMS_OBJ);
  n = n->down;
  if (n->off == -1)
    return gpg_error (GPG_ERR_BUG);
  if (n->len != digest_len
      || memcmp (si->image + n->off + n->nhdr, digest, digest_len))
    return gpg_error (GPG_ERR_BAD_SIGNATURE);

  return 0;
}


/* Check a RecipientInfo using GOST VKO.  This validates the
 * originator key format, allowed algorithm OIDs, and the UKM.  In
 * addition the certificate of the recipient is checked for the VKO
 * keyUsage and the TK-26 policy.  */
gpg_error_t
ksba_cms_check_recipientinfo_vko (ksba_cms_t cms, int idx)
{
  gpg_error_t err;
  struct value_tree_s *vt;
  AsnNode root, n;
  char *algo = NULL;
  struct tag_info ti;

  if (!cms || idx < 0)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!cms->recp_info)
    return gpg_error (GPG_ERR_NO_DATA);

  for (vt = cms->recp_info; vt && idx; vt = vt->next, idx--)
    ;
  if (!vt)
    return gpg_error (GPG_ERR_INV_INDEX);

  root = _ksba_asn_find_node (vt->root, "RecipientInfo.kari");
  if (!root)
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  /* Check the key encryption algorithm.  */
  n = _ksba_asn_find_node (root, "kari.keyEncryptionAlgorithm");
  if (!n || n->off == -1)
    return gpg_error (GPG_ERR_INV_KEYINFO);
  err = _ksba_parse_algorithm_identifier2 (vt->image + n->off,
                                           n->nhdr + n->len, NULL,
                                           &algo, NULL, NULL);
  if (err)
    goto leave;
  if (strcmp (algo, "1.2.643.2.2.96"))
    { err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO); goto leave; }

  /* Check the originator key.  */
  n = _ksba_asn_find_node (root, "kari.originator.originatorKey");
  if (!n || n->off == -1)
    { err = gpg_error (GPG_ERR_INV_KEYINFO); goto leave; }
  {
    const unsigned char *der = vt->image + n->off;
    size_t derlen = n->nhdr + n->len;
    char *tmpoid = NULL;
    size_t nread;

    err = _ksba_parse_context_tag (&der, &derlen, &ti, 1);
    if (err)
      goto leave;
    err = _ksba_parse_algorithm_identifier2 (der, derlen, &nread,
                                             &tmpoid, NULL, NULL);
    if (err)
      { xfree (tmpoid); goto leave; }
    if (strncmp (tmpoid, "1.2.643", 7))
      { xfree (tmpoid); err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO); goto leave; }
    der += nread;
    derlen -= nread;
    xfree (tmpoid);

    err = _ksba_ber_parse_tl (&der, &derlen, &ti);
    if (err)
      goto leave;
    if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_BIT_STRING
          && !ti.is_constructed) || ti.length > derlen)
      { err = gpg_error (GPG_ERR_INV_OBJ); goto leave; }
    der += ti.length;
    derlen -= ti.length;
    if (derlen)
      { err = gpg_error (GPG_ERR_INV_OBJ); goto leave; }
  }

  /* Check the UKM.  */
  n = _ksba_asn_find_node (root, "kari.ukm");
  if (!n || n->off == -1)
    { err = gpg_error (GPG_ERR_INV_CMS_OBJ); goto leave; }
  else
    {
      const unsigned char *der = vt->image + n->off;
      size_t derlen = n->nhdr + n->len;

      err = _ksba_parse_octet_string (&der, &derlen, &ti);
      if (err)
        goto leave;
      if (!ti.length)
        { err = gpg_error (GPG_ERR_INV_CMS_OBJ); goto leave; }
    }

  {
    ksba_cert_t cert = ksba_cms_get_cert (cms, idx);
    if (cert)
      {
        err = _ksba_check_key_usage_for_gost (cert,
                                              KSBA_KEYUSAGE_KEY_ENCIPHERMENT);
        if (!err)
          err = check_policy_tk26 (cert);
        ksba_cert_release (cert);
        if (err)
          goto leave;
      }
  }

  err = 0;

leave:
  xfree (algo);
  return err;
}



/*
  Code to create CMS structures
*/


/**
 * ksba_cms_set_content_type:
 * @cms: A CMS object
 * @what: 0 for content type, 1 for inner content type
 * @type: Type constant
 *
 * Set the content type used for build operations.  This should be the
 * first operation before starting to create a CMS message.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_set_content_type (ksba_cms_t cms, int what, ksba_content_type_t type)
{
  int i;
  char *oid;

  if (!cms || what < 0 || what > 1 )
    return gpg_error (GPG_ERR_INV_VALUE);

  for (i=0; content_handlers[i].oid; i++)
    {
      if (content_handlers[i].ct == type)
        break;
    }
  if (!content_handlers[i].oid)
    return gpg_error (GPG_ERR_UNKNOWN_CMS_OBJ);
  if (!content_handlers[i].build_handler)
    return gpg_error (GPG_ERR_UNSUPPORTED_CMS_OBJ);
  oid = xtrystrdup (content_handlers[i].oid);
  if (!oid)
    return gpg_error (GPG_ERR_ENOMEM);

  if (!what)
    {
      cms->content.oid     = oid;
      cms->content.ct      = content_handlers[i].ct;
      cms->content.handler = content_handlers[i].build_handler;
    }
  else
    {
      cms->inner_cont_oid = oid;
    }

  return 0;
}


/**
 * ksba_cms_add_digest_algo:
 * @cms:  A CMS object
 * @oid: A stringified object OID describing the hash algorithm
 *
 * Set the algorithm to be used for creating the hash. Note, that we
 * currently can't do a per-signer hash.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_add_digest_algo (ksba_cms_t cms, const char *oid)
{
  struct oidlist_s *ol;

  if (!cms || !oid)
    return gpg_error (GPG_ERR_INV_VALUE);

  ol = xtrymalloc (sizeof *ol);
  if (!ol)
    return gpg_error (GPG_ERR_ENOMEM);

  ol->oid = xtrystrdup (oid);
  if (!ol->oid)
    {
      xfree (ol);
      return gpg_error (GPG_ERR_ENOMEM);
    }
  ol->next = cms->digest_algos;
  cms->digest_algos = ol;
  return 0;
}


/**
 * ksba_cms_add_signer:
 * @cms: A CMS object
 * @cert: A certificate used to describe the signer.
 *
 * This functions starts assembly of a new signed data content or adds
 * another signer to the list of signers.
 *
 * Return value: 0 on success or an error code.
 **/
gpg_error_t
ksba_cms_add_signer (ksba_cms_t cms, ksba_cert_t cert)
{
  struct certlist_s *cl, *cl2;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);

  cl = xtrycalloc (1,sizeof *cl);
  if (!cl)
      return gpg_error (GPG_ERR_ENOMEM);

  ksba_cert_ref (cert);
  cl->cert = cert;
  if (!cms->cert_list)
    cms->cert_list = cl;
  else
    {
      for (cl2=cms->cert_list; cl2->next; cl2 = cl2->next)
        ;
      cl2->next = cl;
    }
  return 0;
}

/**
 * ksba_cms_add_cert:
 * @cms: A CMS object
 * @cert: A certificate to be send along with the signed data.
 *
 * This functions adds a certificate to the list of certificates send
 * along with the signed data.  Using this is optional but it is very
 * common to include at least the certificate of the signer it self.
 *
 * Return value: 0 on success or an error code.
 **/
gpg_error_t
ksba_cms_add_cert (ksba_cms_t cms, ksba_cert_t cert)
{
  struct certlist_s *cl;

  if (!cms || !cert)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* first check whether this is a duplicate. */
  for (cl = cms->cert_info_list; cl; cl = cl->next)
    {
      if (!_ksba_cert_cmp (cert, cl->cert))
        return 0; /* duplicate */
    }

  /* Okay, add it. */
  cl = xtrycalloc (1,sizeof *cl);
  if (!cl)
      return gpg_error (GPG_ERR_ENOMEM);

  ksba_cert_ref (cert);
  cl->cert = cert;
  cl->next = cms->cert_info_list;
  cms->cert_info_list = cl;
  return 0;
}


/* Add an S/MIME capability as an extended attribute to the message.
   This function is to be called for each capability in turn. The
   first capability added will receive the highest priority.  CMS is
   the context, OID the object identifier of the capability and if DER
   is not NULL it is used as the DER-encoded parameters of the
   capability; the length of that DER object is given in DERLEN.
   DERLEN should be 0 if DER is NULL.

   The function returns 0 on success or an error code.
*/
gpg_error_t
ksba_cms_add_smime_capability (ksba_cms_t cms, const char *oid,
                               const unsigned char *der, size_t derlen)
{
  gpg_error_t err;
  struct oidparmlist_s *opl, *opl2;

  if (!cms || !oid)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!der)
    derlen = 0;

  opl = xtrymalloc (sizeof *opl + derlen - 1);
  if (!opl)
    return gpg_error_from_errno (errno);
  opl->next = NULL;
  opl->oid = xtrystrdup (oid);
  if (!opl->oid)
    {
      err = gpg_error_from_errno (errno);
      xfree (opl);
      return err;
    }
  opl->parmlen = derlen;
  if (der)
    memcpy (opl->parm, der, derlen);

  /* Append it to maintain the desired order. */
  if (!cms->capability_list)
    cms->capability_list = opl;
  else
    {
      for (opl2=cms->capability_list; opl2->next; opl2 = opl2->next)
        ;
      opl2->next = opl;
    }

  return 0;
}



/**
 * ksba_cms_set_message_digest:
 * @cms: A CMS object
 * @idx: The index of the signer
 * @digest: a message digest
 * @digest_len: the length of the message digest
 *
 * Set a message digest into the signedAttributes of the signer with
 * the index IDX.  The index of a signer is determined by the sequence
 * of ksba_cms_add_signer() calls; the first signer has the index 0.
 * This function is to be used when the hash value of the data has
 * been calculated and before the create function requests the sign
 * operation.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_set_message_digest (ksba_cms_t cms, int idx,
                             const unsigned char *digest, size_t digest_len)
{
  struct certlist_s *cl;

  if (!cms || !digest)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!digest_len || digest_len > DIM(cl->msg_digest))
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return gpg_error (GPG_ERR_INV_INDEX); /* no certificate to store it */
  cl->msg_digest_len = digest_len;
  memcpy (cl->msg_digest, digest, digest_len);
  return 0;
}

/**
 * ksba_cms_set_signing_time:
 * @cms: A CMS object
 * @idx: The index of the signer
 * @sigtime: a time or an empty value to use the current time
 *
 * Set a signing time into the signedAttributes of the signer with
 * the index IDX.  The index of a signer is determined by the sequence
 * of ksba_cms_add_signer() calls; the first signer has the index 0.
 *
 * Return value: 0 on success or an error code
 **/
gpg_error_t
ksba_cms_set_signing_time (ksba_cms_t cms, int idx, const ksba_isotime_t sigtime)
{
  struct certlist_s *cl;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return gpg_error (GPG_ERR_INV_INDEX); /* no certificate to store it */

  /* Fixme: We might want to check the validity of the passed time
     string. */
  if (!*sigtime)
    _ksba_current_time (cl->signing_time);
  else
    _ksba_copy_time (cl->signing_time, sigtime);
  return 0;
}


/* Set the signature value as a canonical encoded s-expression.
 *
 * r_sig  = (sig-val
 *	      (<algo>
 *		(<param_name1> <mpi>)
 *		...
 *		(<param_namen> <mpi>)
 *	      ))
 *
 * <algo> must be given as a stringified OID or the special string
 * "rsa".  For ECC <algo> must either be "ecdsa" or the OID matching the used
 * hash algorithm; the expected parameters are "r" and "s".
 *
 * Note that IDX is only used for consistency checks.
 */
gpg_error_t
ksba_cms_set_sig_val (ksba_cms_t cms, int idx, ksba_const_sexp_t sigval)
{
  gpg_error_t err;
  unsigned long n, namelen;
  struct sig_val_s *sv, **sv_tail;
  const unsigned char *s, *endp, *name;
  int ecc;  /* True for ECC algos.  */
  int i;

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX); /* only one signer for now */

  /* log_sexp ("sigval:", sigval); */
  s = sigval;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;

  for (i=0, sv_tail=&cms->sig_val; *sv_tail; sv_tail=&(*sv_tail)->next, i++)
    ;
  if (i != idx)
    return gpg_error (GPG_ERR_INV_INDEX);

  if (!(n = snext (&s)))
    return gpg_error (GPG_ERR_INV_SEXP);
  if (!smatch (&s, 7, "sig-val"))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  if (*s != '(')
    return gpg_error (digitp (s)? GPG_ERR_UNKNOWN_SEXP : GPG_ERR_INV_SEXP);
  s++;

  /* Break out the algorithm ID. */
  if (!(n = snext (&s)))
    return gpg_error (GPG_ERR_INV_SEXP);

  sv = xtrycalloc (1, sizeof *sv);
  if (!sv)
    return gpg_error (GPG_ERR_ENOMEM);

  if (n==3 && s[0] == 'r' && s[1] == 's' && s[2] == 'a')
    {
      sv->algo = xtrystrdup ("1.2.840.113549.1.1.1"); /* rsa */
      if (!sv->algo)
        {
          xfree (sv);
          return gpg_error (GPG_ERR_ENOMEM);
        }
    }
  else if (n==5 && !memcmp (s, "ecdsa", 5))
    {
      /* Use a placeholder for later fixup.  */
      sv->algo = xtrystrdup ("ecdsa");
      if (!sv->algo)
        {
          xfree (sv);
          return gpg_error (GPG_ERR_ENOMEM);
        }
    }
  else
    {
      sv->algo = xtrymalloc (n+1);
      if (!sv->algo)
        {
          xfree (sv);
          return gpg_error (GPG_ERR_ENOMEM);
        }
      memcpy (sv->algo, s, n);
      sv->algo[n] = 0;
    }
  s += n;

  ecc = (!strcmp (sv->algo, "ecdsa")                  /* placeholder */
         || !strcmp (sv->algo, "1.2.840.10045.4.3.2") /* ecdsa-with-SHA256 */
         || !strcmp (sv->algo, "1.2.840.10045.4.3.3") /* ecdsa-with-SHA384 */
         || !strcmp (sv->algo, "1.2.840.10045.4.3.4") /* ecdsa-with-SHA512 */
         || !strcmp (sv->algo, "gost")
         || !strncmp (sv->algo, "1.2.643", 7)
         );

  xfree (sv->value); sv->value = NULL;
  xfree (sv->ecc.r); sv->ecc.r = NULL;

  while (*s == '(')
    {
      s++;
      n = strtoul (s, (char**)&endp, 10);
      s = endp;
      if (!n || *s != ':')
        {
          err = gpg_error (GPG_ERR_INV_SEXP);
          goto leave;
        }
      s++;
      name = s;
      namelen = n;
      s += n;

      if (!digitp(s))
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP); /* or invalid sexp */
          goto leave;
        }
      n = strtoul (s, (char**)&endp, 10);
      s = endp;
      if (!n || *s != ':')
        {
          err = gpg_error (GPG_ERR_INV_SEXP);
          goto leave;
        }
      s++;

      if (namelen == 1 && *name == 's')
        {
          /* Store the "main" parameter into value. */
          xfree (sv->value);
          sv->value = xtrymalloc (n);
          if (!sv->value)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          memcpy (sv->value, s, n);
          sv->valuelen = n;
        }
      else if (ecc && namelen == 1 && *name == 'r')
        {
          xfree (sv->ecc.r);
          sv->ecc.r = xtrymalloc (n);
          if (!sv->ecc.r)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          memcpy (sv->ecc.r, s, n);
          sv->ecc.rlen = n;
        }
      /* (We ignore all other parameter of the (key value) form.)  */

      s += n;
      if ( *s != ')')
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP); /* or invalid sexp */
          goto leave;
        }
      s++;
    }

  /* Expect two closing parenthesis.  */
  if (*s != ')')
    {
      err = gpg_error (digitp (s)? GPG_ERR_UNKNOWN_SEXP : GPG_ERR_INV_SEXP);
      goto leave;
    }
  s++;
  if ( *s != ')')
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }

  /* Check that we have all required data.  */
  if (!sv->value)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }
  if (ecc && (!sv->ecc.r || !sv->ecc.rlen))
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }

  if (is_gost_algo (sv->algo))
    {
      ksba_cert_t cert = ksba_cms_get_cert (cms, idx);
      if (cert)
        {
          err = _ksba_check_key_usage_for_gost (cert,
                                                KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
          if (!err)
            err = check_policy_tk26 (cert);
          ksba_cert_release (cert);
          if (err)
            goto leave;
        }
    }
	
	
  *sv_tail = sv;
  return 0; /* Success.  */

 leave:  /* Note: This is an error-only label.  */
  xfree (sv->value);
  xfree (sv->algo);
  xfree (sv->ecc.r);
  xfree (sv);
  return err;
}


/* Set the content encryption algorithm to OID and optionally set the
   initialization vector to IV */
gpg_error_t
ksba_cms_set_content_enc_algo (ksba_cms_t cms,
                               const char *oid,
                               const void *iv, size_t ivlen)
{
  if (!cms || !oid)
    return gpg_error (GPG_ERR_INV_VALUE);

  xfree (cms->encr_iv);
  cms->encr_iv = NULL;
  cms->encr_ivlen = 0;

  cms->encr_algo_oid = xtrystrdup (oid);
  if (!cms->encr_algo_oid)
    return gpg_error (GPG_ERR_ENOMEM);

  if (iv)
    {
      cms->encr_iv = xtrymalloc (ivlen);
      if (!cms->encr_iv)
        return gpg_error (GPG_ERR_ENOMEM);
      memcpy (cms->encr_iv, iv, ivlen);
      cms->encr_ivlen = ivlen;
    }
  return 0;
}


/*
 * encval is expected to be a canonical encoded  S-Exp of this form:
 *  (enc-val
 *	(<algo>
 *	   (<param_name1> <mpi>)
 *	    ...
 *         (<param_namen> <mpi>)
 *         (encr-algo <oid>)
 *         (wrap-algo <oid>)
 *	))
 *
 * Note the <algo> must be given as a stringified OID or the special
 * string "rsa".  For RSA there is just one parameter named "a";
 * encr-algo and wrap-algo are also not used.  For ECC <algo> must be
 * "ecdh", the parameter "s" gives the encrypted key, "e" specified
 * the ephemeral public key, and wrap-algo algo and encr-algo are the
 * stringified OIDs for the ECDH algorithm parameters.  */
gpg_error_t
ksba_cms_set_enc_val (ksba_cms_t cms, int idx, ksba_const_sexp_t encval)
{
  /*FIXME: This shares most code with ...set_sig_val */
  struct certlist_s *cl;
  const char *s, *endp, *name;
  unsigned long n, namelen;
  int ecdh = 0;   /* We expect ECC parameters.  */

  if (!cms)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (idx < 0)
    return gpg_error (GPG_ERR_INV_INDEX);
  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return gpg_error (GPG_ERR_INV_INDEX); /* No cert to store the value.  */

  /* log_sexp ("encval", encval); */
  s = encval;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;

  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s!=':')
    return gpg_error (GPG_ERR_INV_SEXP); /* we don't allow empty lengths */
  s++;
  if (n != 7 || memcmp (s, "enc-val", 7))
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);
  s += 7;
  if (*s != '(')
    return gpg_error (digitp (s)? GPG_ERR_UNKNOWN_SEXP : GPG_ERR_INV_SEXP);
  s++;

  /* break out the algorithm ID */
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return gpg_error (GPG_ERR_INV_SEXP); /* we don't allow empty lengths */
  s++;
  xfree (cl->enc_val.algo);
  if (n==3 && !memcmp (s, "rsa", 3))
    { /* kludge to allow "rsa" to be passed as algorithm name */
      cl->enc_val.algo = xtrystrdup ("1.2.840.113549.1.1.1");
      if (!cl->enc_val.algo)
        return gpg_error (GPG_ERR_ENOMEM);
    }
  else if (n==4 && !memcmp (s, "ecdh", 4))
    {
      cl->enc_val.algo = xtrystrdup ("1.2.840.10045.2.1"); /* ecPublicKey */
      if (!cl->enc_val.algo)
        return gpg_error (GPG_ERR_ENOMEM);
    }
  else
    {
      cl->enc_val.algo = xtrymalloc (n+1);
      if (!cl->enc_val.algo)
        return gpg_error (GPG_ERR_ENOMEM);
      memcpy (cl->enc_val.algo, s, n);
      cl->enc_val.algo[n] = 0;
    }
  s += n;

  ecdh = (!strcmp (cl->enc_val.algo, "1.2.840.10045.2.1")
          || !strncmp (cl->enc_val.algo, "1.2.643", 7));
  xfree (cl->enc_val.value);  cl->enc_val.value = NULL;
  xfree (cl->enc_val.ecdh.e); cl->enc_val.ecdh.e = NULL;
  xfree (cl->enc_val.ecdh.encr_algo); cl->enc_val.ecdh.encr_algo = NULL;
  xfree (cl->enc_val.ecdh.wrap_algo); cl->enc_val.ecdh.wrap_algo = NULL;
  xfree (cl->enc_val.ecdh.ukm); cl->enc_val.ecdh.ukm = NULL; cl->enc_val.ecdh.ukmlen = 0;


  while (*s == '(')
    {
      s++;
      n = strtoul (s, (char**)&endp, 10);
      s = endp;
      if (!n || *s != ':')
        return gpg_error (GPG_ERR_INV_SEXP);
      s++;
      name = s;
      namelen = n;
      s += n;

      if (!digitp(s))
        return gpg_error (GPG_ERR_UNKNOWN_SEXP); /* or invalid sexp */
      n = strtoul (s, (char**)&endp, 10);
      s = endp;
      if (!n || *s != ':')
        return gpg_error (GPG_ERR_INV_SEXP);
      s++;

      if (namelen == 1 && ((!ecdh && *name == 'a') || (ecdh && *name == 's')))
        {
          /* Store the "main" parameter into value. */
          xfree (cl->enc_val.value);
          cl->enc_val.value = xtrymalloc (n);
          if (!cl->enc_val.value)
            return gpg_error (GPG_ERR_ENOMEM);
          memcpy (cl->enc_val.value, s, n);
          cl->enc_val.valuelen = n;
        }
      else if (!ecdh)
        ; /* Ignore all other parameters for RSA.  */
      else if (namelen == 1 && *name == 'e')
        {
          xfree (cl->enc_val.ecdh.e);
          cl->enc_val.ecdh.e = xtrymalloc (n);
          if (!cl->enc_val.ecdh.e)
            return gpg_error (GPG_ERR_ENOMEM);
          memcpy (cl->enc_val.ecdh.e, s, n);
          cl->enc_val.ecdh.elen = n;
        }
      else if (namelen == 9 && !memcmp (name, "encr-algo", 9))
        {
          xfree (cl->enc_val.ecdh.encr_algo);
          cl->enc_val.ecdh.encr_algo = xtrymalloc (n+1);
          if (!cl->enc_val.ecdh.encr_algo)
            return gpg_error (GPG_ERR_ENOMEM);
          memcpy (cl->enc_val.ecdh.encr_algo, s, n);
          cl->enc_val.ecdh.encr_algo[n] = 0;
        }
      else if (namelen == 9 && !memcmp (name, "wrap-algo", 9))
        {
          xfree (cl->enc_val.ecdh.wrap_algo);
          cl->enc_val.ecdh.wrap_algo = xtrymalloc (n+1);
          if (!cl->enc_val.ecdh.wrap_algo)
            return gpg_error (GPG_ERR_ENOMEM);
          memcpy (cl->enc_val.ecdh.wrap_algo, s, n);
          cl->enc_val.ecdh.wrap_algo[n] = 0;
        }
      else if (namelen == 3 && !memcmp (name, "ukm", 3))
        {
          xfree (cl->enc_val.ecdh.ukm);
          cl->enc_val.ecdh.ukm = xtrymalloc (n);
          if (!cl->enc_val.ecdh.ukm)
            return gpg_error (GPG_ERR_ENOMEM);
          memcpy (cl->enc_val.ecdh.ukm, s, n);
          cl->enc_val.ecdh.ukmlen = n;
        }
      /* (We ignore all other parameter of the (key value) form.)  */

      s += n;
      if ( *s != ')')
        return gpg_error (GPG_ERR_UNKNOWN_SEXP); /* or invalid sexp */
      s++;
    }
  /* Expect two closing parenthesis.  */
  if (*s != ')')
    return gpg_error (digitp (s)? GPG_ERR_UNKNOWN_SEXP : GPG_ERR_INV_SEXP);
  s++;
  if ( *s != ')')
    return gpg_error (GPG_ERR_INV_SEXP);

  /* Check that we have all required data.  */
  if (!cl->enc_val.value)
    return gpg_error (GPG_ERR_INV_SEXP);
  if (ecdh && (!cl->enc_val.ecdh.e
               || !cl->enc_val.ecdh.elen
               || !cl->enc_val.ecdh.encr_algo
               || !cl->enc_val.ecdh.wrap_algo))
    return gpg_error (GPG_ERR_INV_SEXP);
  /* Run additional checks for GOST algorithms.  */
  if (cl->enc_val.algo && !strncmp (cl->enc_val.algo, "1.2.643", 7))
    {
      gpg_error_t err;

      if (cl->cert)
        {
          err = _ksba_check_key_usage_for_gost (cl->cert,
                                                KSBA_KEYUSAGE_KEY_ENCIPHERMENT);
          if (!err)
            err = check_policy_tk26 (cl->cert);
          if (err)
            return err;
        }
    }


  return 0;
}




/**
 * ksba_cms_add_recipient:
 * @cms: A CMS object
 * @cert: A certificate used to describe the recipient.
 *
 * This functions starts assembly of a new enveloped data content or adds
 * another recipient to the list of recipients.
 *
 * Note: after successful completion of this function ownership of
 * @cert is transferred to @cms.
 *
 * Return value: 0 on success or an error code.
 **/
gpg_error_t
ksba_cms_add_recipient (ksba_cms_t cms, ksba_cert_t cert)
{
  /* for now we use the same structure */
  return ksba_cms_add_signer (cms, cert);
}




/*
   Content handler for parsing messages
*/

static gpg_error_t
ct_parse_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static gpg_error_t
ct_parse_signed_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sGOT_HASH,
    sIN_DATA,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason = cms->stop_reason;
  gpg_error_t err = 0;

  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_NEED_HASH)
    {
      state = sGOT_HASH;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      if (!cms->hash_fnc)
        err = gpg_error (GPG_ERR_MISSING_ACTION);
      else
        state = sIN_DATA;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    {
      state = sGOT_HASH;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = _ksba_cms_parse_signed_data_part_1 (cms);
  else if (state == sGOT_HASH)
    err = _ksba_cms_parse_signed_data_part_2 (cms);
  else if (state == sIN_DATA)
    err = read_and_hash_cont (cms);
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      if (cms->detached_data)
        { /* We use this stop reason to inform the caller about a
             detached signatures.  Actually there is no need for him
             to hash the data now, he can do this also later. */
          stop_reason = KSBA_SR_NEED_HASH;
        }
      else
        { /* The user must now provide a hash function so that we can
             hash the data in the next round */
          stop_reason = KSBA_SR_BEGIN_DATA;
        }
    }
  else if (state == sIN_DATA)
    stop_reason = KSBA_SR_END_DATA;
  else if (state ==sGOT_HASH)
    stop_reason = KSBA_SR_READY;

  cms->stop_reason = stop_reason;
  return 0;
}


static gpg_error_t
ct_parse_enveloped_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sREST,
    sINDATA,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason = cms->stop_reason;
  gpg_error_t err = 0;

  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_DETACHED_DATA)
    {
      state = sREST;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      state = sINDATA;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    {
      state = sREST;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = _ksba_cms_parse_enveloped_data_part_1 (cms);
  else if (state == sREST)
    err = _ksba_cms_parse_enveloped_data_part_2 (cms);
  else if (state == sINDATA)
    err = read_encrypted_cont (cms);
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      stop_reason = cms->detached_data? KSBA_SR_DETACHED_DATA
                                      : KSBA_SR_BEGIN_DATA;
    }
  else if (state == sINDATA)
    stop_reason = KSBA_SR_END_DATA;
  else if (state ==sREST)
    stop_reason = KSBA_SR_READY;

  cms->stop_reason = stop_reason;
  return 0;
}


static gpg_error_t
ct_parse_digested_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static gpg_error_t
ct_parse_encrypted_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}



/*
   Content handlers for building messages
*/

static gpg_error_t
ct_build_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}



/* Write everything up to the encapsulated data content type. */
static gpg_error_t
build_signed_data_header (ksba_cms_t cms)
{
  gpg_error_t err;
  unsigned char *buf;
  const char *s;
  size_t len;
  int i;

  /* Write the outer contentInfo. */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->content.oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;

  /* The SEQUENCE */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;

  /* figure out the CMSVersion to be used */
  if (0 /* fixme: have_attribute_certificates
           || encapsulated_content != data
           || any_signer_info_is_version_3*/ )
    s = "\x03";
  else
    s = "\x01";
  err = _ksba_ber_write_tl (cms->writer, TYPE_INTEGER, CLASS_UNIVERSAL, 0, 1);
  if (err)
    return err;
  err = ksba_writer_write (cms->writer, s, 1);
  if (err)
    return err;

  /* SET OF DigestAlgorithmIdentifier */
  {
    unsigned char *value;
    size_t valuelen;
    ksba_writer_t tmpwrt;

    err = ksba_writer_new (&tmpwrt);
    if (err)
      return err;
    err = ksba_writer_set_mem (tmpwrt, 512);
    if (err)
      {
        ksba_writer_release (tmpwrt);
        return err;
      }

    for (i=0; (s = ksba_cms_get_digest_algo_list (cms, i)); i++)
      {
        int j;
        const char *s2;

        /* (make sure not to write duplicates) */
        for (j=0; j < i && (s2=ksba_cms_get_digest_algo_list (cms, j)); j++)
          {
            if (!strcmp (s, s2))
              break;
          }
        if (j == i)
          {
            err = _ksba_der_write_algorithm_identifier (tmpwrt, s, NULL, 0);
            if (err)
              {
                ksba_writer_release (tmpwrt);
                return err;
              }
          }
      }

    value = ksba_writer_snatch_mem (tmpwrt, &valuelen);
    ksba_writer_release (tmpwrt);
    if (!value)
      {
        err = gpg_error (GPG_ERR_ENOMEM);
        return err;
      }
    err = _ksba_ber_write_tl (cms->writer, TYPE_SET, CLASS_UNIVERSAL,
                              1, valuelen);
    if (!err)
      err = ksba_writer_write (cms->writer, value, valuelen);
    xfree (value);
    if (err)
      return err;
  }



  /* Write the (inner) encapsulatedContentInfo */
  /* if we have a detached signature we don't need to use undefinite
     length here - but it doesn't matter either */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->inner_cont_oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  if ( !cms->detached_data)
    { /* write the tag */
      err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
      if (err)
        return err;
    }

  return err;
}

/* Set the issuer/serial from the cert to the node.
   mode 0: sid
   mode 1: rid
 */
static gpg_error_t
set_issuer_serial (AsnNode info, ksba_cert_t cert, int mode)
{
  gpg_error_t err;
  AsnNode dst, src;

  if (!info || !cert)
    return gpg_error (GPG_ERR_INV_VALUE);

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.serialNumber");
  dst = _ksba_asn_find_node (info,
                             mode?
                             "rid.issuerAndSerialNumber.serialNumber":
                             "sid.issuerAndSerialNumber.serialNumber");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.issuer");
  dst = _ksba_asn_find_node (info,
                             mode?
                             "rid.issuerAndSerialNumber.issuer":
                             "sid.issuerAndSerialNumber.issuer");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;

  return 0;
}


/* Store the sequence of capabilities at NODE */
static gpg_error_t
store_smime_capability_sequence (AsnNode node,
                                 struct oidparmlist_s *capabilities)
{
  gpg_error_t err;
  struct oidparmlist_s *cap, *cap2;
  unsigned char *value;
  size_t valuelen;
  ksba_writer_t tmpwrt;

  err = ksba_writer_new (&tmpwrt);
  if (err)
    return err;
  err = ksba_writer_set_mem (tmpwrt, 512);
  if (err)
    {
      ksba_writer_release (tmpwrt);
      return err;
    }

  for (cap=capabilities; cap; cap = cap->next)
    {
      /* (avoid writing duplicates) */
      for (cap2=capabilities; cap2 != cap; cap2 = cap2->next)
        {
          if (!strcmp (cap->oid, cap2->oid)
              && cap->parmlen && cap->parmlen == cap2->parmlen
              && !memcmp (cap->parm, cap2->parm, cap->parmlen))
            break; /* Duplicate found. */
        }
      if (cap2 == cap)
        {
          /* RFC3851 requires that a missing parameter must not be
             encoded as NULL.  This is in contrast to all other usages
             of the algorithm identifier where ist is allowed and in
             some profiles (e.g. tmttv2) even explicitly suggested to
             use NULL.  */
          err = _ksba_der_write_algorithm_identifier
                 (tmpwrt, cap->oid,
                  cap->parmlen?cap->parm:(const void*)"", cap->parmlen);
          if (err)
            {
              ksba_writer_release (tmpwrt);
              return err;
            }
        }
    }

  value = ksba_writer_snatch_mem (tmpwrt, &valuelen);
  if (!value)
    err = gpg_error (GPG_ERR_ENOMEM);
  if (!err)
    err = _ksba_der_store_sequence (node, value, valuelen);
  xfree (value);
  ksba_writer_release (tmpwrt);
  return err;
}


/* An object used to construct the signed attributes. */
struct attrarray_s {
  AsnNode root;
  unsigned char *image;
  size_t imagelen;
};


/* Thank you ASN.1 committee for allowing us to employ a sort to make
   that DER encoding even more complicate. */
static int
compare_attrarray (const void *a_v, const void *b_v)
{
  const struct attrarray_s *a = a_v;
  const struct attrarray_s *b = b_v;
  const unsigned char *ap, *bp;
  size_t an, bn;

  ap = a->image;
  an = a->imagelen;
  bp = b->image;
  bn = b->imagelen;
  for (; an && bn; an--, bn--, ap++, bp++ )
    if (*ap != *bp)
      return *ap - *bp;

  return (an == bn)? 0 : (an > bn)? 1 : -1;
}




/* Write the END of data NULL tag and everything we can write before
   the user can calculate the signature */
static gpg_error_t
build_signed_data_attributes (ksba_cms_t cms)
{
  gpg_error_t err;
  int signer;
  ksba_asn_tree_t cms_tree = NULL;
  struct certlist_s *certlist;
  struct oidlist_s *digestlist;
  struct signer_info_s *si, **si_tail;
  AsnNode root = NULL;
  struct attrarray_s attrarray[4];
  int attridx = 0;
  int i;

  memset (attrarray, 0, sizeof (attrarray));

  /* Write the End tag */
  err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (err)
    return err;

  if (cms->signer_info)
    return gpg_error (GPG_ERR_CONFLICT); /* This list must be empty at
                                            this point. */

  /* Write optional certificates */
  if (cms->cert_info_list)
    {
      unsigned long totallen = 0;
      const unsigned char *der;
      size_t n;

      for (certlist = cms->cert_info_list; certlist; certlist = certlist->next)
        {
          if (!ksba_cert_get_image (certlist->cert, &n))
            return gpg_error (GPG_ERR_GENERAL); /* User passed an
                                                   unitialized cert */
          totallen += n;
        }

      err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, totallen);
      if (err)
        return err;

      for (certlist = cms->cert_info_list; certlist; certlist = certlist->next)
        {
          if (!(der=ksba_cert_get_image (certlist->cert, &n)))
            return gpg_error (GPG_ERR_BUG);
          err = ksba_writer_write (cms->writer, der, n);
          if (err )
            return err;
        }
    }

  /* If we ever support it, here is the right place to do it:
     Write the optional CRLs */

  /* Now we have to prepare the signer info.  For now we will just build the
     signedAttributes, so that the user can do the signature calculation */
  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err)
    return err;

  certlist = cms->cert_list;
  if (!certlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      goto leave;
    }
  digestlist = cms->digest_algos;
  if (!digestlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      goto leave;
    }

  si_tail = &cms->signer_info;
  for (signer=0; certlist;
       signer++, certlist = certlist->next, digestlist = digestlist->next)
    {
      AsnNode attr;
      AsnNode n;
      unsigned char *image;
      size_t imagelen;
      int is_gost;

      for (i = 0; i < attridx; i++)
        {
          _ksba_asn_release_nodes (attrarray[i].root);
          xfree (attrarray[i].image);
        }
      attridx = 0;
      memset (attrarray, 0, sizeof (attrarray));

      if (!digestlist)
        {
	  err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
	  goto leave;
	}

      if (!certlist->cert || !digestlist->oid)
        {
          err = gpg_error (GPG_ERR_BUG);
          goto leave;
        }

      is_gost = is_gost_oid (digestlist->oid);

      /* For GOST put content-type first.  */
      if (is_gost)
        {
          attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                        "CryptographicMessageSyntax.Attribute");
          if (!attr)
            { err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND); goto leave; }
          n = _ksba_asn_find_node (attr, "Attribute.attrType");
          if (!n)
            { err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND); goto leave; }
          err = _ksba_der_store_oid (n, oidstr_contentType);
          if (err)
            goto leave;
          n = _ksba_asn_find_node (attr, "Attribute.attrValues");
          if (!n || !n->down)
            { err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND); goto leave; }
          n = n->down;
          err = _ksba_der_store_oid (n, cms->inner_cont_oid);
          if (err)
            goto leave;
          err = _ksba_der_encode_tree (attr, &image, &imagelen);
          if (err)
            goto leave;
          attrarray[attridx].root = attr;
          attrarray[attridx].image = image;
          attrarray[attridx].imagelen = imagelen;
          attridx++;
        }


      /* Include the pretty important message digest. */
      attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.Attribute");
      if (!attr)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      n = _ksba_asn_find_node (attr, "Attribute.attrType");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_oid (n, oidstr_messageDigest);
      if (err)
        goto leave;
      n = _ksba_asn_find_node (attr, "Attribute.attrValues");
      if (!n || !n->down)
        return gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
      n = n->down; /* fixme: ugly hack */
      assert (certlist && certlist->msg_digest_len);
      err = _ksba_der_store_octet_string (n, certlist->msg_digest,
                                          certlist->msg_digest_len);
      if (err)
        goto leave;
      err = _ksba_der_encode_tree (attr, &image, &imagelen);
      if (err)
        goto leave;
      attrarray[attridx].root = attr;
      attrarray[attridx].image = image;
      attrarray[attridx].imagelen = imagelen;
      attridx++;

      if (!is_gost)
        {
          /* Include the content-type attribute. */
          attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                        "CryptographicMessageSyntax.Attribute");
          if (!attr)
            { err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND); goto leave; }
          n = _ksba_asn_find_node (attr, "Attribute.attrType");
          if (!n)
            { err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND); goto leave; }
          err = _ksba_der_store_oid (n, oidstr_contentType);
          if (err)
            goto leave;
          n = _ksba_asn_find_node (attr, "Attribute.attrValues");
          if (!n || !n->down)
            { err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND); goto leave; }
          n = n->down;
          err = _ksba_der_store_oid (n, cms->inner_cont_oid);
          if (err)
            goto leave;
          err = _ksba_der_encode_tree (attr, &image, &imagelen);
          if (err)
            goto leave;
          attrarray[attridx].root = attr;
          attrarray[attridx].image = image;
          attrarray[attridx].imagelen = imagelen;
          attridx++;
        }

      /* Include the signing time */
      if (*certlist->signing_time)
        {
          attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                     "CryptographicMessageSyntax.Attribute");
          if (!attr)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = _ksba_asn_find_node (attr, "Attribute.attrType");
          if (!n)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          err = _ksba_der_store_oid (n, oidstr_signingTime);
          if (err)
            goto leave;
          n = _ksba_asn_find_node (attr, "Attribute.attrValues");
          if (!n || !n->down)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = n->down; /* fixme: ugly hack */
          err = _ksba_der_store_time (n, certlist->signing_time);
          if (err)
            goto leave;
          err = _ksba_der_encode_tree (attr, &image, &imagelen);
          if (err)
            goto leave;
          /* We will use the attributes again - so save them */
          attrarray[attridx].root = attr;
          attrarray[attridx].image = image;
          attrarray[attridx].imagelen = imagelen;
          attridx++;
        }

      /* Include the S/MIME capabilities with the first signer. */
      if (cms->capability_list && !signer)
        {
          attr = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.Attribute");
          if (!attr)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = _ksba_asn_find_node (attr, "Attribute.attrType");
          if (!n)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          err = _ksba_der_store_oid (n, oidstr_smimeCapabilities);
          if (err)
            goto leave;
          n = _ksba_asn_find_node (attr, "Attribute.attrValues");
          if (!n || !n->down)
            {
	      err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	      goto leave;
	    }
          n = n->down; /* fixme: ugly hack */
          err = store_smime_capability_sequence (n, cms->capability_list);
          if (err)
            goto leave;
          err = _ksba_der_encode_tree (attr, &image, &imagelen);
          if (err)
            goto leave;
          attrarray[attridx].root = attr;
          attrarray[attridx].image = image;
          attrarray[attridx].imagelen = imagelen;
          attridx++;
        }

      /* Arggh.  That silly ASN.1 DER encoding rules: We need to sort
         the SET values unless building a GOST sequence.  */
      if (!is_gost)
        qsort (attrarray, attridx, sizeof (struct attrarray_s),
               compare_attrarray);

      /* Now copy them to an SignerInfo tree.  This tree is not
         complete but suitable for ksba_cms_hash_signed_attributes() */
      root = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.SignerInfo");
      n = _ksba_asn_find_node (root, "SignerInfo.signedAttrs");
      if (!n || !n->down)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      /* This is another ugly hack to move to the element we want */
      for (n = n->down->down; n && n->type != TYPE_SEQUENCE; n = n->right)
        ;
      if (!n)
        {
          err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
          goto leave;
        }

      if (is_gost)
        {
          AsnNode parent = find_up (n);
          if (parent)
            parent->type = TYPE_SEQUENCE;
        }

      assert (attridx <= DIM (attrarray));
      for (i=0; i < attridx; i++)
        {
          if (i)
            {
              if ( !(n=_ksba_asn_insert_copy (n)))
                {
		  err = gpg_error (GPG_ERR_ENOMEM);
		  goto leave;
		}
            }
          err = _ksba_der_copy_tree (n, attrarray[i].root, attrarray[i].image);
          if (err)
            goto leave;
	  _ksba_asn_release_nodes (attrarray[i].root);
	  free (attrarray[i].image);
	  attrarray[i].root = NULL;
	  attrarray[i].image = NULL;
        }

      err = _ksba_der_encode_tree (root, &image, NULL);
      if (err)
        goto leave;

      si = xtrycalloc (1, sizeof *si);
      if (!si)
        return gpg_error (GPG_ERR_ENOMEM);
      si->root = root;
      root = NULL;
      si->image = image;
      /* Hmmm, we don't set the length of the image. */
      *si_tail = si;
      si_tail = &si->next;
    }

 leave:
  _ksba_asn_release_nodes (root);
  ksba_asn_tree_release (cms_tree);
  for (i = 0; i < attridx; i++)
    {
      _ksba_asn_release_nodes (attrarray[i].root);
      xfree (attrarray[i].image);
    }

  return err;
}




/* The user has calculated the signatures and we can therefore write
   everything left over to do. */
static gpg_error_t
build_signed_data_rest (ksba_cms_t cms)
{
  gpg_error_t err;
  int signer;
  ksba_asn_tree_t cms_tree = NULL;
  struct certlist_s *certlist;
  struct oidlist_s *digestlist;
  struct signer_info_s *si;
  struct sig_val_s *sv;
  ksba_writer_t tmpwrt = NULL;
  AsnNode root = NULL;
  ksba_der_t dbld = NULL;

  /* Now we can really write the signer info */
  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err)
    return err;

  certlist = cms->cert_list;
  if (!certlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      return err;
    }

  /* To construct the set we use a temporary writer object. */
  err = ksba_writer_new (&tmpwrt);
  if (err)
    goto leave;
  err = ksba_writer_set_mem (tmpwrt, 2048);
  if (err)
    goto leave;

  digestlist = cms->digest_algos;
  si = cms->signer_info;
  sv = cms->sig_val;

  for (signer=0; certlist;
       signer++,
         certlist = certlist->next,
         digestlist = digestlist->next,
         si = si->next,
         sv = sv->next)
    {
      AsnNode n, n2;
      unsigned char *image;
      size_t imagelen;
      const char *oid;

      if (!digestlist || !si || !sv)
        {
	  err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
	  goto leave;
	}
      if (!certlist->cert || !digestlist->oid)
        {
	  err = gpg_error (GPG_ERR_BUG);
	  goto leave;
	}

      root = _ksba_asn_expand_tree (cms_tree->parse_tree,
                                    "CryptographicMessageSyntax.SignerInfo");

      /* We store a version of 1 because we use the issuerAndSerialNumber */
      n = _ksba_asn_find_node (root, "SignerInfo.version");
      if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_integer (n, "\x00\x00\x00\x01\x01");
      if (err)
        goto leave;

      /* Store the sid */
      n = _ksba_asn_find_node (root, "SignerInfo.sid");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}

      err = set_issuer_serial (n, certlist->cert, 0);
      if (err)
        goto leave;

      /* store the digestAlgorithm */
      n = _ksba_asn_find_node (root, "SignerInfo.digestAlgorithm.algorithm");
      if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_oid (n, digestlist->oid);
      if (err)
        goto leave;
      n = _ksba_asn_find_node (root, "SignerInfo.digestAlgorithm.parameters");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_null (n);
      if (err)
        goto leave;

      /* and the signed attributes */
      n = _ksba_asn_find_node (root, "SignerInfo.signedAttrs");
      if (!n || !n->down)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      assert (si->root);
      assert (si->image);
      n2 = _ksba_asn_find_node (si->root, "SignerInfo.signedAttrs");
      if (!n2 || !n2->down)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_copy_tree (n, n2, si->image);
      if (err)
        goto leave;
      image = NULL;

      /* store the signatureAlgorithm */
      n = _ksba_asn_find_node (root,
			       "SignerInfo.signatureAlgorithm.algorithm");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      if (!sv->algo)
        {
	  err = gpg_error (GPG_ERR_MISSING_VALUE);
	  goto leave;
	}

      if (!strcmp (sv->algo, "ecdsa"))
        {
          /* Look at the digest algorithm and replace accordingly.  */
          if (!strcmp (digestlist->oid, "2.16.840.1.101.3.4.2.1"))
            oid = "1.2.840.10045.4.3.2";  /* ecdsa-with-SHA256 */
          else if (!strcmp (digestlist->oid, "2.16.840.1.101.3.4.2.2"))
            oid = "1.2.840.10045.4.3.3";  /* ecdsa-with-SHA384 */
          else if (!strcmp (digestlist->oid, "2.16.840.1.101.3.4.2.3"))
            oid = "1.2.840.10045.4.3.4";  /* ecdsa-with-SHA512 */
          else
            {
              err = gpg_error (GPG_ERR_DIGEST_ALGO);
              goto leave;
            }
        }
      else
        oid = sv->algo;

      err = _ksba_der_store_oid (n, oid);
      if (err)
	goto leave;
      n = _ksba_asn_find_node (root,
			       "SignerInfo.signatureAlgorithm.parameters");
      if (!n)
        {
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}
      err = _ksba_der_store_null (n);
      if (err)
	goto leave;

      /* store the signature  */
      if (!sv->value)
        {
	  err = gpg_error (GPG_ERR_MISSING_VALUE);
	  goto leave;
	}
      n = _ksba_asn_find_node (root, "SignerInfo.signature");
      if (!n)
	{
	  err = gpg_error (GPG_ERR_ELEMENT_NOT_FOUND);
	  goto leave;
	}

      if (sv->ecc.r && is_gost_algo (sv->algo))
        {
          /* GOST signatures are stored as an OCTET STRING with
             little-endian S followed by R.  We build this format by
             first inverting R and S.  */
          unsigned char *rrev, *srev, *tmp;
          if (sv->ecc.rlen != sv->valuelen)
            {
              err = gpg_error (GPG_ERR_INV_VALUE);
              goto leave;
            }

          rrev = xtrymalloc (sv->ecc.rlen);
          srev = xtrymalloc (sv->valuelen);
          if (!rrev || !srev)
            {
              err = gpg_error_from_syserror ();
              xfree (rrev);
              xfree (srev);
              goto leave;
            }
          invert_bytes (rrev, sv->ecc.r, sv->ecc.rlen);
          invert_bytes (srev, sv->value, sv->valuelen);


          tmp = xtrymalloc (sv->valuelen + sv->ecc.rlen);
          if (!tmp)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          memcpy (tmp, srev, sv->valuelen);
          memcpy (tmp + sv->valuelen, rrev, sv->ecc.rlen);

          /* Build the canonical S-expression.  */
          {
            struct stringbuf sb;

            init_stringbuf (&sb, sv->valuelen + sv->ecc.rlen + 40);
            put_stringbuf (&sb, "(sig-val (gost (r ");
            put_stringbuf_mem_sexp (&sb, rrev, sv->ecc.rlen);
            put_stringbuf (&sb, ")(s ");
            put_stringbuf_mem_sexp (&sb, srev, sv->valuelen);
            put_stringbuf (&sb, ")))");
            xfree (get_stringbuf (&sb));
            deinit_stringbuf (&sb);
          }

          err = _ksba_der_store_octet_string (n, tmp,
                                             sv->valuelen + sv->ecc.rlen);
          xfree (tmp);
          xfree (rrev);
          xfree (srev);
          if (err)
            goto leave;
        }
      else if (sv->ecc.r)  /* ECDSA */
        {
          unsigned char *tmpder;
          size_t tmpderlen;

          _ksba_der_release (dbld);
          dbld = _ksba_der_builder_new (0);
          if (!dbld)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          _ksba_der_add_int (dbld, sv->ecc.r, sv->ecc.rlen, 1);
          _ksba_der_add_int (dbld, sv->value, sv->valuelen, 1);
          _ksba_der_add_end (dbld);

          err = _ksba_der_builder_get (dbld, &tmpder, &tmpderlen);
          if (err)
            goto leave;
          err = _ksba_der_store_octet_string (n, tmpder, tmpderlen);
          xfree (tmpder);
          if (err)
            goto leave;
        }
      else  /* RSA */
        {
          err = _ksba_der_store_octet_string (n, sv->value, sv->valuelen);
          if (err)
            goto leave;
        }

      /* Make the DER encoding and write it out. */
      err = _ksba_der_encode_tree (root, &image, &imagelen);
      if (err)
	goto leave;

      err = ksba_writer_write (tmpwrt, image, imagelen);
      xfree (image);
      if (err)
	goto leave;
    }

  /* Write out the SET filled with all signer infos */
  {
    unsigned char *value;
    size_t valuelen;

    value = ksba_writer_snatch_mem (tmpwrt, &valuelen);
    if (!value)
      {
        err = gpg_error (GPG_ERR_ENOMEM);
	goto leave;
      }
    err = _ksba_ber_write_tl (cms->writer, TYPE_SET, CLASS_UNIVERSAL,
                              1, valuelen);
    if (!err)
      err = ksba_writer_write (cms->writer, value, valuelen);
    xfree (value);
    if (err)
      goto leave;
  }

  /* Write 3 end tags */
  err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (!err)
    err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (!err)
    err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);

 leave:
  ksba_asn_tree_release (cms_tree);
  _ksba_asn_release_nodes (root);
  ksba_writer_release (tmpwrt);
  _ksba_der_release (dbld);
  return err;
}




static gpg_error_t
ct_build_signed_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sDATAREADY,
    sGOTSIG,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason;
  gpg_error_t err = 0;

  stop_reason = cms->stop_reason;
  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      /* fixme: check that the message digest has been set */
      state = sDATAREADY;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    state = sDATAREADY;
  else if (stop_reason == KSBA_SR_NEED_SIG)
    {
      if (!cms->sig_val)
        err = gpg_error (GPG_ERR_MISSING_ACTION); /* No ksba_cms_set_sig_val () called */
      state = sGOTSIG;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    {
      /* figure out whether a detached signature is requested */
      if (cms->cert_list && cms->cert_list->msg_digest_len)
        cms->detached_data = 1;
      else
        cms->detached_data = 0;
      /* and start encoding */
      err = build_signed_data_header (cms);
    }
  else if (state == sDATAREADY)
    {
      if (!cms->detached_data)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = build_signed_data_attributes (cms);
    }
  else if (state == sGOTSIG)
    err = build_signed_data_rest (cms);
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      /* user should write the data and calculate the hash or do
         nothing in case of END_DATA */
      stop_reason = cms->detached_data? KSBA_SR_END_DATA
                                      : KSBA_SR_BEGIN_DATA;
    }
  else if (state == sDATAREADY)
    stop_reason = KSBA_SR_NEED_SIG;
  else if (state == sGOTSIG)
    stop_reason = KSBA_SR_READY;

  cms->stop_reason = stop_reason;
  return 0;
}


/* write everything up to the encryptedContentInfo including the tag */
static gpg_error_t
build_enveloped_data_header (ksba_cms_t cms)
{
  gpg_error_t err;
  int recpno;
  struct certlist_s *certlist;
  unsigned char *buf;
  const char *s;
  size_t len;
  ksba_der_t dbld = NULL;
  int any_ecdh = 0;

  /* See whether we have any ECDH or GOST recipients requiring CMS v2.  */
  for (certlist = cms->cert_list; certlist; certlist = certlist->next)
    if (certlist->enc_val.ecdh.e
        || (certlist->enc_val.algo
            && !strncmp (certlist->enc_val.algo, "1.2.643", 7)))
     {
        any_ecdh = 1;
        break;
      }

  /* Write the outer contentInfo */
  /* fixme: code is shared with signed_data_header */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->content.oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;

  /* The SEQUENCE */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;

  /* figure out the CMSVersion to be used (from rfc2630):
     version is the syntax version number.  If originatorInfo is
     present, then version shall be 2.  If any of the RecipientInfo
     structures included have a version other than 0, then the version
     shall be 2.  If unprotectedAttrs is present, then version shall
     be 2.  If originatorInfo is absent, all of the RecipientInfo
     structures are version 0, and unprotectedAttrs is absent, then
     version shall be 0.

     For SPHINX the version number must be 0.
  */


  s = any_ecdh? "\x02" :"\x00";
  err = _ksba_ber_write_tl (cms->writer, TYPE_INTEGER, CLASS_UNIVERSAL, 0, 1);
  if (err)
    return err;
  err = ksba_writer_write (cms->writer, s, 1);
  if (err)
    return err;

  /* Note: originatorInfo is not yet implemented and must not be used
     for SPHINX */

  certlist = cms->cert_list;
  if (!certlist)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE); /* oops */
      goto leave;
    }


  dbld = _ksba_der_builder_new (0);
  if (!dbld)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  _ksba_der_add_tag (dbld, 0, TYPE_SET);
  for (recpno=0; certlist; recpno++, certlist = certlist->next)
    {
      const unsigned char *der;
      size_t derlen;

      if (!certlist->cert)
        {
          err = gpg_error (GPG_ERR_BUG);
          goto leave;
        }
      if (certlist->enc_val.algo &&
          !strncmp (certlist->enc_val.algo, "1.2.643", 7))
        {
          err = _ksba_check_key_usage_for_gost (certlist->cert,
                                                KSBA_KEYUSAGE_KEY_ENCIPHERMENT);
          if (!err)
            err = check_policy_tk26 (certlist->cert);
          if (err)
            goto leave;
        }
	    
      if (certlist->enc_val.ecdh.e
          || (certlist->enc_val.algo
              && !strcmp (certlist->enc_val.algo, "1.2.643.2.2.96")))
        { /* Build a KeyAgreeRecipientInfo (ECDH or GOST VKO).  */
          _ksba_der_add_tag (dbld, CLASS_CONTEXT, 1); /* kari */
          _ksba_der_add_ptr (dbld, 0, TYPE_INTEGER, "\x03", 1);

          _ksba_der_add_tag (dbld, CLASS_CONTEXT, 0); /* originator */
          _ksba_der_add_tag (dbld, CLASS_CONTEXT, 1); /* originatorKey */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* algorithm */
          _ksba_der_add_oid (dbld, certlist->enc_val.algo);
          _ksba_der_add_end (dbld);
          if (certlist->enc_val.ecdh.e)
            _ksba_der_add_bts (dbld, certlist->enc_val.ecdh.e,
                               certlist->enc_val.ecdh.elen, 0);
          else
            {
              const unsigned char *pubkey;
              size_t publen;

              err = _ksba_cert_get_public_key_ptr (certlist->cert,
                                                   &pubkey, &publen);
              if (err)
                goto leave;
              _ksba_der_add_bts (dbld, pubkey, publen, 0);
            }
          _ksba_der_add_end (dbld); /* end originatorKey */
          _ksba_der_add_end (dbld); /* end originator */

          if (certlist->enc_val.ecdh.ukm && certlist->enc_val.ecdh.ukmlen)
            {
              _ksba_der_add_tag (dbld, CLASS_CONTEXT, 1); /* ukm */
              _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING,
                                 certlist->enc_val.ecdh.ukm,
                                 certlist->enc_val.ecdh.ukmlen);
            }

          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* keyEncrAlgo */
          _ksba_der_add_oid (dbld, certlist->enc_val.ecdh.encr_algo);
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          _ksba_der_add_oid (dbld, certlist->enc_val.ecdh.wrap_algo);
          _ksba_der_add_end (dbld);
          _ksba_der_add_end (dbld); /* end keyEncrAlgo */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* recpEncrKeys */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* recpEncrKey */

          if (certlist->enc_val.algo && !strncmp (certlist->enc_val.algo,"1.2.643",7))
            {
              unsigned char *ski; size_t skilen;
              err = get_subject_key_id (certlist->cert, &ski, &skilen);
              if (err)
                goto leave;
              _ksba_der_add_tag (dbld, CLASS_CONTEXT, 0); /* rKeyId */
              _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
              _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING, ski, skilen);
              _ksba_der_add_end (dbld);
              _ksba_der_add_end (dbld); /* rKeyId */
              xfree (ski);
            }
          else
            {
              _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
              err = _ksba_cert_get_issuer_dn_ptr (certlist->cert, &der, &derlen);
              if (err)
                goto leave;
              _ksba_der_add_der (dbld, der, derlen);
              err = _ksba_cert_get_serial_ptr (certlist->cert, &der, &derlen);
              if (err)
                goto leave;
              _ksba_der_add_der (dbld, der, derlen);
              _ksba_der_add_end (dbld);
            }

          if (!certlist->enc_val.value)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              goto leave;
            }
          _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING,
                             certlist->enc_val.value,
                             certlist->enc_val.valuelen);

          _ksba_der_add_end (dbld); /* end recpEncrKey */
          _ksba_der_add_end (dbld); /* end recpEncrKeys */
        }
      else if (certlist->enc_val.algo
               && !strncmp (certlist->enc_val.algo, "1.2.643", 7)
               && strcmp (certlist->enc_val.algo, "1.2.643.2.2.96")) /* KEK */
        {
          unsigned char *ski; size_t skilen;
          _ksba_der_add_tag (dbld, CLASS_CONTEXT, 2); /* kekri */
          _ksba_der_add_ptr (dbld, 0, TYPE_INTEGER, "\x04", 1);

          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* kekid */
          err = get_subject_key_id (certlist->cert, &ski, &skilen);
          if (err)
            goto leave;
          _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING, ski, skilen);
          _ksba_der_add_end (dbld);
          xfree (ski);

          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE); /* keyEncryptionAlgorithm */
          _ksba_der_add_oid (dbld, certlist->enc_val.algo);
          _ksba_der_add_ptr (dbld, 0, TYPE_NULL, NULL, 0);
          _ksba_der_add_end (dbld);

          if (!certlist->enc_val.value)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              goto leave;
            }
          _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING,
                             certlist->enc_val.value,
                             certlist->enc_val.valuelen);
        }
      else /* RSA (ktri) */
       {
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          /* We store a version of 0 because we are only allowed to
           * use the issuerAndSerialNumber for SPHINX */
          _ksba_der_add_ptr (dbld, 0, TYPE_INTEGER, "", 1);
          /* rid.issuerAndSerialNumber */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          /* rid.issuerAndSerialNumber.issuer */
          err = _ksba_cert_get_issuer_dn_ptr (certlist->cert, &der, &derlen);
          if (err)
            goto leave;
          _ksba_der_add_der (dbld, der, derlen);
          /* rid.issuerAndSerialNumber.serialNumber */
          err = _ksba_cert_get_serial_ptr (certlist->cert, &der, &derlen);
          if (err)
            goto leave;
          _ksba_der_add_der (dbld, der, derlen);
          _ksba_der_add_end (dbld);

          /* Store the keyEncryptionAlgorithm */
          _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
          if (!certlist->enc_val.algo || !certlist->enc_val.value)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              goto leave;
            }
          _ksba_der_add_oid (dbld, certlist->enc_val.algo);
          /* Now store NULL for the optional parameters.  From Peter
           * Gutmann's X.509 style guide:
           *
           *   Another pitfall to be aware of is that algorithms which
           *   have no parameters have this specified as a NULL value
           *   rather than omitting the parameters field entirely.  The
           *   reason for this is that when the 1988 syntax for
           *   AlgorithmIdentifier was translated into the 1997 syntax,
           *   the OPTIONAL associated with the AlgorithmIdentifier
           *   parameters got lost.  Later it was recovered via a defect
           *   report, but by then everyone thought that algorithm
           *   parameters were mandatory.  Because of this the algorithm
           *   parameters should be specified as NULL, regardless of what
           *   you read elsewhere.
           *
           *        The trouble is that things *never* get better, they just
           *        stay the same, only more so
           *            -- Terry Pratchett, "Eric"
           *
           * Although this is about signing, we always do it.  Versions of
           * Libksba before 1.0.6 had a bug writing out the NULL tag here,
           * thus in reality we used to be correct according to the
           * standards despite we didn't intended so.
           */
          _ksba_der_add_ptr (dbld, 0, TYPE_NULL, NULL, 0);
          _ksba_der_add_end (dbld);

          /* Store the encryptedKey  */
          if (!certlist->enc_val.value)
            {
              err = gpg_error (GPG_ERR_MISSING_VALUE);
              goto leave;
            }
          _ksba_der_add_ptr (dbld, 0, TYPE_OCTET_STRING,
                             certlist->enc_val.value,
                             certlist->enc_val.valuelen);

        }
      _ksba_der_add_end (dbld); /* End SEQUENCE (ktri or kari) */
    }
  _ksba_der_add_end (dbld);  /* End SET */

  /* Write out the SET filled with all recipient infos */
  {
    unsigned char *image;
    size_t imagelen;

    err = _ksba_der_builder_get (dbld, &image, &imagelen);
    if (err)
      goto leave;
    err = ksba_writer_write (cms->writer, image, imagelen);
    xfree (image);
    if (err)
      goto leave;
  }

  /* Write the (inner) encryptedContentInfo */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->inner_cont_oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  /* and the encryptionAlgorithm */
  err = _ksba_der_write_algorithm_identifier (cms->writer,
                                              cms->encr_algo_oid,
                                              cms->encr_iv,
                                              cms->encr_ivlen);
  if (err)
    return err;

  /* write the tag for the encrypted data, it is an implicit octect
     string in constructed form and indefinite length */
  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;

  /* Now the encrypted data should be written */

 leave:
  _ksba_der_release (dbld);
  return err;
}


static gpg_error_t
ct_build_enveloped_data (ksba_cms_t cms)
{
  enum {
    sSTART,
    sINDATA,
    sREST,
    sERROR
  } state = sERROR;
  ksba_stop_reason_t stop_reason;
  gpg_error_t err = 0;

  stop_reason = cms->stop_reason;
  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    state = sSTART;
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    state = sINDATA;
  else if (stop_reason == KSBA_SR_END_DATA)
    state = sREST;
  else if (stop_reason == KSBA_SR_RUNNING)
    err = gpg_error (GPG_ERR_INV_STATE);
  else if (stop_reason)
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = build_enveloped_data_header (cms);
  else if (state == sINDATA)
    err = write_encrypted_cont (cms);
  else if (state == sREST)
    {
      /* SPHINX does not allow for unprotectedAttributes */

      /* Write 5 end tags */
      err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
      if (!err)
        err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
    }
  else
    err = gpg_error (GPG_ERR_INV_STATE);

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    { /* user should now write the encrypted data */
      stop_reason = KSBA_SR_BEGIN_DATA;
    }
  else if (state == sINDATA)
    { /* tell the user that we wrote everything */
      stop_reason = KSBA_SR_END_DATA;
    }
  else if (state == sREST)
    {
      stop_reason = KSBA_SR_READY;
    }

  cms->stop_reason = stop_reason;
  return 0;
}


static gpg_error_t
ct_build_digested_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static gpg_error_t
ct_build_encrypted_data (ksba_cms_t cms)
{
  (void)cms;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}
