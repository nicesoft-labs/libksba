#include <config.h>
#include <ctype.h>
#include <string.h>
#include <gcrypt.h>

#include "util.h"
#include "convert.h"
#include "keyinfo.h"
#include "cert.h"
#include "ksba.h"
#include <assert.h>
#include "ber-help.h"

#define HASH_FNC ((void (*)(void *, const void *, size_t))gcry_md_write)

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
  if (!rbuf || !sbuf || !rlen || rlen != slen)
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

/* Wrapper to check keyUsage for GOST certificates.  */
static gpg_error_t
check_key_usage_for_gost (const ksba_cert_t cert, unsigned usage_flag)
{
  return _ksba_check_key_usage_for_gost (cert, usage_flag);
}

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

  {
    char *line = pols;
    while (line && *line)
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
  }
  return ok? 0 : gpg_error (GPG_ERR_NO_POLICY_MATCH);
}

/* Check that CERT has only TK-26 policies (1.2.643.*) and at least one
   such policy is present.  */
static gpg_error_t
check_policy_tk26_only (ksba_cert_t cert)
{
  gpg_error_t err;
  char *pols = NULL;
  int any = 0;

  err = ksba_cert_get_cert_policies (cert, &pols);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    return gpg_error (GPG_ERR_NO_POLICY_MATCH);
  if (err)
    return err;

  {
    char *line = pols;
    while (line && *line)
      {
        char *end = strchr (line, '\n');
        if (!end)
          end = line + strlen (line);
        if (end - line >= 7 && !memcmp (line, "1.2.643", 7))
          any = 1;
        else if (end - line == 13 && !memcmp (line, "2.5.29.32.0", 11))
          {
            /* Ignore anyPolicy.  */
          }
        else
          {
            xfree (pols);
            return gpg_error (GPG_ERR_NO_POLICY_MATCH);
          }
        if (*end)
          line = end + 1;
        else
          break;
      }
  }
  xfree (pols);

  return any? 0 : gpg_error (GPG_ERR_NO_POLICY_MATCH);
}

/* Parse the value of a certificatePolicies extension and check that
   only TK-26 policies (OID prefix 1.2.643) are used and that at least
   one such policy exists.  */
static gpg_error_t
parse_policies_tk26_only (const unsigned char *der, size_t derlen)
{
  gpg_error_t err;
  struct tag_info ti;
  size_t seqlen;
  int any = 0;

  err = _ksba_ber_parse_tl (&der, &derlen, &ti);
  if (err)
    return err;
  if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE && ti.is_constructed))
    return gpg_error (GPG_ERR_INV_OBJ);
  if (ti.ndef)
    return gpg_error (GPG_ERR_NOT_DER_ENCODED);
  if (ti.length > derlen)
    return gpg_error (GPG_ERR_BAD_BER);
  seqlen = ti.length;

  while (seqlen)
    {
      size_t innerlen;

      err = _ksba_ber_parse_tl (&der, &derlen, &ti);
      if (err)
        return err;
      if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE && ti.is_constructed))
        return gpg_error (GPG_ERR_INV_OBJ);
      if (ti.ndef)
        return gpg_error (GPG_ERR_NOT_DER_ENCODED);
      if (ti.length > derlen || ti.nhdr + ti.length > seqlen)
        return gpg_error (GPG_ERR_BAD_BER);
      seqlen -= ti.nhdr + ti.length;
      innerlen = ti.length;

      err = _ksba_ber_parse_tl (&der, &derlen, &ti);
      if (err)
        return err;
      if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OBJECT_ID))
        return gpg_error (GPG_ERR_INV_OBJ);
      if (ti.length > derlen || ti.nhdr + ti.length > innerlen)
        return gpg_error (GPG_ERR_BAD_BER);
      {
        char *oid = ksba_oid_to_str (der, ti.length);
        if (!oid)
          return gpg_error (GPG_ERR_ENOMEM);
        if (!strncmp (oid, "1.2.643", 7))
          any = 1;
        else if (!strcmp (oid, "2.5.29.32.0"))
          {
            /* Ignore anyPolicy.  */
          }
        else
          {
            xfree (oid);
            return gpg_error (GPG_ERR_NO_POLICY_MATCH);
          }
        xfree (oid);
      }
      der += ti.length;
      derlen -= ti.length;
      if (innerlen < ti.nhdr + ti.length)
        return gpg_error (GPG_ERR_BAD_BER);
      der += innerlen - (ti.nhdr + ti.length);
      derlen -= innerlen - (ti.nhdr + ti.length);
    }

  return any? 0 : gpg_error (GPG_ERR_NO_POLICY_MATCH);
}

/* Parse the value of an extendedKeyUsage extension and make sure that
   at least one of the supported OIDs for GOST keys is present.  */
static gpg_error_t
parse_eku_for_gost (const unsigned char *der, size_t derlen)
{
  gpg_error_t err;
  struct tag_info ti;
  size_t seqlen;
  int ok = 0;

  err = _ksba_ber_parse_tl (&der, &derlen, &ti);
  if (err)
    return err;
  if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE && ti.is_constructed))
    return gpg_error (GPG_ERR_INV_OBJ);
  if (ti.ndef)
    return gpg_error (GPG_ERR_NOT_DER_ENCODED);
  if (ti.length > derlen)
    return gpg_error (GPG_ERR_BAD_BER);
  seqlen = ti.length;

  while (seqlen)
    {
      err = _ksba_ber_parse_tl (&der, &derlen, &ti);
      if (err)
        return err;
      if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OBJECT_ID))
        return gpg_error (GPG_ERR_INV_OBJ);
      if (ti.ndef)
        return gpg_error (GPG_ERR_NOT_DER_ENCODED);
      if (ti.length > derlen || ti.nhdr + ti.length > seqlen)
        return gpg_error (GPG_ERR_BAD_BER);
      {
        char *oid = ksba_oid_to_str (der, ti.length);
        if (!oid)
          return gpg_error (GPG_ERR_ENOMEM);
        if (!strcmp (oid, "1.3.6.1.5.5.7.3.3")
            || !strcmp (oid, "1.3.6.1.5.5.7.3.9")
            || !strcmp (oid, "2.5.29.31"))
          ok = 1;
        xfree (oid);
      }
      der += ti.length;
      derlen -= ti.length;
      seqlen -= ti.nhdr + ti.length;
    }

  return ok? 0 : gpg_error (GPG_ERR_WRONG_KEY_USAGE);
}

/* Parse the value of a keyUsage extension and verify that either the
   digitalSignature or the keyEncipherment bit is set.  Returns the
   usage flags in R_USAGE on success.  */
static gpg_error_t
parse_key_usage_for_gost (const unsigned char *der, size_t derlen,
                          unsigned int *r_usage)
{
  gpg_error_t err;
  struct tag_info ti;
  unsigned int flags = 0;
  int unused, full, mask, i;
  unsigned char bits;

  if (r_usage)
    *r_usage = 0;

  err = _ksba_ber_parse_tl (&der, &derlen, &ti);
  if (err)
    return err;
  if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_BIT_STRING
        && !ti.is_constructed))
    return gpg_error (GPG_ERR_INV_OBJ);
  if (ti.ndef)
    return gpg_error (GPG_ERR_NOT_DER_ENCODED);
  if (!ti.length || ti.length > derlen)
    return gpg_error (GPG_ERR_BAD_BER);

  unused = *der++;
  derlen--; ti.length--;
  if ((!ti.length && unused) || unused/8 > ti.length)
    return gpg_error (GPG_ERR_BAD_BER);

  full = ti.length - (unused + 7)/8;
  mask = 0;
  for (i = 1; unused; i <<= 1, unused--)
    mask |= i;

  if (ti.length)
    {
      bits = *der++; derlen--; ti.length--;
      if (full)
        full--;
      else
        {
          bits &= ~mask;
          mask = 0;
        }
      if (bits & 0x80)
        flags |= KSBA_KEYUSAGE_DIGITAL_SIGNATURE;
      if (bits & 0x40)
        flags |= KSBA_KEYUSAGE_NON_REPUDIATION;
      if (bits & 0x20)
        flags |= KSBA_KEYUSAGE_KEY_ENCIPHERMENT;
      if (bits & 0x10)
        flags |= KSBA_KEYUSAGE_DATA_ENCIPHERMENT;
      if (bits & 0x08)
        flags |= KSBA_KEYUSAGE_KEY_AGREEMENT;
      if (bits & 0x04)
        flags |= KSBA_KEYUSAGE_KEY_CERT_SIGN;
      if (bits & 0x02)
        flags |= KSBA_KEYUSAGE_CRL_SIGN;
      if (bits & 0x01)
        flags |= KSBA_KEYUSAGE_ENCIPHER_ONLY;
    }

  if (ti.length)
    {
      bits = *der++; derlen--; ti.length--;
      if (full)
        full--;
      else
        {
          bits &= mask;
          mask = ~0;
        }
      if (bits & 0x80)
        flags |= KSBA_KEYUSAGE_DECIPHER_ONLY;
    }

  if (r_usage)
    *r_usage = flags;

  if (!(flags & (KSBA_KEYUSAGE_DIGITAL_SIGNATURE|KSBA_KEYUSAGE_KEY_ENCIPHERMENT)))
    return gpg_error (GPG_ERR_WRONG_KEY_USAGE);

  return 0;
}


struct hash_collect_state
{
  unsigned char *buffer;
  size_t length;
  size_t allocated;
};

static void
collect_hash_bytes (void *opaque, const void *buf, size_t buflen)
{
  struct hash_collect_state *st = opaque;

  if (st->length + buflen > st->allocated)
    {
      size_t n = st->allocated? st->allocated*2:8192;
      while (n < st->length + buflen)
        n *= 2;
      st->buffer = xtryrealloc (st->buffer, n);
      if (!st->buffer)
        {
          st->length = st->allocated = 0;
          return;
        }
      st->allocated = n;
    }
  memcpy (st->buffer + st->length, buf, buflen);
  st->length += buflen;
}


/* Verify CERT using ISSUER_CERT.  */
gpg_error_t
_ksba_check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert)
{
  gpg_error_t err;
  const char *algoid;
  gcry_md_hd_t md;
  int algo, i;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  ksba_sexp_t pkey_str = NULL, sig_str = NULL;
  size_t sexp_len;
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

  if (gost_key)
    {
      err = check_key_usage_for_gost (cert,
                                      KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
      if (err)
        return err;

      /* TK-26: validate issuer certificate when a GOST signature is
         used for certificate signing.  */
      {
        unsigned int ku = 0;
        gpg_error_t e2 = ksba_cert_get_key_usage (issuer_cert, &ku);
        if (gpg_err_code (e2) != GPG_ERR_NO_DATA)
          {
            if (e2)
              return e2;
            if (!(ku & KSBA_KEYUSAGE_KEY_CERT_SIGN))
              return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
          }

        e2 = check_policy_tk26 (issuer_cert);
        if (e2)
          return e2;
      }
    }

  s = gcry_md_algo_name (algo);
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

  p = ksba_cert_get_public_key (issuer_cert);
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
  if (err && gost_key)
    {
      gcry_sexp_t tmp = s_sig;
      gpg_error_t e2;

      e2 = gost_adjust_signature (&tmp);
      if (!e2)
        {
          s_sig = tmp;
          err = gcry_pk_verify (s_sig, s_hash, s_pkey);
        }
      else
        {
          gcry_sexp_release (tmp);
          err = e2;
        }
    }

  gcry_md_close (md);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return err;
}

/* Verify CRL CRL using ISSUER_CERT for GOST signatures.  */
gpg_error_t
_ksba_crl_check_signature_gost (ksba_crl_t crl, ksba_cert_t issuer_cert)
{
  gpg_error_t err = 0;
  struct hash_collect_state hstate = { NULL, 0, 0 };
  ksba_stop_reason_t stop = 0;
  const char *algoid;
  int algo, i;
  gcry_md_hd_t md;
  ksba_sexp_t p;
  size_t n;
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  const char *s;
  char algo_name[17];
  int digestlen;
  unsigned char *digest;

  if (!crl || !issuer_cert)
    return gpg_error (GPG_ERR_INV_VALUE);

  ksba_crl_set_hash_function (crl, collect_hash_bytes, &hstate);
  do
    {
      err = ksba_crl_parse (crl, &stop);
    }
  while (!err && stop != KSBA_SR_READY);
  ksba_crl_set_hash_function (crl, NULL, NULL);
  if (err)
    goto leave;

  algoid = ksba_crl_get_digest_algo (crl);
  if (!algoid || strncmp (algoid, "1.2.643", 7))
    { err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO); goto leave; }

  err = _ksba_check_key_usage_for_gost (issuer_cert, KSBA_KEYUSAGE_CRL_SIGN);
  if (!err)
    /* TK-26: ensure CRL issuer keys follow the profile policy.  */
    err = check_policy_tk26 (issuer_cert);
  if (err)
    goto leave;

  algo = gcry_md_map_name (algoid);
  if (!algo)
    { err = gpg_error (GPG_ERR_DIGEST_ALGO); goto leave; }

  err = gcry_md_open (&md, algo, 0);
  if (err)
    goto leave;
  gcry_md_write (md, hstate.buffer, hstate.length);
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
    { gcry_md_close (md); goto leave; }

  p = ksba_crl_get_sig_val (crl);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    { err = gpg_error (GPG_ERR_INV_SEXP); gcry_md_close (md); ksba_free (p); goto leave; }
  err = gcry_sexp_sscan (&s_sig, NULL, p, n);
  ksba_free (p);
  if (err)
    { gcry_md_close (md); goto leave; }

  p = ksba_cert_get_public_key (issuer_cert);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    { err = gpg_error (GPG_ERR_INV_SEXP); gcry_md_close (md); ksba_free (p); goto leave; }
  err = gcry_sexp_sscan (&s_pkey, NULL, p, n);
  ksba_free (p);
  if (err)
    { gcry_md_close (md); goto leave; }

  err = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (err)
    {
      gcry_sexp_t tmp = s_sig;
      gpg_error_t e2;

      e2 = gost_adjust_signature (&tmp);
      if (!e2)
      {
          s_sig = tmp;
          err = gcry_pk_verify (s_sig, s_hash, s_pkey);
        }
      else
        {
          gcry_sexp_release (tmp);
          err = e2;
        }
    }

  gcry_md_close (md);

leave:
  xfree (hstate.buffer);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return err;
}


/* Verify a certificate chain for GOST according to TK-26.  CHAIN must
   contain CHAINLEN certificates starting with the root or an issuer
   certificate and ending with the end-entity certificate.  If
   CHECK_ENC is true the end-entity certificate is also required to
   allow encryption.  */
gpg_error_t
_ksba_check_cert_chain_tk26 (const ksba_cert_t *chain, size_t chainlen,
                             int check_enc)
{
  gpg_error_t err;
  ksba_isotime_t now, t1;

  if (!chain || !chainlen)
    return gpg_error (GPG_ERR_INV_VALUE);

  _ksba_current_time (now);

  {
    size_t i;
    for (i = 0; i < chainlen; i++)
    {
      ksba_cert_t cert = chain[i];

      /* Check validity period.  */
      if (!ksba_cert_get_validity (cert, 0, t1) && *t1
          && _ksba_cmp_time (now, t1) < 0)
        return gpg_error (GPG_ERR_CERT_TOO_YOUNG);
      if (!ksba_cert_get_validity (cert, 1, t1) && *t1
          && _ksba_cmp_time (now, t1) > 0)
        return gpg_error (GPG_ERR_CERT_EXPIRED);

      /* Check policy.  */
      err = check_policy_tk26_only (cert);
      if (err)
        return err;

      /* Check algorithm.  */
      if (strncmp (ksba_cert_get_digest_algo (cert), "1.2.643", 7))
        return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

      /* Key Usage checks depending on level.  */
      if (i == chainlen - 1)
        {
          err = check_key_usage_for_gost (cert, KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
          if (!err && check_enc)
            err = check_key_usage_for_gost (cert, KSBA_KEYUSAGE_KEY_ENCIPHERMENT);
        }
      else if (i == 0)
        err = check_key_usage_for_gost (cert, KSBA_KEYUSAGE_KEY_CERT_SIGN);
      else
        {
          err = check_key_usage_for_gost (cert, KSBA_KEYUSAGE_CRL_SIGN);
          if (!err)
            err = check_key_usage_for_gost (cert, KSBA_KEYUSAGE_DIGITAL_SIGNATURE);
        }
      if (err)
        return err;
    }
  }
  /* Verify the signature chain.  */
  {
    size_t i;
    for (i = 1; i < chainlen; i++)
      {
        err = _ksba_check_cert_sig (chain[i-1], chain[i]);
        if (err)
          return err;
      }
  }

  return 0;
}

/* Minimal parser to validate GOST PKCS#10 requests.  */
gpg_error_t
_ksba_pkcs10_check_gost (const unsigned char *der, size_t derlen)
{
  gpg_error_t err;
  struct tag_info ti;
  const unsigned char *ptr = der;
  size_t len = derlen;
  char *oid = NULL;
  const unsigned char *cri;
  size_t cri_len;
  const unsigned char *spki;
  size_t spki_len;
  const unsigned char *cri_start;
  size_t cri_tlen;
  gcry_md_hd_t md;
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  int algo, digestlen, gost_key, i;
  unsigned char *digest;
  char algo_name[17];
  size_t nread;
  ksba_sexp_t pkey_str = NULL, sig_str = NULL;
  size_t sexp_len;
  unsigned int ku_flags = 0;
  const unsigned char *attrs;
  size_t attrs_len;
  int have_policy = 0;
  int have_eku = 0;
  const unsigned char *set_ptr = NULL, *ext_ptr = NULL;
  const unsigned char *extensions = NULL, *e_ptr = NULL;
  size_t set_len = 0, ext_len = 0, extensions_len = 0, e_len = 0;
  int crit = 0;
  

  if (!der || !derlen)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = parse_sequence (&ptr, &len, &ti);
  if (err)
    return err;
  if (ti.ndef || ti.length > len)
    return gpg_error (GPG_ERR_BAD_BER);
  len = ti.length;

  err = parse_sequence (&ptr, &len, &ti); /* CertificationRequestInfo */
  if (err)
    return err;
  if (ti.ndef || ti.length > len)
    return gpg_error (GPG_ERR_BAD_BER);
  cri_start = ptr - ti.nhdr;
  cri_tlen  = ti.nhdr + ti.length;
  cri = ptr;
  cri_len = ti.length;
  ptr += cri_len;
  len -= cri_len;

  /* version */
  err = parse_integer (&cri, &cri_len, &ti);
  if (err)
    return err;
  parse_skip (&cri, &cri_len, &ti);

  /* subject */
  err = parse_sequence (&cri, &cri_len, &ti);
  if (err)
    return err;
  if (ti.length > cri_len)
    return gpg_error (GPG_ERR_BAD_BER);
  parse_skip (&cri, &cri_len, &ti);

  /* subjectPublicKeyInfo */
  err = parse_sequence (&cri, &cri_len, &ti);
  if (err)
    return err;
  if (ti.length > cri_len)
    return gpg_error (GPG_ERR_BAD_BER);
  spki = cri;
  spki_len = ti.length;
  cri += spki_len;
  cri_len -= spki_len;

  err = _ksba_parse_algorithm_identifier (spki, spki_len, NULL, &oid);
  if (err)
    return err;
  if (strncmp (oid, "1.2.643", 7))
    {
      xfree (oid);
      return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
    }
  xfree (oid);
  oid = NULL;

  /* signatureAlgorithm */
  err = _ksba_parse_algorithm_identifier (ptr, len, NULL, &oid);
  if (err)
    return err;
  if (strncmp (oid, "1.2.643", 7))
    {
      xfree (oid);
      return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
    }
  xfree (oid);
  oid = NULL;

  /* Extensions are stored as attributes.  Parse them for TK-26 policy
     and Extended Key Usage checks.  */
  err = parse_context_tag (&cri, &cri_len, &ti, 0);
  if (gpg_err_code (err) == GPG_ERR_FALSE || gpg_err_code (err) == GPG_ERR_INV_OBJ)
    return gpg_error (GPG_ERR_NO_POLICY_MATCH);
  if (err)
    return err;
  if (ti.length > cri_len)
    return gpg_error (GPG_ERR_BAD_BER);

  attrs = cri;
  attrs_len = ti.length;

  while (attrs_len)
    {
      const unsigned char *attr_ptr;
      size_t attr_len;

      err = parse_sequence (&attrs, &attrs_len, &ti);
      if (err)
        return err;
      if (ti.length > attrs_len)
        return gpg_error (GPG_ERR_BAD_BER);
      attr_ptr = attrs;
      attr_len = ti.length;
      attrs += attr_len;
      attrs_len -= attr_len;

      err = parse_object_id_into_str (&attr_ptr, &attr_len, &oid);
      if (err)
        return err;

      err = _ksba_ber_parse_tl (&attr_ptr, &attr_len, &ti);
      if (err)
        {
          xfree (oid);
          return err;
        }
      if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SET && ti.is_constructed))
        {
          xfree (oid);
          return gpg_error (GPG_ERR_INV_OBJ);
        }
      if (ti.ndef || ti.length > attr_len)
        {
          xfree (oid);
          return gpg_error (GPG_ERR_BAD_BER);
        }
      set_ptr = attr_ptr;
      set_len = ti.length;

      if (!strcmp (oid, "1.2.840.113549.1.9.14"))
        {
          /* extensionRequest */
          ext_ptr = set_ptr;
          ext_len = set_len;

          err = parse_sequence (&ext_ptr, &ext_len, &ti);
          if (err)
            {
              xfree (oid);
              return err;
            }
          if (ti.length > ext_len)
            {
              xfree (oid);
              return gpg_error (GPG_ERR_BAD_BER);
            }
          extensions = ext_ptr;
          extensions_len = ti.length;

          while (extensions_len)
            {
              /* Parse one extension.  */

              err = parse_sequence (&extensions, &extensions_len, &ti);
              if (err)
                {
                  xfree (oid);
                  return err;
                }
              if (ti.length > extensions_len)
                {
                  xfree (oid);
                  return gpg_error (GPG_ERR_BAD_BER);
                }
              e_ptr = extensions;
              e_len = ti.length;
              extensions += e_len;
              extensions_len -= e_len;

              err = parse_object_id_into_str (&e_ptr, &e_len, &oid);
              if (err)
                return err;
              crit = 0;
              err = parse_optional_boolean (&e_ptr, &e_len, &crit);
              if (err)
                {
                  xfree (oid);
                  return err;
                }
              err = parse_octet_string (&e_ptr, &e_len, &ti);
              if (err)
                {
                  xfree (oid);
                  return err;
                }
              if (ti.length > e_len)
                {
                  xfree (oid);
                  return gpg_error (GPG_ERR_BAD_BER);
                }
              if (!strcmp (oid, "2.5.29.32"))
                {
                  have_policy = 1;
                  err = parse_policies_tk26_only (e_ptr, ti.length);
                  xfree (oid);
                  if (err)
                    return err;
                }
              else if (!strcmp (oid, "2.5.29.37"))
                {
                  have_eku = 1;
                  err = parse_eku_for_gost (e_ptr, ti.length);
                  xfree (oid);
                  if (err)
                    return err;
                }
              else if (!strcmp (oid, "2.5.29.15"))
                {
                  err = parse_key_usage_for_gost (e_ptr, ti.length, &ku_flags);
                  xfree (oid);
                  if (err)
                    return err;
                }
              else
                {
                  xfree (oid);
                  return gpg_error (GPG_ERR_INV_OBJ);
                }
            }
        }
      else
        {
          xfree (oid);
          return gpg_error (GPG_ERR_INV_OBJ);
        }
    }

  if (!have_policy)
    return gpg_error (GPG_ERR_NO_POLICY_MATCH);
  if (!have_eku)
    return gpg_error (GPG_ERR_WRONG_KEY_USAGE); 
  if (!ku_flags)
    return gpg_error (GPG_ERR_WRONG_KEY_USAGE);

  /* Verify the signature over CertificationRequestInfo.  */
  err = _ksba_keyinfo_to_sexp (spki, spki_len, &pkey_str);
  if (err)
    goto leave;
  sexp_len = gcry_sexp_canon_len (pkey_str, 0, NULL, NULL);
  if (!sexp_len)
    { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }
  err = gcry_sexp_sscan (&s_pkey, NULL, pkey_str, sexp_len);
  xfree (pkey_str); pkey_str = NULL;
  if (err)
    goto leave;

  err = _ksba_parse_algorithm_identifier (ptr, len, &nread, &oid);
  if (err)
    goto leave;
  algo = gcry_md_map_name (oid);
  if (!algo)
    { err = gpg_error (GPG_ERR_DIGEST_ALGO); goto leave; }
  gost_key = !strncmp (oid, "1.2.643", 7);

  err = _ksba_sigval_to_sexp (ptr, len, &sig_str);
  if (err)
    goto leave;
  sexp_len = gcry_sexp_canon_len (sig_str, 0, NULL, NULL);
  if (!sexp_len)
    { err = gpg_error (GPG_ERR_INV_SEXP); goto leave; }
  err = gcry_sexp_sscan (&s_sig, NULL, sig_str, sexp_len);
  xfree (sig_str); sig_str = NULL;
  if (err)
    goto leave;

  err = gcry_md_open (&md, algo, 0);
  if (err)
    goto leave;
  gcry_md_write (md, cri_start, cri_tlen);
  gcry_md_final (md);
  digestlen = gcry_md_get_algo_dlen (algo);
  digest = gcry_md_read (md, algo);
  if (gost_key)
    {
      unsigned char *h = digest;
      unsigned char c;
      int len_xy;
      unsigned short arch = 1;
      len_xy = *((unsigned char *)&arch) == 0 ? 0 : digestlen;
      for (i=0; i < (len_xy/2); i++)
        {
          c = h[i];
          h[i] = h[len_xy - i - 1];
          h[len_xy - i - 1] = c;
        }
    }
  {
    const char *s = gcry_md_algo_name (algo);
    for (i=0; *s && i < (int)sizeof algo_name - 1; s++, i++)
      algo_name[i] = tolower (*s);
    algo_name[i] = 0;
  }

  if (!gost_key)
    err = gcry_sexp_build (&s_hash, NULL,
                           "(data(flags pkcs1)(hash %s %b))",
                           algo_name, digestlen, digest);
  else
    err = gcry_sexp_build (&s_hash, NULL,
                           "(data(flags gost)(value %b))",
                           digestlen, digest);
  if (err)
    {
      gcry_md_close (md);
      goto leave;
    }

  err = gcry_pk_verify (s_sig, s_hash, s_pkey);
  if (err && gost_key)
    {
      gcry_sexp_t tmp = s_sig;
      gpg_error_t e2;

      e2 = gost_adjust_signature (&tmp);
      if (!e2)
        {
          s_sig = tmp;
          err = gcry_pk_verify (s_sig, s_hash, s_pkey);
        }
      else
        {
          gcry_sexp_release (tmp);
          err = e2;
        }
    }

  gcry_md_close (md);

leave:
  xfree (oid);
  xfree (pkey_str);
  xfree (sig_str);
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  if (err)
    return err;  
  return 0;
}
