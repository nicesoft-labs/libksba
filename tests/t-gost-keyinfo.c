#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/ksba.h"
#define KSBA_TESTING
#define _KSBA_VISIBILITY_DEFAULT
#include "../src/keyinfo.h"
#include "t-common.h"

int
main(int argc, char **argv)
{
  gpg_error_t err;
  ksba_der_t d;
  ksba_sexp_t sexp = NULL;
  unsigned char *der = NULL, *der2 = NULL;
  size_t derlen = 0, derlen2 = 0;
  unsigned char q[64];

  (void)argc; (void)argv;

  for (int i = 0; i < 64; i++)
    q[i] = i + 1;

  d = ksba_der_builder_new(0);
  assert(d);

  ksba_der_add_tag(d, KSBA_CLASS_UNIVERSAL, KSBA_TYPE_SEQUENCE);
  ksba_der_add_tag(d, KSBA_CLASS_UNIVERSAL, KSBA_TYPE_SEQUENCE);    /* AlgId */
  ksba_der_add_oid(d, "1.2.643.7.1.1.1.1");
  ksba_der_add_tag(d, KSBA_CLASS_UNIVERSAL, KSBA_TYPE_SEQUENCE);    /* Params */
  ksba_der_add_oid(d, "1.2.643.7.1.2.1.2");
  ksba_der_add_oid(d, "1.2.643.7.1.1.2.2");
  ksba_der_add_end(d);  /* Params */
  ksba_der_add_end(d);  /* AlgId */
  unsigned char inner[1 + sizeof q];
  inner[0] = 0x04; /* Uncompressed point prefix */
  memcpy(inner + 1, q, sizeof q);
  ksba_der_add_bts(d, inner, sizeof inner, 0);
  ksba_der_add_end(d);  /* outer */

  err = ksba_der_builder_get(d, &der, &derlen);
  fail_if_err(err);
  assert(der && derlen);

  fprintf(stderr, "DER (%zu bytes): ", derlen);
  for (size_t i = 0; i < derlen; i++)
    fprintf(stderr, "%02X", der[i]);
  fprintf(stderr, "\n");

  err = _ksba_keyinfo_to_sexp(der, derlen, &sexp);
  fail_if_err(err);
  assert(sexp);

  fprintf(stderr, "SEXP: ");
  print_sexp(sexp);
  fprintf(stderr, "\n");

  assert(strstr((char*)sexp, "public-key"));
  assert(strstr((char*)sexp, "gost"));
  assert(strstr((char*)sexp, "curve"));
  assert(strstr((char*)sexp, "1.2.643.7.1.2.1.2"));
  assert(strstr((char*)sexp, "q"));

  err = _ksba_keyinfo_from_sexp(sexp, 0, &der2, &derlen2);
  fail_if_err(err);

  fprintf(stderr, "DER2 (%zu bytes): ", derlen2);
  for (size_t i = 0; i < derlen2; i++)
    fprintf(stderr, "%02X", der2[i]);
  fprintf(stderr, "\n");

  assert(derlen == derlen2);
  assert(!memcmp(der, der2, derlen));

  ksba_der_release(d);
  xfree(der);
  xfree(der2);
  xfree(sexp);
  return 0;
}
