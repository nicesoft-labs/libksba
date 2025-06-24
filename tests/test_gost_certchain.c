#include <stdio.h>
#include <gcrypt.h>
#include "../src/ksba.h"
#include "t-common.h"

/*
 * Проверки test_gost_certchain.c
 * 1. Успешная проверка цепочки ГОСТ.
 * 2. Проверка с требованием шифрования -> ошибка keyUsage.
 * 3. Цепочка с неверным алгоритмом -> ошибка.
 */

static ksba_cert_t
read_cert (const char *fname)
{
  ksba_reader_t r; ksba_cert_t c; FILE *fp; gpg_error_t err;
  fp = fopen (fname, "rb"); if (!fp) fail ("open cert");
  err = ksba_reader_new (&r); fail_if_err (err);
  err = ksba_reader_set_file (r, fp); fail_if_err (err);
  err = ksba_cert_new (&c); fail_if_err (err);
  err = ksba_cert_read_der (c, r); fail_if_err (err);
  fclose (fp); ksba_reader_release (r);
  return c;
}

int main(void)
{
  ksba_cert_t chain[2];
  gpg_error_t err;

  chain[0] = read_cert ("samples/ca_gost.der");
  chain[1] = read_cert ("samples/user_gost.der");

  err = ksba_check_cert_chain_tk26 (chain, 2, 0);
  fail_if_err (err);
  ksba_cert_release (chain[0]);
  ksba_cert_release (chain[1]);

  chain[0] = read_cert ("samples/ca_gost.der");
  chain[1] = read_cert ("samples/user_gost.der");
  err = ksba_check_cert_chain_tk26 (chain, 2, 1);
  if (gpg_err_code (err) != GPG_ERR_WRONG_KEY_USAGE)
    fail ("expected WRONG_KEY_USAGE");
  ksba_cert_release (chain[0]);
  ksba_cert_release (chain[1]);

  chain[0] = read_cert ("samples/authority.crt");
  chain[1] = read_cert ("samples/user_gost.der");
  err = ksba_check_cert_chain_tk26 (chain, 2, 0);
  if (!err)
    fail ("expected failure for wrong algo");
  ksba_cert_release (chain[0]);
  ksba_cert_release (chain[1]);

  return 0;
}
