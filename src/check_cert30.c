#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <gcrypt.h>
#include <ksba.h>

/* Макрос для проверки ошибок */
#define CHECK_ERR(err, msg) do { \
    if (err) { \
        fprintf(stderr, "[ERROR] %s: %s (%d)\n", msg, gpg_strerror(err), err); \
        return err; \
    } \
} while (0)

/* Функция для печати бинарных данных в hex */
static void print_hex(const char *prefix, const unsigned char *data, size_t len) {
    fprintf(stderr, "%s (%zu bytes): ", prefix, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02X", data[i]);
    }
    fprintf(stderr, "\n");
}

/* Функция для печати S-выражения */
static void show_sexp(const char *prefix, gcry_sexp_t a) {
    char *buf;
    size_t size;

    fprintf(stderr, "%s", prefix);
    size = gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = gcry_xmalloc(size);
    gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, buf, size);
    fprintf(stderr, "%.*s", (int)size, buf);
    gcry_free(buf);
}

/* Функция для инверсии массива байтов */
static void invert_bytes(unsigned char *dest, const unsigned char *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dest[i] = src[len - 1 - i];
    }
}

/* Функция проверки подписи сертификата */
static gpg_error_t check_cert_sig(ksba_cert_t issuer_cert, ksba_cert_t cert) {
    gpg_error_t err;
    const char *algoid;
    gcry_md_hd_t md;
    int algo, gost_key;
    ksba_sexp_t p;
    size_t n;
    char algo_name[17];
    int digestlen;
    unsigned char *digest = NULL;
    gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
    unsigned char digest_orig[32], digest_inv[32];
    unsigned char r_orig[32], s_orig[32], r_inv[32], s_inv[32];

    fprintf(stderr, "=== Begin signature verification ===\n");

    /* Получаем алгоритм хэширования из сертификата */
    algoid = ksba_cert_get_digest_algo(cert);
    fprintf(stderr, "[DEBUG] Digest OID: %s\n", algoid ? algoid : "NULL");
    algo = gcry_md_map_name(algoid);
    if (!algo) {
        fprintf(stderr, "[ERROR] Unknown hash algorithm: %s\n", algoid ? algoid : "NULL");
        return gpg_error(GPG_ERR_INV_VALUE);
    }
    fprintf(stderr, "[DEBUG] Mapped hash algorithm: %s (ID: %d)\n", gcry_md_algo_name(algo), algo);

    /* Определяем, используется ли ГОСТ */
    gost_key = !memcmp(algoid, "1.2.643", 7);
    fprintf(stderr, "[DEBUG] Is GOST key: %d\n", gost_key);

    /* Преобразуем имя алгоритма в нижний регистр */
    const char *s = gcry_md_algo_name(algo);
    for (int i = 0; *s && i < sizeof(algo_name) - 1; s++, i++) {
        algo_name[i] = tolower(*s);
    }
    algo_name[s - gcry_md_algo_name(algo)] = 0;
    fprintf(stderr, "[DEBUG] Hash algorithm name (lowercase): %s\n", algo_name);

    /* Инициализируем хэш */
    err = gcry_md_open(&md, algo, 0);
    CHECK_ERR(err, "gcry_md_open failed");
    fprintf(stderr, "[DEBUG] Hash context initialized\n");

    /* Вычисляем хэш сертификата */
    err = ksba_cert_hash(cert, 1, (void (*)(void *, const void *, size_t))gcry_md_write, md);
    CHECK_ERR(err, "ksba_cert_hash failed");
    gcry_md_final(md);
    digestlen = gcry_md_get_algo_dlen(algo);
    fprintf(stderr, "[DEBUG] Digest length: %d bytes\n", digestlen);
    digest = gcry_md_read(md, algo);
    memcpy(digest_orig, digest, digestlen);
    print_hex("[DEBUG] Raw digest", digest_orig, digestlen);

    /* Пропускаем инверсию хэша для ГОСТ */
    fprintf(stderr, "[DEBUG] Skipping hash inversion for GOST\n");
    print_hex("[DEBUG] Digest (unchanged)", digest_orig, digestlen);

    /* Также сохраняем инвертированный хэш для теста */
    if (gost_key) {
        invert_bytes(digest_inv, digest_orig, digestlen);
        print_hex("[DEBUG] Digest (inverted for testing)", digest_inv, digestlen);
    }

    /* Пробуем разные варианты хэша */
    unsigned char *hash_variants[] = { digest_orig, digest_inv };
    const char *hash_names[] = { "original", "inverted" };
    int hash_variant_count = gost_key ? 2 : 1;

    /* Извлекаем подпись из сертификата */
    p = ksba_cert_get_sig_val(cert);
    n = gcry_sexp_canon_len(p, 0, NULL, NULL);
    fprintf(stderr, "[DEBUG] Signature S-expression length: %zu bytes\n", n);
    print_hex("[DEBUG] Raw signature S-expression", p, n);
    if (!n) {
        fprintf(stderr, "[ERROR] Invalid signature S-expression\n");
        ksba_free(p);
        gcry_md_close(md);
        return gpg_error(GPG_ERR_INV_SEXP);
    }
    err = gcry_sexp_sscan(&s_sig, NULL, p, n);
    ksba_free(p);
    CHECK_ERR(err, "gcry_sexp_sscan for s_sig failed");
    show_sexp("[DEBUG] Original s_sig S-expression:\n", s_sig);

    /* Извлекаем r и s */
    gcry_sexp_t r_sexp = gcry_sexp_find_token(s_sig, "r", 0);
    gcry_sexp_t s_sexp = gcry_sexp_find_token(s_sig, "s", 0);
    if (!r_sexp || !s_sexp) {
        fprintf(stderr, "[ERROR] Cannot find r or s in signature S-expression\n");
        gcry_sexp_release(s_sig);
        gcry_md_close(md);
        return gpg_error(GPG_ERR_INV_SEXP);
    }
    const char *r_data = gcry_sexp_nth_data(r_sexp, 1, &n);
    const char *s_data = gcry_sexp_nth_data(s_sexp, 1, &n);
    if (n != 32) {
        fprintf(stderr, "[ERROR] Invalid r or s length: %zu\n", n);
        gcry_sexp_release(r_sexp);
        gcry_sexp_release(s_sexp);
        gcry_sexp_release(s_sig);
        gcry_md_close(md);
        return gpg_error(GPG_ERR_INV_SEXP);
    }
    memcpy(r_orig, r_data, 32);
    memcpy(s_orig, s_data, 32);
    print_hex("[DEBUG] Original r", r_orig, 32);
    print_hex("[DEBUG] Original s", s_orig, 32);

    /* Формируем инвертированные r и s */
    invert_bytes(r_inv, r_orig, 32);
    invert_bytes(s_inv, s_orig, 32);
    print_hex("[DEBUG] Inverted r", r_inv, 32);
    print_hex("[DEBUG] Inverted s", s_inv, 32);

    gcry_sexp_release(r_sexp);
    gcry_sexp_release(s_sexp);

    /* Извлекаем открытый ключ */
    p = ksba_cert_get_public_key(issuer_cert);
    n = gcry_sexp_canon_len(p, 0, NULL, NULL);
    fprintf(stderr, "[DEBUG] Public key S-expression length: %zu bytes\n", n);
    print_hex("[DEBUG] Raw public key S-expression", p, n);
    if (!n) {
        fprintf(stderr, "[ERROR] Invalid public key S-expression\n");
        ksba_free(p);
        gcry_md_close(md);
        gcry_sexp_release(s_sig);
        return gpg_error(GPG_ERR_INV_SEXP);
    }
    err = gcry_sexp_sscan(&s_pkey, NULL, p, n);
    ksba_free(p);
    CHECK_ERR(err, "gcry_sexp_sscan for s_pkey failed");
    show_sexp("[DEBUG] s_pkey S-expression:\n", s_pkey);

    /* Пробуем разные варианты подписи и хэша */
    const char *sig_formats[] = {
        "(sig-val (gost (r %b) (s %b)) (hash gostr3411_94))",
        "(sig-val (gost (r %b) (s %b)))",
        "(sig-val (gost (s %b) (r %b)) (hash gostr3411_94))",
        "(sig-val (gost (s %b) (r %b)))"
    };
    const char *sig_names[] = {
        "original with hash",
        "original without hash",
        "swapped s-r with hash",
        "swapped s-r without hash"
    };
    unsigned char *sig_r_variants[] = { r_orig, r_inv, r_orig, r_inv };
    unsigned char *sig_s_variants[] = { s_orig, s_inv, s_orig, s_inv };
    int sig_variant_count = gost_key ? 4 : 1;

    for (int i = 0; i < hash_variant_count; i++) {
        fprintf(stderr, "\n[INFO] Testing hash variant: %s\n", hash_names[i]);
        gcry_sexp_release(s_hash);
        err = gcry_sexp_build(&s_hash, NULL, "(data (flags gost) (value %b))", digestlen, hash_variants[i]);
        CHECK_ERR(err, "gcry_sexp_build for s_hash failed");
        show_sexp("[DEBUG] s_hash S-expression:\n", s_hash);

        for (int j = 0; j < sig_variant_count; j++) {
            fprintf(stderr, "[INFO] Testing signature variant: %s\n", sig_names[j]);
            gcry_sexp_release(s_sig);
            err = gcry_sexp_build(&s_sig, NULL, sig_formats[j], 32, sig_r_variants[j], 32, sig_s_variants[j]);
            CHECK_ERR(err, "gcry_sexp_build for s_sig failed");
            show_sexp("[DEBUG] s_sig S-expression:\n", s_sig);

            fprintf(stderr, "[DEBUG] Calling gcry_pk_verify...\n");
            err = gcry_pk_verify(s_sig, s_hash, s_pkey);
            if (!err) {
                fprintf(stderr, "[INFO] Verification succeeded with hash=%s, sig=%s\n",
                        hash_names[i], sig_names[j]);
                gcry_sexp_release(s_sig);
                gcry_sexp_release(s_hash);
                gcry_sexp_release(s_pkey);
                gcry_md_close(md);
                return 0;
            }
            fprintf(stderr, "[ERROR] gcry_pk_verify failed: %s (%d)\n", gpg_strerror(err), err);
        }
    }

    /* Освобождаем ресурсы */
    gcry_sexp_release(s_sig);
    gcry_sexp_release(s_hash);
    gcry_sexp_release(s_pkey);
    gcry_md_close(md);
    fprintf(stderr, "=== End signature verification ===\n");
    return gpg_error(GPG_ERR_BAD_SIGNATURE);
}

int main(int argc, char *argv[]) {
    gpg_error_t err;
    FILE *fp, *fp_ca;
    ksba_reader_t r, r_ca;
    ksba_cert_t cert, cert_ca;
    unsigned char *sub_dn;

    /* Проверка версии libgcrypt и поддержка ГОСТ */
    fprintf(stderr, "[INFO] libgcrypt version: %s\n", gcry_check_version(NULL));
    fprintf(stderr, "[INFO] Checking libgcrypt GOST support:\n");
    gcry_control(GCRYCTL_PRINT_CONFIG, stderr);
    fprintf(stderr, "[INFO] libksba version: %s\n", ksba_check_version(NULL));

    /* Проверка аргументов */
    if (argc != 3) {
        fprintf(stderr, "[ERROR] Usage: %s <user_cert> <ca_cert>\n", argv[0]);
        exit(1);
    }
    fprintf(stderr, "[INFO] Verifying certificate: %s with CA: %s\n", argv[1], argv[2]);

    /* Читаем пользовательский сертификат */
    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot open user certificate: %s\n", argv[1]);
        exit(1);
    }
    err = ksba_reader_new(&r);
    CHECK_ERR(err, "ksba_reader_new for user cert failed");
    err = ksba_reader_set_file(r, fp);
    CHECK_ERR(err, "ksba_reader_set_file for user cert failed");
    err = ksba_cert_new(&cert);
    CHECK_ERR(err, "ksba_cert_new for user cert failed");
    err = ksba_cert_read_der(cert, r);
    CHECK_ERR(err, "ksba_cert_read_der for user cert failed");
    fclose(fp);
    ksba_reader_release(r);
    fprintf(stderr, "[DEBUG] User certificate loaded successfully\n");

    /* Читаем корневой сертификат */
    fp_ca = fopen(argv[2], "rb");
    if (!fp_ca) {
        fprintf(stderr, "[ERROR] Cannot open CA certificate: %s\n", argv[2]);
        ksba_cert_release(cert);
        exit(1);
    }
    err = ksba_reader_new(&r_ca);
    CHECK_ERR(err, "ksba_reader_new for CA cert failed");
    err = ksba_reader_set_file(r_ca, fp_ca);
    CHECK_ERR(err, "ksba_reader_set_file for CA cert failed");
    err = ksba_cert_new(&cert_ca);
    CHECK_ERR(err, "ksba_cert_new for CA cert failed");
    err = ksba_cert_read_der(cert_ca, r_ca);
    CHECK_ERR(err, "ksba_cert_read_der for CA cert failed");
    fclose(fp_ca);
    ksba_reader_release(r_ca);
    fprintf(stderr, "[DEBUG] CA certificate loaded successfully\n");

    /* Выводим информацию о сертификате */
    sub_dn = ksba_cert_get_subject(cert, 0);
    fprintf(stderr, "[INFO] Subject DN: %s\n", sub_dn ? (char *)sub_dn : "NULL");
    ksba_free(sub_dn);

    /* Проверяем подпись */
    err = check_cert_sig(cert_ca, cert);
    if (err) {
        fprintf(stderr, "[ERROR] Certificate verification failed: %s\n", argv[1]);
    } else {
        fprintf(stderr, "[INFO] Certificate verification succeeded: %s\n", argv[1]);
    }

    /* Освобождаем ресурсы */
    ksba_cert_release(cert);
    ksba_cert_release(cert_ca);
    return err ? 1 : 0;
}
