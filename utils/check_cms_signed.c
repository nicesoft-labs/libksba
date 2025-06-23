#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <ksba.h>
#include <gcrypt.h>

#define BUFFER_SIZE 1024
#define HASH_FNC ((void (*)(void *, const void *, size_t))gcry_md_write)

// Макросы для ошибок и очистки
#define HANDLE_ERROR(msg, ...) do { \
    fprintf(stderr, "Ошибка: " msg, ##__VA_ARGS__); \
    return GPG_ERR_GENERAL; \
} while (0)
#define SAFE_FREE(ptr) do { if (ptr) { gcry_free((void *)ptr); ptr = NULL; } } while (0)
#define SAFE_RELEASE_SEXP(ptr) do { if (ptr) { ksba_free((void *)ptr); ptr = NULL; } } while (0)

// Заглушка для хэширования атрибутов (сигнатура: const void*)
static void dummy_hash_fnc(void *arg, const void *data, size_t length) {
    (void)arg; (void)data; (void)length;
}

// Пустой писатель для libksba
static int dummy_writer_cb(void *cb_value, const void *buffer, size_t count) {
    (void)cb_value; (void)buffer; (void)count;
    return 0;
}

// Вывести ISO-время
static void dump_isotime(const ksba_isotime_t t) {
    if (!t || !*t) {
        fputs("[none]", stderr);
    } else {
        fprintf(stderr, "%.4s-%.2s-%.2s %.2s:%.2s:%s",
                t, t+4, t+6, t+9, t+11, t+13);
    }
}

// Показать S-выражение
static void show_sexp(const char *prefix, gcry_sexp_t a) {
    if (!a) return;
    if (prefix) fputs(prefix, stderr);
    size_t size = gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char *buf = gcry_xmalloc(size);
    if (!buf) {
        fprintf(stderr, "Ошибка аллока буфера S-выражения\n");
        return;
    }
    gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, buf, size);
    fprintf(stderr, "%.*s", (int)size, buf);
    SAFE_FREE(buf);
}

// Хэш-функция для файлов
static unsigned char *compute_file_digest(const char *oid, const char *filename, int *digest_len) {
    gcry_md_hd_t hd;
    int algo = gcry_md_map_name(oid);
    if (algo == GCRY_MD_NONE) {
        fprintf(stderr, "Неподдерживаемый алгоритм: %s\n", oid);
        return NULL;
    }
    if (gcry_md_open(&hd, algo, 0)) {
        fprintf(stderr, "gcry_md_open failed\n");
        return NULL;
    }
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        gcry_md_close(hd);
        fprintf(stderr, "Не открыть файл: %s\n", filename);
        return NULL;
    }
    unsigned char buf[BUFFER_SIZE];
    size_t n;
    while ((n = fread(buf,1,BUFFER_SIZE,fp))>0) {
        gcry_md_write(hd, buf, n);
    }
    fclose(fp);
    unsigned char *h = gcry_md_read(hd, 0);
    *digest_len = gcry_md_get_algo_dlen(algo);
    unsigned char *out = gcry_xmalloc(*digest_len);
    memcpy(out, h, *digest_len);
    gcry_md_close(hd);
    return out;
}

// Основная обработка CMS
static gcry_error_t process_file(const char *sig_file,
                                 const char *content_file,
                                 const char *cert_file) {
    gcry_error_t err = 0;
    FILE *fp = NULL;
    ksba_reader_t reader = NULL;
    ksba_writer_t writer = NULL;
    ksba_cms_t cms = NULL;
    gcry_md_hd_t data_md = NULL;
    gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL, s_num = NULL;
    unsigned char *subject_dn = NULL, *issuer_dn = NULL;
    ksba_cert_t cert = NULL;
    ksba_sexp_t serial = NULL;
    ksba_isotime_t sigtime = {0};

    fprintf(stderr, "\n*** Проверка подписи '%s' ***\n", sig_file);
    fp = fopen(sig_file, "rb");
    if (!fp) {
        fprintf(stderr, "Не открыть '%s'\n", sig_file);
        return GPG_ERR_GENERAL;
    }

    if ((err = ksba_reader_new(&reader)))            return err;
    if ((err = ksba_reader_set_file(reader, fp)))    return err;
    if ((err = ksba_writer_new(&writer)))            return err;
    if ((err = ksba_writer_set_cb(writer, dummy_writer_cb, NULL))) return err;
    if ((err = ksba_cms_new(&cms)))                  return err;
    if ((err = ksba_cms_set_reader_writer(cms, reader, writer))) return err;
    if ((err = gcry_md_open(&data_md, 0, 0)))         return err;

    // Первичная инициализация парсера
    ksba_stop_reason_t stopreason;
    if ((err = ksba_cms_parse(cms, &stopreason))) {
        HANDLE_ERROR("Ошибка предразбора CMS\n");
    }

    // Ставим заглушку хэша атрибутов
    ksba_cms_set_hash_function(cms, dummy_hash_fnc, NULL);

    // Догоняем до готовности
    while (stopreason != KSBA_SR_READY) {
        if ((err = ksba_cms_parse(cms, &stopreason))) {
            HANDLE_ERROR("Ошибка разбора CMS\n");
        }
    }

    // Извлекаем первый сертификат и публи́чный ключ
    if ((cert = ksba_cms_get_cert(cms, 0))) {
        size_t der_len = 0;
        const unsigned char *der = ksba_cert_get_image(cert, &der_len);
        int fd = open(cert_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);
        if (fd < 0) {
            ksba_cert_release(cert);
            HANDLE_ERROR("Не открыть файл для сертификата\n");
        }
        if (write(fd, der, der_len) != (ssize_t)der_len) {
            close(fd);
            ksba_cert_release(cert);
            HANDLE_ERROR("Ошибка записи сертификата\n");
        }
        close(fd);

        // subject DN
        subject_dn = (unsigned char *)ksba_cert_get_subject(cert, 0);
        // загрузка публ. ключа
        ksba_sexp_t p = ksba_cert_get_public_key(cert);
        ksba_cert_release(cert);

        size_t p_len = gcry_sexp_canon_len((const unsigned char*)p,0,NULL,NULL);
        if (!p_len)           HANDLE_ERROR("Неправильный S-Exp публичного ключа\n");
        if ((err = gcry_sexp_sscan(&s_pkey, NULL, (const char*)p, p_len)))
            HANDLE_ERROR("Ошибка разбора публичного ключа\n");
        SAFE_RELEASE_SEXP(p);
    }

    // Получаем issuer/serial
    if ((err = ksba_cms_get_issuer_serial(cms, 0, (char**)&issuer_dn, &serial)))
        HANDLE_ERROR("Не получить issuer/serial\n");

    // Определяем алгоритм хэша атрибутов
    const char *algoid = ksba_cms_get_digest_algo(cms, 0);
    int algo = gcry_md_map_name(algoid);
    int is_gost = !strncmp(algoid, "1.2.643", 7);

    gcry_md_enable(data_md, algo);
    // Ставим реальную хэш-функцию на data_md
    ksba_cms_set_hash_function(cms, HASH_FNC, data_md);
    if ((err = ksba_cms_hash_signed_attrs(cms, 0)))
        HANDLE_ERROR("Не удалось хэшировать атрибуты\n");

    gcry_md_final(data_md);
    unsigned char *digest = gcry_md_read(data_md, algo);
    int digest_len = gcry_md_get_algo_dlen(algo);

    if (is_gost) {
        // инверсия для GOST
        for (int i = 0; i < digest_len/2; i++) {
            unsigned char t = digest[i];
            digest[i] = digest[digest_len-1-i];
            digest[digest_len-1-i] = t;
        }
        if ((err = gcry_sexp_build(&s_hash, NULL, "(data(flags gost)(value %b))",
                                  digest_len, digest)))
            HANDLE_ERROR("Ошибка создания S-Exp GOST-хэша\n");
    } else {
        if ((err = gcry_sexp_build(&s_hash, NULL, "(data(flags pkcs1)(hash %s %b))",
                                  algoid, digest_len, digest)))
            HANDLE_ERROR("Ошибка создания S-Exp PKCS#1-хэша\n");
    }

    // Подпись времени
    if ((err = ksba_cms_get_signing_time(cms, 0, sigtime)))
        HANDLE_ERROR("Не получить время подписи\n");

    // Хэш содержимого из CMS
    char *msg_digest = NULL;
    size_t msg_len = 0;
    if ((err = ksba_cms_get_message_digest(cms, 0, &msg_digest, &msg_len)))
        HANDLE_ERROR("Не получить messageDigest из CMS\n");

    // Считаем локально и сравниваем
    int file_digest_len;
    unsigned char *file_digest = compute_file_digest(algoid, content_file, &file_digest_len);
    if (!file_digest || memcmp(file_digest, msg_digest, msg_len)) {
        SAFE_FREE(file_digest);
        SAFE_FREE(msg_digest);
        HANDLE_ERROR("Хэш содержимого не совпадает\n");
    }
    SAFE_FREE(file_digest);
    SAFE_FREE(msg_digest);

    // Снимаем саму сигнатуру
    unsigned char *sig_val = ksba_cms_get_sig_val(cms, 0);
    if (!sig_val) HANDLE_ERROR("Не найден sigValue\n");
    size_t sig_len = gcry_sexp_canon_len(sig_val,0,NULL,NULL);
    if ((err = gcry_sexp_sscan(&s_sig, NULL, (const char*)sig_val, sig_len)))
        HANDLE_ERROR("Ошибка разбора S-Exp сигнатуры\n");

    // Печать результатов
    fprintf(stderr, "\n========= Информация о подписи =========\n");
    if (*sigtime) {
        fprintf(stderr, "Дата подписи: ");
        dump_isotime(sigtime);
        fputc('\n', stderr);
    } else {
        fputs("[no signing time]\n", stderr);
    }
    fprintf(stderr, "Подписал: %s\n", subject_dn ?: (unsigned char *)"[unknown]");
    fprintf(stderr, "Выдал:   %s\n", issuer_dn ?: (unsigned char *)"[unknown]");

    if ((err = gcry_sexp_sscan(&s_num, NULL,
             (const char*)serial,
             gcry_sexp_canon_len(serial,0,NULL,NULL))))
        HANDLE_ERROR("Ошибка разбора серийного номера\n");
    show_sexp("Серийный номер:\n", s_num);
    fputs("========================================\n", stderr);

    // Финальная проверка подписи публичным ключом
    if ((err = gcry_pk_verify(s_sig, s_hash, s_pkey))) {
        show_sexp("Public Key:\n", s_pkey);
        show_sexp("Signature :\n", s_sig);
        show_sexp("Hash      :\n", s_hash);
    }

cleanup:
    SAFE_FREE(subject_dn);
    SAFE_FREE(issuer_dn);
    SAFE_FREE(serial);
    gcry_sexp_release(s_sig);
    gcry_sexp_release(s_hash);
    gcry_sexp_release(s_pkey);
    gcry_sexp_release(s_num);
    if (data_md) gcry_md_close(data_md);
    if (cms)     ksba_cms_release(cms);
    if (writer)  ksba_writer_release(writer);
    if (reader)  ksba_reader_release(reader);
    if (fp)      fclose(fp);
    return err;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <sig.p7s> <content> <out_cert.der>\n", argv[0]);
        return 1;
    }
    gcry_error_t err = process_file(argv[1], argv[2], argv[3]);
    if (err) {
        fprintf(stderr, "Проверка подписи '%s' не удалась: %s\n",
                argv[1], gcry_strerror(err));
        return 1;
    }
    fprintf(stderr, "Подпись '%s' корректна, сертификат сохранён в '%s'\n",
            argv[1], argv[3]);
    return 0;
}

