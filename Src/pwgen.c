/*
 * pwgen.c - Generador seguro de contraseñas en C
 *
 * Author: TuNombre (2025)
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>

#ifdef _WIN32
  #include <windows.h>
  #include <wincrypt.h>
#else
  #include <unistd.h>
  #include <fcntl.h>
#endif

#define DEFAULT_LEN 16
#define DEFAULT_COUNT 1

static const char *UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *LOWER = "abcdefghijklmnopqrstuvwxyz";
static const char *DIGITS = "0123456789";
static const char *SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?";

static const char *AMBIGUOUS = "O0oIl1|`'\"";
static int avoid_ambiguous = 0;

int secure_random_bytes(unsigned char *buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return -1;
    if (!CryptGenRandom(hProv, (DWORD)len, buf)) {
        CryptReleaseContext(hProv, 0);
        return -2;
    }
    CryptReleaseContext(hProv, 0);
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, len);
    close(fd);
    if (r != (ssize_t)len) return -2;
    return 0;
#endif
}

int is_ambig(char c) {
    for (const char *p = AMBIGUOUS; *p; ++p) if (*p == c) return 1;
    return 0;
}

char *build_pool(int use_upper, int use_lower, int use_digits, int use_symbols, int *pool_len) {
    size_t cap = 128;
    char *pool = malloc(cap);
    if (!pool) return NULL;
    size_t pos = 0;

    if (use_upper) for (const char *p = UPPER; *p; ++p) if (!(avoid_ambiguous && is_ambig(*p))) pool[pos++] = *p;
    if (use_lower) for (const char *p = LOWER; *p; ++p) if (!(avoid_ambiguous && is_ambig(*p))) pool[pos++] = *p;
    if (use_digits) for (const char *p = DIGITS; *p; ++p) if (!(avoid_ambiguous && is_ambig(*p))) pool[pos++] = *p;
    if (use_symbols) for (const char *p = SYMBOLS; *p; ++p) if (!(avoid_ambiguous && is_ambig(*p))) pool[pos++] = *p;

    if (pos == 0) { free(pool); *pool_len = 0; return NULL; }
    pool[pos] = '\0';
    *pool_len = (int)pos;
    return pool;
}

char *generate_password(int length, const char *pool, int pool_len) {
    if (pool_len <= 0) return NULL;
    char *pw = malloc((size_t)length + 1);
    if (!pw) return NULL;
    unsigned char *rnd = malloc((size_t)length);
    if (!rnd) { free(pw); return NULL; }

    if (secure_random_bytes(rnd, (size_t)length) != 0) {
        free(rnd); free(pw);
        return NULL;
    }
    for (int i = 0; i < length; ++i) pw[i] = pool[rnd[i] % pool_len];
    pw[length] = '\0';
    free(rnd);
    return pw;
}

void print_usage(const char *prog) {
    printf("Uso: %s [opciones]\n", prog);
    printf("Opciones:\n");
    printf("  -l LENGTH      longitud de la contrase\u00f1a (8-30, default %d)\n", DEFAULT_LEN);
    printf("  -n COUNT       cu\u00e1ntas contrase\u00f1as generar (1-6, default %d)\n", DEFAULT_COUNT);
    printf("  -u             incluir may\u00fasculas (A-Z, default si)\n");
    printf("  -L             incluir min\u00fasculas (a-z, default si)\n");
    printf("  -d             incluir d\u00edgitos (0-9, default si)\n");
    printf("  -s             incluir s\u00edmbolos (!@#..., default si)\n");
    printf("  -a             incluir todo (equivale a -u -L -d -s)\n");
    printf("  -b             evitar caracteres ambiguos (0 O l 1 i ...)\n");
    printf("  -o FILE        escribir salida a FILE (en vez de stdout)\n");
    printf("  -h             ayuda\n");
}

int main(int argc, char **argv) {
#ifdef _WIN32
    // Forzar consola Windows a UTF-8 (para ñ y acentos)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    int running = 1;

    while (running) {
        printf("\n=== Generador de Contrase\u00f1as ===\n");
        printf("1. Generar contrase\u00f1a(s)\n");
        printf("2. Ver ayuda\n");
        printf("3. Salir\n");
        printf("Elige una opci\u00f3n: ");

        int option;
        if (scanf("%d", &option) != 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            printf("⚠ Entrada inv\u00e1lida.\n");
            continue;
        }
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        if (option == 1) {
            int length = DEFAULT_LEN, count = DEFAULT_COUNT;
            int use_upper = 1, use_lower = 1, use_digits = 1, use_symbols = 1;
            char input_char;

            // Longitud
            printf("Longitud de la contrase\u00f1a (8-30, por defecto %d): ", DEFAULT_LEN);
            if (scanf("%d", &length) != 1) {
                while ((c = getchar()) != '\n' && c != EOF);
                printf("Usando longitud por defecto: %d\n", DEFAULT_LEN);
                length = DEFAULT_LEN;
            } else {
                while ((c = getchar()) != '\n' && c != EOF);
                if (length < 8) length = 8;
                if (length > 30) length = 30;
            }

            // Cantidad
            printf("Cantidad de contrase\u00f1as (1-6, por defecto %d): ", DEFAULT_COUNT);
            if (scanf("%d", &count) != 1) {
                while ((c = getchar()) != '\n' && c != EOF);
                printf("Usando cantidad por defecto: %d\n", DEFAULT_COUNT);
                count = DEFAULT_COUNT;
            } else {
                while ((c = getchar()) != '\n' && c != EOF);
                if (count < 1) count = 1;
                if (count > 6) count = 6;
            }

            // Mayúsculas
            printf("Incluir may\u00fasculas? (S/n, por defecto S): ");
            input_char = tolower(getchar());
            while ((c = getchar()) != '\n' && c != EOF);
            if (input_char == 'n') use_upper = 0;

            // Minúsculas
            printf("Incluir min\u00fasculas? (S/n, por defecto S): ");
            input_char = tolower(getchar());
            while ((c = getchar()) != '\n' && c != EOF);
            if (input_char == 'n') use_lower = 0;

            // Dígitos
            printf("Incluir d\u00edgitos? (S/n, por defecto S): ");
            input_char = tolower(getchar());
            while ((c = getchar()) != '\n' && c != EOF);
            if (input_char == 'n') use_digits = 0;

            // Símbolos
            printf("Incluir s\u00edmbolos? (S/n, por defecto S): ");
            input_char = tolower(getchar());
            while ((c = getchar()) != '\n' && c != EOF);
            if (input_char == 'n') use_symbols = 0;

            int pool_len = 0;
            char *pool = build_pool(use_upper, use_lower, use_digits, use_symbols, &pool_len);
            if (!pool) {
                fprintf(stderr, "❌ Error: conjunto de caracteres vac\u00edo.\n");
                continue;
            }

            for (int i = 0; i < count; i++) {
                char *pw = generate_password(length, pool, pool_len);
                if (pw) {
                    printf("Contrase\u00f1a %d: %s\n", i+1, pw);
                    free(pw);
                }
            }
            free(pool);
        }
        else if (option == 2) {
            print_usage("pwgen");
        }
        else if (option == 3) {
            running = 0;
        }
        else {
            printf("⚠ Opci\u00f3n no v\u00e1lida.\n");
        }
    }

    return 0;
}