#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define PORT 8082
#define SALT_LEN SHA256_DIGEST_LENGTH   /* соль == размер хеша, 32 байта */

typedef struct {
    char          login[64];
    unsigned char salt[SALT_LEN];
    unsigned char ver[SHA256_DIGEST_LENGTH];
} Record;

static Record db[16];
static int    db_n = 0;

/* Считает h1 = H(login || '|' || password) */
static void hash_login_password(const char *login, const char *password,
                                unsigned char out[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, login, strlen(login));
    SHA256_Update(&c, "|", 1);
    SHA256_Update(&c, password, strlen(password));
    SHA256_Final(out, &c);
}

/* Считает ver = H(salt || h1) */
static void hash_salt_h1(const unsigned char salt[SALT_LEN],
                         const unsigned char h1[SHA256_DIGEST_LENGTH],
                         unsigned char out[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, salt, SALT_LEN);
    SHA256_Update(&c, h1, SHA256_DIGEST_LENGTH);
    SHA256_Final(out, &c);
}

static void add_user(const char *login, const char *password) {
    Record *r = &db[db_n++];
    strncpy(r->login, login, sizeof(r->login) - 1);

    /* Случайная соль длиной 32 байта */
    for (int i = 0; i < SALT_LEN; i++)
        r->salt[i] = (unsigned char)(rand() & 0xff);

    unsigned char h1[SHA256_DIGEST_LENGTH];
    hash_login_password(login, password, h1);
    hash_salt_h1(r->salt, h1, r->ver);
}

static Record *find_user(const char *login) {
    for (int i = 0; i < db_n; i++)
        if (!strcmp(db[i].login, login)) return &db[i];
    return NULL;
}

int main(void) {
    srand((unsigned)time(NULL));
    add_user("alice", "password123");
    add_user("bob",   "qwerty");

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sfd, 4);

    printf("SRP server слушает порт %d\n", PORT);

    while (1) {
        int cfd = accept(sfd, NULL, NULL);

        /* 1) Получаем логин */
        char login[64] = {0};
        ssize_t n = recv(cfd, login, sizeof(login) - 1, 0);
        if (n <= 0) { close(cfd); continue; }

        Record *r = find_user(login);
        if (!r) {
            send(cfd, "FAIL", 4, 0);
            close(cfd);
            continue;
        }

        /* 2) Шлём соль */
        send(cfd, r->salt, SALT_LEN, 0);

        /* 3) Получаем A = H(salt || H(login||'|'||password)) */
        unsigned char A[SHA256_DIGEST_LENGTH];
        if (recv(cfd, A, sizeof(A), MSG_WAITALL) != (ssize_t)sizeof(A)) {
            close(cfd);
            continue;
        }

        /* 4) Сравниваем с хранимым верификатором */
        int ok = (memcmp(A, r->ver, SHA256_DIGEST_LENGTH) == 0);
        send(cfd, ok ? "OK" : "FAIL", 4, 0);
        printf("Пользователь %s: %s\n", login, ok ? "OK" : "FAIL");

        close(cfd);
    }
    return 0;
}