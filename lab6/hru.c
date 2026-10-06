#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX     64
#define OWN     1
#define R       2
#define W       4

typedef struct {
    char name[32];
    int  type;    /* 0 = субъект, 1 = объект */
    int  alive;
} Entity;

static Entity ents[MAX];
static int    en = 0;

/* M[s][o]: битовая маска прав субъекта s на объект o */
static int M[MAX][MAX];

/* ---- Утилиты ---- */

static int find(const char *n) {
    for (int i = 0; i < en; i++)
        if (ents[i].alive && !strcmp(ents[i].name, n)) return i;
    return -1;
}

static int create_entity(const char *n, int type) {
    if (find(n) >= 0) return -1;
    ents[en].type = type;
    strncpy(ents[en].name, n, sizeof(ents[en].name) - 1);
    ents[en].alive = 1;
    return en++;
}

static const char *rights_str(int mask, char *buf) {
    buf[0] = 0;
    if (mask & OWN) strcat(buf, "own ");
    if (mask & R)   strcat(buf, "r ");
    if (mask & W)   strcat(buf, "w ");
    if (!buf[0])    strcpy(buf, "-");
    return buf;
}

static int parse_right(const char *s) {
    if (!strcmp(s, "own")) return OWN;
    if (!strcmp(s, "r"))   return R;
    if (!strcmp(s, "w"))   return W;
    return 0;
}

/* ---- Команды ---- */

/* создать субъект s */
static void cmd_create_subject(const char *s) {
    int i = create_entity(s, 0);
    if (i < 0) { printf("Ошибка: сущность '%s' уже существует\n", s); return; }
    printf("Создан субъект %s\n", s);
}

/* удалить субъект s */
static void cmd_destroy_subject(const char *s) {
    int i = find(s);
    if (i < 0 || ents[i].type != 0) {
        printf("Ошибка: субъект '%s' не найден\n", s);
        return;
    }
    ents[i].alive = 0;
    /* Обнуляем строку субъекта и столбец (если он был объектом — а он не был) */
    for (int j = 0; j < MAX; j++) { M[i][j] = 0; M[j][i] = 0; }
    printf("Удалён субъект %s\n", s);
}

/* создать объект o субъектом s, с получением прав r и w (и own как создатель) */
static void cmd_create_object(const char *s, const char *o) {
    int si = find(s);
    if (si < 0 || ents[si].type != 0) {
        printf("Ошибка: субъект '%s' не найден\n", s);
        return;
    }
    int oi = create_entity(o, 1);
    if (oi < 0) { printf("Ошибка: сущность '%s' уже существует\n", o); return; }
    /* Создатель получает владение + чтение + запись */
    M[si][oi] |= OWN | R | W;
    printf("Субъект %s создал объект %s с правами own, r, w\n", s, o);
}

/* удалить объект o, с проверкой права */
static void cmd_destroy_object(const char *s, const char *o) {
    int si = find(s);
    int oi = find(o);
    if (si < 0 || ents[si].type != 0) { printf("Ошибка: нет субъекта '%s'\n", s); return; }
    if (oi < 0 || ents[oi].type != 1) { printf("Ошибка: нет объекта '%s'\n", o); return; }

    /* Проверка: субъект должен иметь право владения на объект */
    if (!(M[si][oi] & OWN)) {
        printf("Отказ: субъект %s не владеет объектом %s\n", s, o);
        return;
    }
    ents[oi].alive = 0;
    for (int j = 0; j < MAX; j++) M[j][oi] = 0;
    printf("Объект %s удалён субъектом %s\n", o, s);
}

/* передать право r на объект o: s1 (владелец) -> s2 */
static void cmd_grant(const char *s1, const char *o, const char *r, const char *s2) {
    int a = find(s1), b = find(s2), c = find(o);
    if (a < 0 || ents[a].type != 0) { printf("Ошибка: нет субъекта '%s'\n", s1); return; }
    if (b < 0 || ents[b].type != 0) { printf("Ошибка: нет субъекта '%s'\n", s2); return; }
    if (c < 0 || ents[c].type != 1) { printf("Ошибка: нет объекта '%s'\n", o);   return; }

    int bit = parse_right(r);
    if (!bit) { printf("Ошибка: неизвестное право '%s'\n", r); return; }

    /* Проверка: s1 должен владеть объектом */
    if (!(M[a][c] & OWN)) {
        printf("Отказ: субъект %s не владеет объектом %s\n", s1, o);
        return;
    }
    M[b][c] |= bit;
    printf("Право '%s' на %s передано от %s к %s\n", r, o, s1, s2);
}

/* забрать право r на объект o: s1 (владелец) у s2 */
static void cmd_revoke(const char *s1, const char *o, const char *r, const char *s2) {
    int a = find(s1), b = find(s2), c = find(o);
    if (a < 0 || ents[a].type != 0) { printf("Ошибка: нет субъекта '%s'\n", s1); return; }
    if (b < 0 || ents[b].type != 0) { printf("Ошибка: нет субъекта '%s'\n", s2); return; }
    if (c < 0 || ents[c].type != 1) { printf("Ошибка: нет объекта '%s'\n", o);   return; }

    int bit = parse_right(r);
    if (!bit) { printf("Ошибка: неизвестное право '%s'\n", r); return; }

    if (!(M[a][c] & OWN)) {
        printf("Отказ: субъект %s не владеет объектом %s\n", s1, o);
        return;
    }
    if (!(M[b][c] & bit)) {
        printf("Отказ: у %s и так нет права '%s' на %s\n", s2, r, o);
        return;
    }
    M[b][c] &= ~bit;
    printf("Право '%s' на %s отозвано у %s субъектом %s\n", r, o, s2, s1);
}

/* вывод прав: указать можно либо субъект (что он имеет), либо объект (кто имеет) */
static void cmd_list(const char *name) {
    int i = find(name);
    if (i < 0) { printf("Ошибка: '%s' не найдено\n", name); return; }

    char buf[64];

    if (ents[i].type == 0) {
        /* Субъект: печатаем все его права на объекты */
        printf("Права субъекта %s:\n", name);
        int any = 0;
        for (int j = 0; j < en; j++) {
            if (!ents[j].alive || ents[j].type != 1) continue;
            if (!M[i][j]) continue;
            printf("  %-16s : %s\n", ents[j].name, rights_str(M[i][j], buf));
            any = 1;
        }
        if (!any) printf("  (нет прав)\n");
    } else {
        /* Объект: печатаем, у кого какие права на него */
        printf("Права на объект %s:\n", name);
        int any = 0;
        for (int j = 0; j < en; j++) {
            if (!ents[j].alive || ents[j].type != 0) continue;
            if (!M[j][i]) continue;
            printf("  %-16s : %s\n", ents[j].name, rights_str(M[j][i], buf));
            any = 1;
        }
        if (!any) printf("  (никто не имеет прав)\n");
    }
}

/* ---- main ---- */

static void help(void) {
    printf("\nДоступные команды:\n");
    printf("  cs <s>                                — создать субъект s\n");
    printf("  ds <s>                                — удалить субъект s\n");
    printf("  co <s> <o>                            — создать объект o субъектом s\n");
    printf("  do <s> <o>                            — удалить объект o субъектом s (нужно own)\n");
    printf("  grant <s1> <o> <r> <s2>               — передать право r на o от s1 к s2 (нужно own у s1)\n");
    printf("  revoke <s1> <o> <r> <s2>              — забрать право r на o у s2 субъектом s1 (нужно own)\n");
    printf("  list <name>                           — вывести права субъекта или на объект\n");
    printf("  help                                  — эта справка\n");
    printf("  quit                                  — выход\n");
    printf("\nПрава: own | r | w\n\n");
}

int main(void) {
    printf("Модель Харрисона—Руззо—Ульмана\n");
    help();

    char line[256];
    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        char cmd[16], a[32], b[32], c[32], d[32];
        int k = sscanf(line, "%15s %31s %31s %31s %31s", cmd, a, b, c, d);

        if (k < 1) continue;

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) break;
        else if (!strcmp(cmd, "help")) help();
        else if (!strcmp(cmd, "cs")     && k >= 2) cmd_create_subject(a);
        else if (!strcmp(cmd, "ds")     && k >= 2) cmd_destroy_subject(a);
        else if (!strcmp(cmd, "co")     && k >= 3) cmd_create_object(a, b);
        else if (!strcmp(cmd, "do")     && k >= 3) cmd_destroy_object(a, b);
        else if (!strcmp(cmd, "grant")  && k >= 5) cmd_grant(a, b, c, d);
        else if (!strcmp(cmd, "revoke") && k >= 5) cmd_revoke(a, b, c, d);
        else if (!strcmp(cmd, "list")   && k >= 2) cmd_list(a);
        else printf("Неизвестная команда или мало аргументов. Введи 'help'.\n");
    }

    printf("Выход.\n");
    return 0;
}