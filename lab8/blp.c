#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 64
#define LEVEL_UNCLASSIFIED 0
#define LEVEL_CONFIDENTIAL 1
#define LEVEL_SECRET       2
#define LEVEL_TOP_SECRET   3

#define ACC_R 1
#define ACC_W 2

typedef struct {
    char name[32];
    int  level;
    int  alive;
} Entity;

typedef struct {
    char name[32];
    int  max_level;        /* максимальный уровень субъекта */
    int  current_level;    /* текущий рабочий уровень (<= max_level) */
    int  alive;
} Subject;

static Entity   objs[MAX];
static int      obj_n = 0;

static Subject  subs[MAX];
static int      sub_n = 0;

/* Активные доступы субъекта s к объекту o: битовая маска ACC_R/ACC_W */
static int M[MAX][MAX];

/* ---- Утилиты ---- */

static const char *level_name(int l) {
    switch (l) {
        case LEVEL_UNCLASSIFIED: return "UNCLASSIFIED";
        case LEVEL_CONFIDENTIAL: return "CONFIDENTIAL";
        case LEVEL_SECRET:       return "SECRET";
        case LEVEL_TOP_SECRET:   return "TOP_SECRET";
    }
    return "?";
}

static int find_sub(const char *n) {
    for (int i = 0; i < sub_n; i++)
        if (subs[i].alive && !strcmp(subs[i].name, n)) return i;
    return -1;
}
static int find_obj(const char *n) {
    for (int i = 0; i < obj_n; i++)
        if (objs[i].alive && !strcmp(objs[i].name, n)) return i;
    return -1;
}

static int parse_level(const char *s) {
    if (!strcmp(s, "0") || !strcmp(s, "u"))  return LEVEL_UNCLASSIFIED;
    if (!strcmp(s, "1") || !strcmp(s, "c"))  return LEVEL_CONFIDENTIAL;
    if (!strcmp(s, "2") || !strcmp(s, "s"))  return LEVEL_SECRET;
    if (!strcmp(s, "3") || !strcmp(s, "t"))  return LEVEL_TOP_SECRET;
    return -1;
}

/* ---- Основные правила BLP ---- */

/* Простое свойство: NRU — можно ли читать */
static int can_read(int sub_idx, int obj_idx) {
    return subs[sub_idx].current_level >= objs[obj_idx].level;
}

/* *-свойство: NWD — можно ли писать */
static int can_write(int sub_idx, int obj_idx) {
    return subs[sub_idx].current_level <= objs[obj_idx].level;
}

/* Перепроверка всех доступов субъекта после смены уровня */
static void recheck_accesses(int s) {
    int revoked = 0;
    for (int o = 0; o < obj_n; o++) {
        if (!objs[o].alive) continue;
        int acc = M[s][o];
        if (!acc) continue;

        int new_acc = 0;
        if ((acc & ACC_R) && can_read(s, o))  new_acc |= ACC_R;
        if ((acc & ACC_W) && can_write(s, o)) new_acc |= ACC_W;

        if (new_acc != acc) {
            printf("  [перепроверка] %s -> %s : %s%s → %s%s\n",
                   subs[s].name, objs[o].name,
                   (acc & ACC_R) ? "r" : "", (acc & ACC_W) ? "w" : "",
                   (new_acc & ACC_R) ? "r" : "", (new_acc & ACC_W) ? "w" : "");
            M[s][o] = new_acc;
            revoked++;
        }
    }
    if (revoked)
        printf("  Отозвано/изменено доступов: %d\n", revoked);
    else
        printf("  Все текущие доступы остаются корректными\n");
}

/* ---- Команды ---- */

static void cmd_create_subject(const char *name, int max_level) {
    if (find_sub(name) >= 0) { printf("Субъект '%s' уже существует\n", name); return; }
    Subject *s = &subs[sub_n];
    strncpy(s->name, name, sizeof(s->name) - 1);
    s->max_level     = max_level;
    s->current_level = max_level;   /* по умолчанию работает на максимуме */
    s->alive = 1;
    printf("Создан субъект %s (max=%s, current=%s)\n",
           name, level_name(max_level), level_name(max_level));
    sub_n++;
}

static void cmd_create_object(const char *name, int level) {
    if (find_obj(name) >= 0) { printf("Объект '%s' уже существует\n", name); return; }
    Entity *o = &objs[obj_n];
    strncpy(o->name, name, sizeof(o->name) - 1);
    o->level = level;
    o->alive = 1;
    printf("Создан объект %s (level=%s)\n", name, level_name(level));
    obj_n++;
}

static void cmd_set_max_level(const char *name, int lvl) {
    int s = find_sub(name);
    if (s < 0) { printf("Нет субъекта '%s'\n", name); return; }
    subs[s].max_level = lvl;
    if (subs[s].current_level > lvl) {
        subs[s].current_level = lvl;
        printf("Максимальный уровень %s понижен до %s; текущий также понижен\n",
               name, level_name(lvl));
        recheck_accesses(s);
    } else {
        printf("Максимальный уровень %s = %s\n", name, level_name(lvl));
    }
}

static void cmd_set_current_level(const char *name, int lvl) {
    int s = find_sub(name);
    if (s < 0) { printf("Нет субъекта '%s'\n", name); return; }
    if (lvl > subs[s].max_level) {
        printf("Отказ: %s не может поднять current_level выше max_level (%s)\n",
               name, level_name(subs[s].max_level));
        return;
    }
    subs[s].current_level = lvl;
    printf("Текущий уровень %s = %s\n", name, level_name(lvl));
    printf("Перепроверка активных доступов:\n");
    recheck_accesses(s);
}

static void cmd_read(const char *sub_name, const char *obj_name) {
    int s = find_sub(sub_name), o = find_obj(obj_name);
    if (s < 0 || o < 0) { printf("Нет субъекта или объекта\n"); return; }

    if (!can_read(s, o)) {
        printf("ОТКАЗ (NRU): %s (%s) не может читать %s (%s)\n",
               sub_name, level_name(subs[s].current_level),
               obj_name, level_name(objs[o].level));
        return;
    }
    M[s][o] |= ACC_R;
    printf("OK: %s читает %s\n", sub_name, obj_name);
}

static void cmd_write(const char *sub_name, const char *obj_name) {
    int s = find_sub(sub_name), o = find_obj(obj_name);
    if (s < 0 || o < 0) { printf("Нет субъекта или объекта\n"); return; }

    if (!can_write(s, o)) {
        printf("ОТКАЗ (NWD): %s (%s) не может писать в %s (%s)\n",
               sub_name, level_name(subs[s].current_level),
               obj_name, level_name(objs[o].level));
        return;
    }
    M[s][o] |= ACC_W;
    printf("OK: %s пишет в %s\n", sub_name, obj_name);
}

static void cmd_close(const char *sub_name, const char *obj_name) {
    int s = find_sub(sub_name), o = find_obj(obj_name);
    if (s < 0 || o < 0) { printf("Нет субъекта или объекта\n"); return; }
    M[s][o] = 0;
    printf("Доступ %s -> %s закрыт\n", sub_name, obj_name);
}

static void cmd_show_sub(const char *name) {
    int s = find_sub(name);
    if (s < 0) { printf("Нет субъекта '%s'\n", name); return; }
    printf("Субъект %s: max=%s, current=%s\n",
           name, level_name(subs[s].max_level), level_name(subs[s].current_level));
    printf("Активные доступы:\n");
    int any = 0;
    for (int o = 0; o < obj_n; o++) {
        if (!objs[o].alive || !M[s][o]) continue;
        printf("  -> %-10s (%s) : %s%s\n",
               objs[o].name, level_name(objs[o].level),
               (M[s][o] & ACC_R) ? "r" : "",
               (M[s][o] & ACC_W) ? "w" : "");
        any = 1;
    }
    if (!any) printf("  (нет)\n");
}

static void cmd_show_all(void) {
    printf("\n--- Субъекты ---\n");
    for (int i = 0; i < sub_n; i++) {
        if (!subs[i].alive) continue;
        printf("  %-10s max=%-14s current=%s\n",
               subs[i].name, level_name(subs[i].max_level),
               level_name(subs[i].current_level));
    }
    printf("--- Объекты ---\n");
    for (int i = 0; i < obj_n; i++) {
        if (!objs[i].alive) continue;
        printf("  %-10s level=%s\n", objs[i].name, level_name(objs[i].level));
    }
    printf("--- Активные доступы ---\n");
    int any = 0;
    for (int s = 0; s < sub_n; s++) {
        if (!subs[s].alive) continue;
        for (int o = 0; o < obj_n; o++) {
            if (!objs[o].alive || !M[s][o]) continue;
            printf("  %-10s -> %-10s : %s%s\n",
                   subs[s].name, objs[o].name,
                   (M[s][o] & ACC_R) ? "r" : "",
                   (M[s][o] & ACC_W) ? "w" : "");
            any = 1;
        }
    }
    if (!any) printf("  (нет)\n");
    printf("\n");
}

/* ---- Демо ---- */

static void cmd_demo(void) {
    /* Чистим всё */
    memset(objs, 0, sizeof(objs)); obj_n = 0;
    memset(subs, 0, sizeof(subs)); sub_n = 0;
    memset(M, 0, sizeof(M));

    printf("=== Демо BLP ===\n");

    /* Субъекты с разными уровнями */
    cmd_create_subject("admin",  LEVEL_TOP_SECRET);
    cmd_create_subject("user",   LEVEL_CONFIDENTIAL);
    cmd_create_subject("guest",  LEVEL_UNCLASSIFIED);

    /* Объекты */
    cmd_create_object("top_doc",   LEVEL_TOP_SECRET);
    cmd_create_object("secret_doc", LEVEL_SECRET);
    cmd_create_object("conf_doc",  LEVEL_CONFIDENTIAL);
    cmd_create_object("pub_doc",   LEVEL_UNCLASSIFIED);

    printf("\n--- Попытки чтения ---\n");
    cmd_read("admin", "top_doc");    /* OK — уровни равны */
    cmd_read("admin", "pub_doc");    /* OK — admin выше */
    cmd_read("user",  "top_doc");    /* ОТКАЗ — NRU */
    cmd_read("user",  "conf_doc");   /* OK */
    cmd_read("guest", "conf_doc");   /* ОТКАЗ — NRU */
    cmd_read("guest", "pub_doc");    /* OK */

    printf("\n--- Попытки записи ---\n");
    cmd_write("admin", "top_doc");    /* OK */
    cmd_write("admin", "pub_doc");    /* ОТКАЗ — NWD, нельзя писать вниз */
    cmd_write("user",  "conf_doc");   /* OK */
    cmd_write("user",  "pub_doc");    /* ОТКАЗ — NWD */
    cmd_write("user",  "secret_doc"); /* OK — можно писать вверх */
    cmd_write("guest", "pub_doc");    /* OK */

    printf("\n--- Понижение уровня user до UNCLASSIFIED ---\n");
    cmd_set_current_level("user", LEVEL_UNCLASSIFIED);
    /* Доступ user->conf_doc (r) должен быть отозван, потому что
       теперь user не может читать CONFIDENTIAL */

    printf("\n--- Что у user сейчас ---\n");
    cmd_show_sub("user");

    printf("\n--- Попытка user прочитать conf_doc после понижения ---\n");
    cmd_read("user", "conf_doc");   /* ОТКАЗ */

    printf("\n--- Возврат user на CONFIDENTIAL ---\n");
    cmd_set_current_level("user", LEVEL_CONFIDENTIAL);
    cmd_read("user", "conf_doc");   /* OK снова */

    printf("\n");
}

/* ---- main ---- */

static void help(void) {
    printf("\nКоманды:\n");
    printf("  cs <s> <lvl>              — создать субъект (lvl: 0|1|2|3 или u|c|s|t)\n");
    printf("  co <o> <lvl>              — создать объект\n");
    printf("  setmax <s> <lvl>          — задать максимальный уровень субъекта\n");
    printf("  setcur <s> <lvl>          — задать текущий уровень (<= max)\n");
    printf("  read <s> <o>              — попытаться прочитать\n");
    printf("  write <s> <o>             — попытаться записать\n");
    printf("  close <s> <o>             — закрыть доступ\n");
    printf("  show <s>                  — показать доступы субъекта\n");
    printf("  showall                   — показать всё состояние\n");
    printf("  demo                      — демонстрация\n");
    printf("  help                      — справка\n");
    printf("  quit                      — выход\n");
    printf("\nУровни: 0=UNCLASSIFIED, 1=CONFIDENTIAL, 2=SECRET, 3=TOP_SECRET\n\n");
}

int main(void) {
    printf("Модель Белла—ЛаПадулы\n");
    help();

    char line[256];
    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        char cmd[16], a[32], b[32];
        int k = sscanf(line, "%15s %31s %31s", cmd, a, b);
        if (k < 1) continue;

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) break;
        else if (!strcmp(cmd, "help")) help();
        else if (!strcmp(cmd, "demo")) cmd_demo();
        else if (!strcmp(cmd, "showall")) cmd_show_all();
        else if (!strcmp(cmd, "cs") && k >= 3) {
            int lvl = parse_level(b);
            if (lvl < 0) printf("Неверный уровень\n");
            else cmd_create_subject(a, lvl);
        }
        else if (!strcmp(cmd, "co") && k >= 3) {
            int lvl = parse_level(b);
            if (lvl < 0) printf("Неверный уровень\n");
            else cmd_create_object(a, lvl);
        }
        else if (!strcmp(cmd, "setmax") && k >= 3) {
            int lvl = parse_level(b);
            if (lvl < 0) printf("Неверный уровень\n");
            else cmd_set_max_level(a, lvl);
        }
        else if (!strcmp(cmd, "setcur") && k >= 3) {
            int lvl = parse_level(b);
            if (lvl < 0) printf("Неверный уровень\n");
            else cmd_set_current_level(a, lvl);
        }
        else if (!strcmp(cmd, "read")  && k >= 3) cmd_read(a, b);
        else if (!strcmp(cmd, "write") && k >= 3) cmd_write(a, b);
        else if (!strcmp(cmd, "close") && k >= 3) cmd_close(a, b);
        else if (!strcmp(cmd, "show")  && k >= 2) cmd_show_sub(a);
        else printf("Неизвестная команда. 'help' для справки.\n");
    }
    printf("Выход.\n");
    return 0;
}