#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX  32
#define T    1   /* take  */
#define G_   2   /* grant */
#define R_   4   /* read  */
#define W_   8   /* write */

typedef struct {
    char name[32];
    int  type;    /* 0 = субъект, 1 = объект */
    int  alive;
} Entity;

static Entity ents[MAX];
static int    en = 0;

/* Реальные права: G[a][b] — маска прав на ребре a -> b */
static int G[MAX][MAX];

/* Мнимые рёбра информационных потоков (де-факто) */
static int F[MAX][MAX];

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
    if (mask & T)  strcat(buf, "t ");
    if (mask & G_) strcat(buf, "g ");
    if (mask & R_) strcat(buf, "r ");
    if (mask & W_) strcat(buf, "w ");
    if (!buf[0])   strcpy(buf, "-");
    return buf;
}

static int parse_right(const char *s) {
    if (!strcmp(s, "t")) return T;
    if (!strcmp(s, "g")) return G_;
    if (!strcmp(s, "r")) return R_;
    if (!strcmp(s, "w")) return W_;
    return 0;
}

/* ---- Де-юре правила ---- */

/* take(x, y, z): x->y (t), y->z (α)  =>  x->z (α) */
static int rule_take(void) {
    int changed = 0;
    for (int x = 0; x < en; x++) {
        if (!ents[x].alive || ents[x].type != 0) continue;
        for (int y = 0; y < en; y++) {
            if (!ents[y].alive) continue;
            if (!(G[x][y] & T)) continue;
            for (int z = 0; z < en; z++) {
                if (!ents[z].alive) continue;
                if (x == z) continue;             /* без петель */
                int alpha = G[y][z];
                if (!alpha) continue;
                int add = alpha & ~G[x][z];
                if (add) { G[x][z] |= add; changed = 1; }
            }
        }
    }
    return changed;
}

/* grant(x, y, z): x->y (g), x->z (α)  =>  y->z (α) */
static int rule_grant(void) {
    int changed = 0;
    for (int x = 0; x < en; x++) {
        if (!ents[x].alive || ents[x].type != 0) continue;
        for (int y = 0; y < en; y++) {
            if (!ents[y].alive || ents[y].type != 0) continue;
            if (!(G[x][y] & G_)) continue;
            for (int z = 0; z < en; z++) {
                if (!ents[z].alive) continue;
                if (y == z) continue;             /* без петель */
                int alpha = G[x][z];
                if (!alpha) continue;
                int add = alpha & ~G[y][z];
                if (add) { G[y][z] |= add; changed = 1; }
            }
        }
    }
    return changed;
}

/* ---- Де-факто правила (информационные потоки) ---- */

/* post(x, y, z): x->y (r), z->y (w)  =>  x->z (r) */
static int rule_post(void) {
    int changed = 0;
    for (int x = 0; x < en; x++) {
        if (!ents[x].alive || ents[x].type != 0) continue;
        for (int y = 0; y < en; y++) {
            if (!ents[y].alive) continue;
            if (!(G[x][y] & R_) && !(F[x][y] & R_)) continue;
            for (int z = 0; z < en; z++) {
                if (!ents[z].alive || ents[z].type != 0) continue;
                if (x == z) continue;
                if (!(G[z][y] & W_) && !(F[z][y] & W_)) continue;
                int add = R_ & ~F[x][z];
                if (add) { F[x][z] |= add; changed = 1; }
            }
        }
    }
    return changed;
}

/* pass(x, y, z): y->x (w), y->z (r)  =>  x->z (r) */
static int rule_pass(void) {
    int changed = 0;
    for (int y = 0; y < en; y++) {
        if (!ents[y].alive || ents[y].type != 0) continue;
        for (int x = 0; x < en; x++) {
            if (!ents[x].alive || ents[x].type != 0) continue;
            if (x == y) continue;
            if (!(G[y][x] & W_) && !(F[y][x] & W_)) continue;
            for (int z = 0; z < en; z++) {
                if (!ents[z].alive) continue;
                if (x == z) continue;
                if (!(G[y][z] & R_) && !(F[y][z] & R_)) continue;
                int add = R_ & ~F[x][z];
                if (add) { F[x][z] |= add; changed = 1; }
            }
        }
    }
    return changed;
}

/* spy(x, y, z): x->y (r), y->z (r)  =>  x->z (r) */
static int rule_spy(void) {
    int changed = 0;
    for (int x = 0; x < en; x++) {
        if (!ents[x].alive || ents[x].type != 0) continue;
        for (int y = 0; y < en; y++) {
            if (!ents[y].alive || ents[y].type != 0) continue;
            if (x == y) continue;
            if (!(G[x][y] & R_) && !(F[x][y] & R_)) continue;
            for (int z = 0; z < en; z++) {
                if (!ents[z].alive) continue;
                if (x == z) continue;
                if (!(G[y][z] & R_) && !(F[y][z] & R_)) continue;
                int add = R_ & ~F[x][z];
                if (add) { F[x][z] |= add; changed = 1; }
            }
        }
    }
    return changed;
}

/* find(y, x, z): y->x (w), z->y (w)  =>  x->z (r) */
static int rule_find(void) {
    int changed = 0;
    for (int y = 0; y < en; y++) {
        if (!ents[y].alive) continue;
        for (int x = 0; x < en; x++) {
            if (!ents[x].alive || ents[x].type != 0) continue;
            if (x == y) continue;
            if (!(G[y][x] & W_) && !(F[y][x] & W_)) continue;
            for (int z = 0; z < en; z++) {
                if (!ents[z].alive || ents[z].type != 0) continue;
                if (x == z) continue;
                if (!(G[z][y] & W_) && !(F[z][y] & W_)) continue;
                int add = R_ & ~F[x][z];
                if (add) { F[x][z] |= add; changed = 1; }
            }
        }
    }
    return changed;
}

/* ---- Построение замыкания ---- */

static void build_closure(void) {
    int changed = 1;
    int iter = 0;
    printf("\n=== Построение замыкания ===\n");
    while (changed) {
        changed = 0;
        changed |= rule_take();
        changed |= rule_grant();
        changed |= rule_post();
        changed |= rule_pass();
        changed |= rule_spy();
        changed |= rule_find();
        iter++;
        if (iter > 100) break;
    }
    printf("Стабилизация за %d итераций\n", iter);
}

/* ---- Вывод графа ---- */

static void print_graph(void) {
    char buf[64];
    printf("\n--- Рёбра де-юре (G) ---\n");
    int any = 0;
    for (int i = 0; i < en; i++) {
        if (!ents[i].alive) continue;
        for (int j = 0; j < en; j++) {
            if (!ents[j].alive) continue;
            if (!G[i][j]) continue;
            printf("  %-10s -> %-10s : %s\n",
                   ents[i].name, ents[j].name, rights_str(G[i][j], buf));
            any = 1;
        }
    }
    if (!any) printf("  (пусто)\n");

    printf("\n--- Рёбра де-факто (F, информационные потоки) ---\n");
    any = 0;
    for (int i = 0; i < en; i++) {
        if (!ents[i].alive) continue;
        for (int j = 0; j < en; j++) {
            if (!ents[j].alive) continue;
            if (!F[i][j]) continue;
            printf("  %-10s => %-10s : %s\n",
                   ents[i].name, ents[j].name, rights_str(F[i][j], buf));
            any = 1;
        }
    }
    if (!any) printf("  (пусто)\n");
}

/* ---- Демо-граф ---- */

static void build_demo(void) {
    /*
     * Демо подобрано так, чтобы показать и де-юре, и де-факто:
     *
     *   alice -t-> bob        (alice может "взять" права bob)
     *   alice -g-> carol      (alice может "передать" carol свои права)
     *   bob   -r-> file1      (bob читает file1)
     *   carol -w-> file1      (carol пишет в file1)
     *   carol -r-> file2      (carol читает file2)
     *   dave  -w-> file2      (dave пишет в file2)
     *   dave  -r-> file3      (dave читает file3)
     *
     * Ожидаемые де-юре эффекты:
     *   take  → alice -r-> file1  (alice берёт r от bob)
     *   grant → carol -t-> bob    (alice передаёт carol право t на bob)
     *         → carol -r-> file1  (alice передаёт carol право r на file1)
     *
     * Ожидаемые де-факто потоки:
     *   post(alice, file1, carol) : alice-r->file1, carol-w->file1  => alice=>carol
     *   spy(alice, bob, file1)    : alice-r->bob, bob-r->file1      => alice=>file1
     *   pass(carol, file1, file2) : carol-w->file1, carol-r->file2  => file1=>file2
     *   find(dave, file2, file3)  : dave-w->file2, file3->dave? нет — не сработает
     */
    create_entity("alice", 0);
    create_entity("bob",   0);
    create_entity("carol", 0);
    create_entity("dave",  0);
    create_entity("file1", 1);
    create_entity("file2", 1);
    create_entity("file3", 1);

    int a = find("alice");
    int b = find("bob");
    int c = find("carol");
    int d = find("dave");
    int f1 = find("file1");
    int f2 = find("file2");
    int f3 = find("file3");

    G[a][b]  |= T;      /* alice -t-> bob */
    G[a][c]  |= G_;     /* alice -g-> carol */
    G[b][f1] |= R_;     /* bob   -r-> file1 */
    G[c][f1] |= W_;     /* carol -w-> file1 */
    G[c][f2] |= R_;     /* carol -r-> file2 */
    G[d][f2] |= W_;     /* dave  -w-> file2 */
    G[d][f3] |= R_;     /* dave  -r-> file3 */

    printf("Демо-граф создан:\n");
    printf("  alice -t-> bob\n");
    printf("  alice -g-> carol\n");
    printf("  bob   -r-> file1\n");
    printf("  carol -w-> file1\n");
    printf("  carol -r-> file2\n");
    printf("  dave  -w-> file2\n");
    printf("  dave  -r-> file3\n");
}

/* ---- main ---- */

static void help(void) {
    printf("\nКоманды:\n");
    printf("  cs <s>                  — создать субъект\n");
    printf("  co <o>                  — создать объект\n");
    printf("  add <a> <b> <r>         — добавить право r на ребре a->b\n");
    printf("  del <a> <b> <r>         — удалить право r\n");
    printf("  closure                 — построить замыкание\n");
    printf("  show                    — показать граф\n");
    printf("  demo                    — загрузить демо-граф\n");
    printf("  reset                   — очистить всё\n");
    printf("  help                    — справка\n");
    printf("  quit                    — выход\n");
    printf("\nПрава: t | g | r | w\n\n");
}

static void reset_all(void) {
    en = 0;
    memset(G, 0, sizeof(G));
    memset(F, 0, sizeof(F));
}

int main(void) {
    printf("Модель Take-Grant (расширенная, с информационными потоками)\n");
    help();

    char line[256];
    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        char cmd[16], a[32], b[32], c[32];
        int k = sscanf(line, "%15s %31s %31s %31s", cmd, a, b, c);

        if (k < 1) continue;

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) break;
        else if (!strcmp(cmd, "help")) help();
        else if (!strcmp(cmd, "reset")) { reset_all(); printf("Сброшено\n"); }
        else if (!strcmp(cmd, "demo")) { reset_all(); build_demo(); }
        else if (!strcmp(cmd, "show")) print_graph();
        else if (!strcmp(cmd, "closure")) build_closure();
        else if (!strcmp(cmd, "cs") && k >= 2) {
            int i = create_entity(a, 0);
            if (i < 0) printf("Уже существует\n");
            else printf("Создан субъект %s\n", a);
        }
        else if (!strcmp(cmd, "co") && k >= 2) {
            int i = create_entity(a, 1);
            if (i < 0) printf("Уже существует\n");
            else printf("Создан объект %s\n", a);
        }
        else if (!strcmp(cmd, "add") && k >= 4) {
            int i = find(a), j = find(b);
            int r = parse_right(c);
            if (i < 0 || j < 0) printf("Нет такой вершины\n");
            else if (!r) printf("Неизвестное право\n");
            else { G[i][j] |= r; printf("Добавлено %s: %s -> %s\n", c, a, b); }
        }
        else if (!strcmp(cmd, "del") && k >= 4) {
            int i = find(a), j = find(b);
            int r = parse_right(c);
            if (i < 0 || j < 0) printf("Нет такой вершины\n");
            else if (!r) printf("Неизвестное право\n");
            else { G[i][j] &= ~r; printf("Удалено %s: %s -> %s\n", c, a, b); }
        }
        else printf("Неизвестная команда. 'help' для справки.\n");
    }

    printf("Выход.\n");
    return 0;
}