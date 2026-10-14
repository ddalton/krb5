/* Record what MIT krb5 makes of duration and enctype-list strings, for
 * src/config.rs's tests. Built and run by scripts/record-mit-settings.sh.
 *
 * Reads lines "D <string>" (krb5_string_to_deltat) or "E <string>"
 * (krb5int_parse_enctype_list with MIT's DEFAULT list) and writes each
 * line back followed by "\t" and MIT's answer: seconds, a space-separated
 * enctype list, or ERR. */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

krb5_error_code krb5int_parse_enctype_list(krb5_context, const char *, char *,
                                           krb5_enctype *, krb5_enctype **);

int main(void) {
    krb5_context ctx;
    char line[4096];
    /* MIT's default_enctype_list (init_ctx.c). */
    krb5_enctype dflt[] = {18, 17, 20, 19, 16, 23, 25, 26, 0};
    if (krb5_init_context(&ctx)) return 1;
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) < 2) continue;
        char *arg = strdup(line + 2);
        printf("%s\t", line);
        if (line[0] == 'D') {
            krb5_deltat d;
            if (krb5_string_to_deltat(arg, &d)) printf("ERR\n");
            else printf("%ld\n", (long)d);
        } else {
            krb5_enctype *list = NULL;
            if (krb5int_parse_enctype_list(ctx, "x", arg, dflt, &list)) printf("ERR\n");
            else {
                for (int i = 0; list[i]; i++) printf(i ? " %d" : "%d", list[i]);
                printf("\n");
                free(list);
            }
        }
        free(arg);
    }
    return 0;
}
