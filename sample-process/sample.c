#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
    printf("%d\n", getpid());

    while (1) {
        continue;
    }
    
    return 0;
}
