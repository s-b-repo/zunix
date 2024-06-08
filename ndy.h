#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <library_path>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    char *lib_path = argv[2];

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        return 1;
    }

    waitpid(pid, NULL, 0);

    void *handle = dlmopen(LM_ID_NEWLM, lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlmopen error: %s\n", dlerror());
        return 1;
    }

    printf("Library %s injected.\n", lib_path);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
