#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>

void inject_library(pid_t pid, const char *lib_path) {
    struct user_regs_struct regs;
    long ptrace_ret;
    
    // Attach to the process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        exit(1);
    }

    // Wait for the process to stop
    waitpid(pid, NULL, 0);

    // Get the registers
    ptrace_ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (ptrace_ret == -1) {
        perror("ptrace(PTRACE_GETREGS)");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        exit(1);
    }

    // Allocate memory in the target process
    size_t path_len = strlen(lib_path) + 1;
    void *remote_addr = (void *)ptrace(PTRACE_PEEKDATA, pid, regs.rsp - 0x1000, NULL);
    
    // Write library path to remote memory
    struct iovec remote_iov = {
        .iov_base = (void *)lib_path,
        .iov_len = path_len
    };
    struct iovec local_iov = {
        .iov_base = remote_addr,
        .iov_len = path_len
    };
    if (process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0) == -1) {
        perror("process_vm_writev");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        exit(1);
    }

    // Write code to load the library
    // ...

    // Resume the process
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_DETACH)");
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <library_path>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char *lib_path = argv[2];

    inject_library(pid, lib_path);

    return 0;
}
