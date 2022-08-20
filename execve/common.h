#ifndef EXECVE_COMMON_H_
#define EXECVE_COMMON_H_

#define FILENAME_LEN 128
#define MAX_ARGS_LEN 256

#pragma pack(1)

struct event {
    int pid;
    uint16_t args_len;
    char fname[FILENAME_LEN];
    char args[MAX_ARGS_LEN];
};

#pragma pack()

#endif  // EXECVE_COMMON_H_
