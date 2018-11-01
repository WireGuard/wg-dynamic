/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2018 Wireguard LLC
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

void daemonize(void) {
    pid_t pid;

    /* fork */
    pid = fork();

    /* check fork for error */
    if (pid < 0) {
        perror("fork error");
        exit(EXIT_FAILURE);
    }

    /* terminate the parent */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* become session leader */
    if (setsid() < 0) {
        perror("setsid error");
        exit(EXIT_FAILURE);
    }

    /* fork */
    pid = fork();

    /* check fork for error */
    if (pid < 0) {
        perror("fork error");
        exit(EXIT_FAILURE);
    }

    /* terminate the parent */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* set up new environment */
    umask(S_IRWXG | S_IRWXO); /* umask 077 */
    chdir("/"); /* cd / to avoid locking up original cwd */

    /* close file descriptors */
    for (int fd = sysconf(_SC_OPEN_MAX); fd >=0; fd--) {
        close(fd);
    }
}
