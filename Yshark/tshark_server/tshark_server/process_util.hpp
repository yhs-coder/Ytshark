#ifndef PROCESSUTIL_H
#define PROCESSUTIL_H

#include <stdio.h>
#include <string>

// 跨平台兼容处理
#ifdef _WIN32
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <csignal>
#include <tlhelp32.h>
typedef DWORD PID_T;
#else
#include <unistd.h>
#include <signal.h>
#include <limits.h>
typedef pid_t PID_T;
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <limits.h>
#endif


class ProcessUtil {
public:
    // Linux/Mac版本
#if defined(__unix__) || defined(__APPLE__)
    static FILE* PopenEx(std::string command, PID_T* pid_out = nullptr) {
        int pipefds[2] = { 0 };
        FILE* pipe_fp = nullptr;
        if (pipe(pipefds) == -1) {
            perror("pipe");
            return nullptr;
        }

        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            close(pipefds[0]);
            close(pipefds[1]);
            return nullptr;
        }

        if (pid == 0) {
            // 子进程
            close(pipefds[0]);  // 关闭独断
            dup2(pipefds[1], STDOUT_FILENO);  // 将stdout重定向到管道写端
            dup2(pipefds[1], STDERR_FILENO);  // 将stderr重定向到管道写端
            close(pipefds[1]);
            execl("bin/sh", "sh", "-c", command.c_str(), NULL);
            _exit(1);   // execl失败退出
        }

        // 父进程读取管道，关闭写端
        close(pipefds[1]);
        pipe_fp = fdopen(pipefds[0], "r");
        if (pid_out) {
            *pid_out = pid;
        }
        return pipe_fp;
    }
#endif
};


