#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>

int runChildren(int argc, char *argv[], char *envp[], unsigned count)
{
    const char *path = argv[0];
    char buf[8];
    buf[0] = '\0';
    argv[0] = buf;
    pid_t pids[count];
    int result = 0;
    int wpid = 0;
    int wstatus = 0;
    for (unsigned i=0; i<count; i++)
        result += posix_spawn(&pids[i], path, 0, 0, argv, envp);


    while ((wpid = wait(&wstatus)) > 0);
    return result;
}
