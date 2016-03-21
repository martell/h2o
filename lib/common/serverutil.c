/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
 //#include "winpthreads.h"
#include <signal.h>
#include <stdint.h>
//#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#if !defined(_SC_NPROCESSORS_ONLN)
#endif
#include "C:\Users\Rathi\Desktop\Repository\one-four-2016\http2-repo1\deps\cloexec\cloexec.h"
#include "h2o/memory.h"
#include "h2o/serverutil.h"
#include "h2o/socket.h"
#include "h2o/string_.h"

#if (_WIN32) //Find alternatives for all these yet
#include <uv.h> //to spawn new child process
#include <assert.h> //debugging
#else
#include <grp.h>
#include <spawn.h> //for subprocess
#include <unistd.h> //pid
#include <sys/wait.h> //waitpid()
#include <sys/sysctl.h>
#endif


//BOOLEAN *CHILD_RETURNED; //Dirty Fix, doesn't know which child returned, but at least one of it/them returned.


//Signal name and related function.
void h2o_set_signal_handler(int signo, void (*cb)(int signo))
{
#ifdef _WIN32
	signal(signo, cb); //pass the signal number to function, without setting all flags.
#else
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = cb;
    sigaction(signo, &action, NULL);
#endif
}

//Sets user and group ID's.
int h2o_setuidgid(struct passwd *passwd)
{
	/*sets the effective group ID of the calling process, seemingly not possible with Visual Studio. 
	  the alternative in windows is SID, but its not the same and not workable.
	  C++ provides UserPrincipal class, that has similar stuff but again not same.
	
	 Can I work without permissions? For now leaving it alone.
	*/
#if defined(__linux__)

    if (setgid(passwd->pw_gid) != 0) {
        fprintf(stderr, "setgid(%d) failed:%s\n", (int)passwd->pw_gid, strerror(errno));
        return -1;
    }
    if (initgroups(passwd->pw_name, passwd->pw_gid) != 0) {
        fprintf(stderr, "initgroups(%s, %d) failed:%s\n", passwd->pw_name, (int)passwd->pw_gid, strerror(errno));
        return -1;
    }
	//sets user ID 
    if (setuid(passwd->pw_uid) != 0) {
        fprintf(stderr, "setuid(%d) failed:%s\n", (int)passwd->pw_uid, strerror(errno));
        return -1;
    }
#endif
    return 0; // just returning 0 as a call of successfully assigning user ID and group ID, since its not do-able in windows.
}

size_t h2o_server_starter_get_fds(int **_fds)
{
    const char *ports_env, *start, *end, *eq;
    size_t t;
	//edit : Empty Initialization
	H2O_VECTOR(int)fds = {0};

    if ((ports_env = getenv("SERVER_STARTER_PORT")) == NULL)
        return 0;
    if (ports_env[0] == '\0') {
        fprintf(stderr, "$SERVER_STARTER_PORT is empty\n");
        return SIZE_MAX;
    }

    /* ports_env example: 127.0.0.1:80=3;/tmp/sock=4 */
    for (start = ports_env; *start != '\0'; start = *end == ';' ? end + 1 : end) {
        if ((end = strchr(start, ';')) == NULL)
            end = start + strlen(start);
        if ((eq = memchr(start, '=', end - start)) == NULL) {
            fprintf(stderr, "invalid $SERVER_STARTER_PORT, an element without `=` in: %s\n", ports_env);
            return SIZE_MAX;
        }
		//ends up here.
        if ((t = h2o_strtosize(eq + 1, end - eq - 1)) == SIZE_MAX) {
            //fprintf(stderr, "invalid file descriptor number in $SERVER_STARTER_PORT: %s\n", ports_env);
            // Debug
			//fprintf(stderr, "With value %d \n", h2o_strtosize(eq + 1, end - eq - 1)); //Returns -1 :/
			return SIZE_MAX;
        }
        h2o_vector_reserve(NULL, (void *)&fds, sizeof(fds.entries[0]), fds.size + 1);
        fds.entries[fds.size++] = (int)t;
    }

    *_fds = fds.entries;
    return fds.size;
}

// Method will be used for uv_spawn exit
void waitpid(uv_process_t *req, int64_t exit_status, int term_signal) {
	fprintf(stderr, "Process exited with statu signal %lld\n", exit_status, term_signal);
	uv_close((uv_handle_t*)req, NULL);
//	*CHILD_RETURNED = TRUE;
}

pid_t h2o_spawnp(const char *cmd, char **argv, const int *mapped_fds, int cloexec_mutex_is_locked)
{
#if defined(__linux__)

    /* posix_spawnp of Linux does not return error if the executable does not exist, see
     * https://gist.github.com/kazuho/0c233e6f86d27d6e4f09
     */
    int pipefds[2] = {-1, -1}, errnum;
    pid_t pid;

    /* create pipe, used for sending error codes */
    if (pipe2(pipefds, O_CLOEXEC) != 0)
        goto Error;

    /* fork */
    if (!cloexec_mutex_is_locked)
        pthread_mutex_lock(&cloexec_mutex);
    if ((pid = fork()) == 0) {
        /* in child process, map the file descriptors and execute; return the errnum through pipe if exec failed */
        if (mapped_fds != NULL) {
            for (; *mapped_fds != -1; mapped_fds += 2) {
                if (mapped_fds[1] != -1)
                    dup2(mapped_fds[0], mapped_fds[1]); //child's output is redirected to stdout.
                close(mapped_fds[0]);
            }
        }
        execvp(cmd, argv);
        errnum = errno;
        write(pipefds[1], &errnum, sizeof(errnum));
        _exit(EX_SOFTWARE);
    }
    if (!cloexec_mutex_is_locked)
        pthread_mutex_unlock(&cloexec_mutex);
    if (pid == -1)
        goto Error;

    /* parent process */
    close(pipefds[1]);
    pipefds[1] = -1;
    ssize_t rret;
    errnum = 0;
    while ((rret = read(pipefds[0], &errnum, sizeof(errnum))) == -1 && errno == EINTR)
        ;
    if (rret != 0) {
        /* spawn failed */
        while (waitpid(pid, NULL, 0) != pid)
            ;
        pid = -1;
        errno = errnum;
        goto Error;
    }

    /* spawn succeeded */
    close(pipefds[0]);
    return pid;

Error:
    errnum = errno;
    if (pipefds[0] != -1)
        close(pipefds[0]);
    if (pipefds[1] != -1)
        close(pipefds[1]);
    errno = errnum;
    return -1;

#elif defined(_WIN32) //-- : process : https://msdn.microsoft.com/en-us/library/20y988d2.aspx
	
	pid_t pid;
	extern char** environ;
	uv_loop_t *loop;
	uv_process_t child_req;
	uv_process_options_t options = { 0 }; //-- Default initialization must be 0
	loop = uv_default_loop();
	//-- Container for file descruptor
	uv_stdio_container_t child_stdio[3];
	child_stdio[0].flags = UV_IGNORE;
	child_stdio[1].flags = UV_INHERIT_FD; //STD_OUT should be redirected to calling function
	child_stdio[2].flags = UV_IGNORE;

	if (mapped_fds != NULL) {
		for (; *mapped_fds != -1; mapped_fds += 2) {
			if (mapped_fds[1] != -1)
			     //dup2(mapped_fds[0], mapped_fds[1]); //Equivalent to dup2() in *inx systems.
				child_stdio[1].data.fd = mapped_fds[0]; //2 or 1?
			//close(mapped_fds[0]); //add or delete a close or open action to a spawn file actions object
		}
	}
	
	if (!cloexec_mutex_is_locked)
		uv_mutex_lock(&cloexec_mutex);
	
	options.stdio = child_stdio;
	options.exit_cb = waitpid; //This function will be executed when child exists.
	options.file = cmd;
	options.args = argv;
	options.env = environ;
	errno = uv_spawn(loop,&child_req,&options);
	pid = child_req.pid;


	if (!cloexec_mutex_is_locked)
		uv_mutex_unlock(&cloexec_mutex);
	if (errno != 0)
		return -1;


	return pid;

#else
	posix_spawn_file_actions_t file_actions;
	pid_t pid;
	extern char **environ;
	posix_spawn_file_actions_init(&file_actions); //Just initializes. 

	if (mapped_fds != NULL) {
		for (; *mapped_fds != -1; mapped_fds += 2) {
			if (mapped_fds[1] != -1)
				posix_spawn_file_actions_adddup2(&file_actions, mapped_fds[0], mapped_fds[1]); //Equivalent to dup2() in *inx systems.
			posix_spawn_file_actions_addclose(&file_actions, mapped_fds[0]); //add or delete a close or open action to a spawn file actions object
		}
	}

	if (!cloexec_mutex_is_locked)
		pthread_mutex_lock(&cloexec_mutex);
	errno = posix_spawnp(&pid, cmd, &file_actions, NULL, argv, environ); //find out what this does? and then write the code that you think should work.!
	if (!cloexec_mutex_is_locked)
		pthread_mutex_unlock(&cloexec_mutex);
	if (errno != 0)
		return -1;

	return pid;
#endif
}

int h2o_read_command(const char *cmd, char **argv, h2o_buffer_t **resp, int *child_status)
{
	int respfds[2] = {-1, -1};
    pid_t pid = -1;
    int mutex_locked = 0, ret = -1;

    h2o_buffer_init(resp, &h2o_socket_buffer_prototype);
	
    uv_mutex_lock(&cloexec_mutex);
    mutex_locked = 1;
	// Debug
	printf("In read command %s \n ", cmd);


    /* create pipe for reading the result */    
	#ifdef _WIN32
		if (_pipe(respfds, 4096, O_BINARY) == -1) //on fail
			//-- : Debug
			printf("Pipe Failed \n");
			goto Exit;
	#else
		if (pipe(respfds) != 0) //on fail
			goto Exit;
	#endif
	
	#ifndef _WIN32
    fcntl(respfds[0], F_SETFD, O_CLOEXEC); //On exit flag, not do-able in windows.
	#endif
	
	/* spawn */
    int mapped_fds[] = {respfds[1], 1, -1}; /* stdout of the child process is read from the pipe */
    
	if ((pid = h2o_spawnp(cmd, argv, mapped_fds, 1)) == -1)
		goto Exit;
	
	
	close(respfds[1]);
	respfds[1] = -1;

    uv_mutex_unlock(&cloexec_mutex);
    mutex_locked = 0;

    /* read the response from pipe */
    while (1) {
        h2o_iovec_t  buf = h2o_buffer_reserve(resp, 8192);
        ssize_t r;
#ifdef _WIN32
		while ((r = _read(respfds[0], buf.base, buf.len)) == -1 && errno == EINTR)
			;
#else
		while ((r = read(respfds[0], buf.base, buf.len)) == -1 && errno == EINTR)
			;
#endif
		if (r <= 0)
            break;
        (*resp)->size += r;
    }

Exit:
    if (mutex_locked)
        uv_mutex_unlock(&cloexec_mutex);

    if (pid != -1) {
        /* wait for the child to complete */
#ifndef _WIN32
		pid_t r;
		//seemingly no such mechanism exists to do it in using LibUV. :/ 

        while (waitpid(&pid, child_status, 0) == -1) && errno == EINTR)  : http://66.165.136.43/dictionary/waitpid-entry.php
            ;

		//while(*CHILD_RETURNED != TRUE)
        if (r == pid) {
            /* success */
            ret = 0;
			//*CHILD_RETURNED = FALSE;
        }
#else
		//Child return handling in windows!!
#endif
    }
	if (respfds[0] != -1)
#ifdef _WIN32
		_close(respfds[0]);
#else
		close(respfds[0]);
#endif
	if (respfds[1] != -1)
#ifdef _WIN32
		_close(respfds[1]);
#else
		close(respfds[1]);
#endif
    if (ret != 0)
        h2o_buffer_dispose(resp);

    return ret;
}

size_t h2o_numproc()
{
//For windows
#if defined (_WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return (size_t) sysinfo.dwNumberOfProcessors;
#endif
#if defined(_SC_NPROCESSORS_ONLN)
    return (size_t)sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(CTL_HW) && defined(HW_AVAILCPU)
    int name[] = {CTL_HW, HW_AVAILCPU};
    int ncpu;
    size_t ncpu_sz = sizeof(ncpu);
    if (sysctl(name, sizeof(name) / sizeof(name[0]), &ncpu, &ncpu_sz, NULL, 0) != 0 || sizeof(ncpu) != ncpu_sz) {
        fprintf(stderr, "[ERROR] failed to obtain number of CPU cores, assuming as one\n");
        ncpu = 1;
    }
    return ncpu;
#else
    return 1;
#endif
}
