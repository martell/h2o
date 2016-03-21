/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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

#include <fcntl.h> //To set flags.
#include "cloexec.h"

uv_mutex_t cloexec_mutex = UV_MUTEX_INITIALIZER;

static int set_cloexec(int fd)
{
	//It sets the close-on-exec flag for the file descriptor, which causes the 
	//file descriptor to be automatically (and atomically) closed when any of the exec-family functions succeed.
#ifndef _WIN32
	return fcntl(fd, F_SETFD, FD_CLOEXEC) != -1 ? 0 : -1;
#endif
	//return	ioctl(fd, FIOCLEX, 0);
	return 0; //When ever creating a socket, create it with WSA_SOCKET, and set the flag there itself. You can't seemingly set the flag once its already							//created as a socket.
}

/*
 * note: the socket must be in non-blocking mode, or the call might block while the mutex is being locked
 */

//Windows: referenced in evloop.c.h, while porting evloop take care of this.
int cloexec_accept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
    int fd = -1;
    uv_mutex_lock(&cloexec_mutex);

#ifdef __linux__ 
    if ((fd = accept(socket, addr, addrlen)) == -1) 
        goto Exit;
    if (set_cloexec(fd) != 0) {
        close(fd); 
        fd = -1;
        goto Exit;
    }
#else // Windows
	if ((fd = accept(socket, addr, addrlen)) == INVALID_SOCKET) //For windows SOCKET is something like "typedef unsigned int SOCKET;" 
		goto Exit; 
	// No way to set the flag!
	//if (set_cloexec(fd) != 0) {
	//	closesocket(fd); //close() as it is, is depracated by Visual studio, switching it to _close(), but the later expects a FileHandle again which is an int itself so should work.
	//	fd = -1;
	//	goto Exit;
	//}
#endif

Exit:
    uv_mutex_unlock(&cloexec_mutex);
    return fd;
}

int cloexec_pipe(int fds[2])
{
#ifdef __linux__
    return pipe2(fds, O_CLOEXEC); //on success 0 is returned.
#else
    int ret = -1;
    uv_mutex_lock(&cloexec_mutex);
	//pipe not a visual C function, instead using _pipe
    //if (pipe(fds) != 0) don't know what type of file exactly its supposed to read or write so assuming for now as to be an Text

	if (_pipe(fds, 4096, O_TEXT) != 0) 
        goto Exit;

    //if (set_cloexec(fds[0]) != 0 || set_cloexec(fds[1]) != 0)
        //goto Exit;
    ret = 0;

Exit:
    uv_mutex_unlock(&cloexec_mutex);
    return ret;
#endif
}

int cloexec_socket(int domain, int type, int protocol)
{
#ifdef __linux__
    return socket(domain, type | SOCK_CLOEXEC, protocol);
#else
    int fd = -1;
    uv_mutex_lock(&cloexec_mutex);

    
#ifdef _WIN32
	if ((fd = socket(domain, type, protocol)) == INVALID_SOCKET) 
		goto Exit;

  //  if (set_cloexec(fd) != 0) {
		//closesocket(fd);
  //      fd = -1;
  //      goto Exit;
  //  }
#else
	if ((fd = socket(domain, type, protocol)) == -1)
		goto Exit;
	if (set_cloexec(fd) != 0) {
		close(fd);
		closesocket(fd);
		fd = -1;
		goto Exit;
#endif
Exit:
    uv_mutex_unlock(&cloexec_mutex);
    return fd;
#endif
}
