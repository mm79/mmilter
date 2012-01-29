/*
 * Copyright (c) 2011 Matteo Mazzarella <matteo@dancingbear.it>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


ssize_t
writen(int fd, const void *vptr, size_t n)
{
	struct timeval tv;
	fd_set wset;
	int r;
	size_t nleft;
	ssize_t nwritten;
	const char *ptr;

	ptr = vptr;
	nleft = n;
	
	while (nleft > 0) {
		FD_ZERO(&wset);
		FD_SET(fd, &wset);
 		tv.tv_sec = 10;
                tv.tv_usec = 0;

		r = select(fd+1, NULL, &wset, NULL, &tv);

		/* timeout reached*/
		if (r == 0 || !FD_ISSET(fd, &wset)) {
			return -1;
	 	} else {
			if (r < 0 && errno == EINTR)
				continue;	
		}

		if ((nwritten = write(fd, ptr, nleft)) < 0) {
			/* it shouldn't happen ... anyway */
			if (errno == EINTR || errno == EWOULDBLOCK)
				continue;

			return -1;
		}

		nleft -= nwritten;
		ptr += nwritten;
	}

	return (n);
}

ssize_t
fdwrite(int fd, const char *fmt, ...)
{
        va_list ap;
        char s[2048];

        va_start(ap, fmt);
        vsnprintf(s, sizeof(s), fmt, ap);
        va_end(ap);

        return writen(fd, s, strlen(s));
}
