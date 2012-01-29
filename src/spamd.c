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
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "milter.h"


int
spamd_getfd(const char *address, in_port_t port)
{
        struct sockaddr_in sa;
	int fd;
	int ret;
	int i;
	struct timeval tv;
	fd_set wset;
	socklen_t len;
	int valopt;


        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
  		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) |  O_NONBLOCK) < 0)
                return (-1);
  	
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(address);
        sa.sin_port = htons(port);

	if ((ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa))) < 0) {
		if (errno == EINPROGRESS) {
			for (i=0; i<3; i++) {

				tv.tv_sec = 10;
				tv.tv_usec = 0;

				FD_ZERO(&wset);
				FD_SET(fd, &wset);

				if ((ret = select(fd+1, NULL, &wset, NULL, &tv)) <= 0) {
					msg(LOG_INFO, "[spamd_getfd] connect failed %s (retry %d)\n", 
						(ret < 0) ? strerror(errno) : "(timeout)", i+1);

					/* giving another chance */
					if (ret == 0 || errno == EINTR)
						continue;
				}	

				if (FD_ISSET(fd, &wset)) {
					len = sizeof(int);	
					if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&valopt, &len) < 0 || valopt != 0) 
						goto failed;
				
					/* successful */
					return fd;
				}
			}
		} else 
			msg(LOG_ERR, "[spamd_getfd] error %s", strerror(errno));

failed:
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * http://svn.apache.org/repos/asf/spamassassin/branches/check_plugin/spamd/PROTOCOL
 */
int
spamd_prepare(const struct mmctx *mmctxp, const char *myhostname, const char *spamduser)
{
	char dtstr[128];

	if (mmctxp->spamassfd < 0 || fdwrite(mmctxp->spamassfd, "SYMBOLS SPAMC/1.2\r\n") < 0)
		return -1;

	if (spamduser != NULL && fdwrite(mmctxp->spamassfd, "User: %s\r\n", spamduser) < 0)
		return -1;

	if (fdwrite(mmctxp->spamassfd, "\r\n") < 0 ||
	    fdwrite(mmctxp->spamassfd, "Received: from %s (%s [%s])",
                mmctxp->helo, mmctxp->host, mmctxp->addr) < 0)
		return(-1);

	msg(LOG_DEBUG, "[spamd_prepare]: Received: from %s (%s [%s])", 
		mmctxp->helo, mmctxp->host, mmctxp->addr);

	if (myhostname != NULL && 
	    fdwrite(mmctxp->spamassfd, "\r\n\tby %s (%s)", myhostname, PACKAGE_NAME) < 0)
		return(-1);

	msg(LOG_DEBUG, "[spamd_prepare]: \tby %s (%s)", myhostname, PACKAGE_NAME);

	if (mmctxp->rcpt != NULL && 
		fdwrite(mmctxp->spamassfd, "\r\n\tfor %s", mmctxp->rcpt) < 0) 
		return(-1);

	time_t t = time(NULL);
	if (strftime(dtstr, sizeof(dtstr), "%a, %e %b %Y %H:%M:%S %z",
	    localtime(&t)) > 0 && fdwrite(mmctxp->spamassfd, "; %s", dtstr) < 0) 
		return(-1);

	msg(LOG_DEBUG, "[spamd_prepare]: \tfor %s; %s", mmctxp->rcpt, dtstr);

	return fdwrite(mmctxp->spamassfd, "\r\n");
} 

spam_t
spamd_reply(struct mmctx *mmctxp)
{
	int retries = 0;
	char b[8192];
	char bt[2048];
	struct timeval tv;
	fd_set rset;
	int ret;
	int i;
	int pos = 0;
	int state = 0;
	char *p;
	char decision[16];
	float score, threshold;
	spam_t result;

	ret = SPAM_UNCLEAR;

	if (shutdown(mmctxp->spamassfd, SHUT_WR) == -1) {
		msg(LOG_ERR, "[spamd_reply]: error shutdown() spamassfd: %s", strerror(errno));
                goto done;
        }

	while (retries < 5) {
		FD_ZERO(&rset);
		FD_SET(mmctxp->spamassfd, &rset);
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		if ((ret = select(mmctxp->spamassfd + 1, &rset, NULL, NULL, &tv)) < 0) {
			if (errno == EINTR)
				continue;
			else
				break;
		}

		if (ret == 0 || !FD_ISSET(mmctxp->spamassfd, &rset)) {
			retries++;
			continue;
		}

		if ((ret = read(mmctxp->spamassfd, b, sizeof(b))) <= 0) {
			if (ret < 0 && (errno == EINTR || errno == EWOULDBLOCK))
				continue;
			else
				break;
		}	

		for (i=0; i < ret; i++) {
			if (b[i] == '\n' || pos == sizeof(bt)-1) {
				if (pos > 0 && bt[pos - 1] == '\r')
					bt[pos-1] = '\0';
				else
					bt[pos] = '\0';				

				pos = 0;

				switch (state) {
					case 0:
						if (strncmp(bt, "SPAMD/", 6) != 0) {
							result = SPAM_FAIL;
							goto done;
						}
						
						p = bt + 6;
                				while (*p && *p != ' ')
                        				++p;
                				while (*p == ' ')
                        				++p;

						if (strncmp(p, "0 EX_OK", 7) != 0) {
							result = SPAM_FAIL;
							goto done;
						}
							
						state++;
						break;
					case 1:
						if (strncmp(bt, "Spam: ", 6) != 0) {
							result = SPAM_FAIL;
							goto done;
						}

						if (sscanf(bt + 6, "%15s ; %f / %f", decision,
                        				&score, &threshold) != 3) {
							result = SPAM_FAIL; 
							goto done;
						}
						if (strcasecmp(decision, "true") == 0) {
							result = SPAM_ISSPAM;
							mmctxp->isspam = 1;
						} else {
							result = SPAM_CLEAN;
							mmctxp->isspam = 0;
						} 

						mmctxp->threshold = threshold;
						mmctxp->score = score;
						state++;
						break;
					case 2:
						if (bt[0] == '\0')
							state++;
						else {
							result = SPAM_FAIL;
							goto done;
						}
						break;
					case 3:
						if ((mmctxp->symbols = strdup(bt)) == NULL) {
							result = SPAM_FAIL;
							goto done;
						}	
						break;
				}

			} else  
				bt[pos++] = b[i];
		}
	}	

done:
	if (mmctxp->spamassfd >= 0)
		spamd_cleanup(mmctxp);

	return result;
}

void
spamd_cleanup(struct mmctx *mmctxp)
{
	msg(LOG_DEBUG, "[spamd_cleanup] called");

	if (mmctxp != NULL && mmctxp->spamassfd >= 0)
	{
		msg(LOG_DEBUG, "[spamd_cleanup] closing descriptor %d", mmctxp->spamassfd);
		close(mmctxp->spamassfd);
		mmctxp->spamassfd = -1;
	}
}
