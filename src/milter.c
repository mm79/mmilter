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
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libmilter/mfapi.h"
#include "milter.h"


#define ADDRSTRLEN	INET6_ADDRSTRLEN


static sfsistat mm_header(SMFICTX *, char *, char *);
static sfsistat mm_envfrom(SMFICTX *, char **);
static sfsistat mm_envrcpt(SMFICTX *, char **);
static sfsistat mm_unknown(SMFICTX *, const char *);
static sfsistat mm_close(SMFICTX *);
static sfsistat mm_body(SMFICTX *, unsigned char *, size_t);
static sfsistat mm_eoh(SMFICTX *);
static sfsistat mm_eom(SMFICTX *);
static sfsistat mm_abort(SMFICTX *);
static sfsistat mm_data(SMFICTX *);
static sfsistat mm_negotiate(SMFICTX *, unsigned long, unsigned long, unsigned long, unsigned long,
        unsigned long *, unsigned long *, unsigned long *, unsigned long *);
static void cleanup(SMFICTX *, int); 
static void drop_priv(uid_t, gid_t);
static void usage(char *);

int debug;

static int headers;
static char *oconn = NULL;
static char *spamsubject = NULL;
static char *dropuser = NULL;
static char *dropgroup= NULL;
static size_t bodysize;
static mmilter_t mopt = -1;
static int lopt;
static float ropt;
static sfsistat spamderror = SMFIS_ACCEPT;
static int spamdport;
static char *spamdaddr;
static char *spamduser = NULL;


static void 
drop_priv(uid_t uid, gid_t gid)
{
        /* drop privileges */
        if (getuid() == 0) {
                if (setgroups(1, &gid) == -1) {
			fprintf(stderr, "setgroups: %s\n", strerror(errno));
			exit(1);
		}
                if (setgid(gid) == -1) {
                        fprintf(stderr, "setgid: %s\n", strerror(errno));
                        exit(1);
                }
		if (setuid(uid) == -1) {
                        fprintf(stderr, "setuid: %s\n", strerror(errno));
                        exit(1);
                }
        }

	if (setuid(0) != -1) {
                fprintf(stderr, "unable to drop privileges\n");
                exit(1);
        }
}

static void
cleanup(SMFICTX *ctx, int freecontext)
{
	struct mmctx *mmctxp;

	msg(LOG_DEBUG, "[cleanup] called with freecontext=%d", freecontext);

	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, "[cleanup] error getting private context");
		return;
	}

	if (mmctxp->symbols != NULL) {
		free(mmctxp->symbols);
		mmctxp->symbols = NULL;
	}

	if (mmctxp->subject != NULL) {
		free(mmctxp->subject);
		mmctxp->subject = NULL;
	}

	if (mmctxp->spamassfd != -1) 
		spamd_cleanup(mmctxp);

	mmctxp->bodysize = 0;
	mmctxp->gothdr = 0;
	mmctxp->threshold = 0;
	mmctxp->score = 0;
	mmctxp->isspam = 0;

	if (freecontext) {
		if (mmctxp->rcpt != NULL) 
			free(mmctxp->rcpt);
		if (mmctxp->helo != NULL) 
			free(mmctxp->helo);
		if (mmctxp->addr != NULL)
			free(mmctxp->addr);
		if (mmctxp->host != NULL)
			free(mmctxp->host);

		free(mmctxp);
		smfi_setpriv(ctx, NULL);
	}
}

static sfsistat
mm_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
	char addr[ADDRSTRLEN]; 
	struct mmctx *mmctxp;

	msg(LOG_DEBUG, "[mm_connect] called");

        if ((mmctxp = (struct mmctx *)calloc(1, sizeof(struct mmctx))) == NULL) 
		return SMFIS_TEMPFAIL;

	mmctxp->spamassfd = -1;

	if (smfi_setpriv(ctx, mmctxp) != MI_SUCCESS) {
		/* cleanup() can't free mmctxp if smfi_setpriv() fails */
		free(mmctxp);
		return SMFIS_TEMPFAIL; 
	}

	strncpy(addr, "unknown", sizeof(addr)-1);
	/* ADDRSTRLEN < "unknown" is almost impossible anyway... */
	addr[sizeof(addr)-1] = '\0';

	if (hostaddr != NULL) {
		switch (hostaddr->sa_family) {
			case AF_INET: 
			{ 
				struct sockaddr_in *sin = 
					(struct sockaddr_in *)hostaddr;
				
				inet_ntop(AF_INET, &sin->sin_addr.s_addr, addr,
					INET_ADDRSTRLEN);
			}
			break;
			case AF_INET6:
			{
				struct sockaddr_in6 *sin6 = 
					(struct sockaddr_in6 *)hostaddr;	

				inet_ntop(AF_INET, &sin6->sin6_addr, addr,
					INET6_ADDRSTRLEN);
			}
			break;
		}
	}

	if ((mmctxp->addr = strdup(addr)) == NULL || 
		(mmctxp->host = strdup(hostname)) == NULL) 
		return SMFIS_TEMPFAIL;

	return SMFIS_CONTINUE;
}

static sfsistat
mm_helo(SMFICTX *ctx, char *helohost)
{
	struct mmctx *mmctxp;

	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL)
		return SMFIS_TEMPFAIL;

	/*
	 * according to xxfi_helo(): 
	 * It may be called several times or even not at all
	 */
	if (mmctxp->helo != NULL) {
		free(mmctxp->helo);
		mmctxp->helo = NULL;
	}

	if ((mmctxp->helo = strdup(helohost)) == NULL) {
		/*
		 * we are in a connection-oriented routine by returning 
		 * SMFIS_TEMPFAIL
		 * xxfi_close() will be called and memory for mmctxp freed
		 */ 
		return SMFIS_TEMPFAIL;
	} 

	return SMFIS_CONTINUE;
}

static sfsistat
mm_envfrom(SMFICTX *ctx, char **argv)
{
        return SMFIS_CONTINUE;
}

/*
 * called once per recipient
 */
static sfsistat
mm_envrcpt(SMFICTX *ctx, char **argv)
{
	struct mmctx *mmctxp;

	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL)
		return SMFIS_TEMPFAIL;

	/*
         * argv[0] is guaranteed to be the recipient address and null terminated
	 */
	if (*argv != NULL) {
		if (mmctxp->rcpt != NULL) { 
			free(mmctxp->rcpt);
			mmctxp->rcpt = NULL;
		}

		if ((mmctxp->rcpt = strdup(argv[0])) == NULL)
			return SMFIS_TEMPFAIL;
	}

	return SMFIS_CONTINUE;
}

/*
 * called once for each message header
 */
static sfsistat
mm_header(SMFICTX *ctx, char *headerf, char *headerv)
{
        struct mmctx *mmctxp;

	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL)
		return SMFIS_TEMPFAIL;

	/*
	 * we open spamassfd here (instead of data callback) because in postfix
	 * milter_content_timeout is 300s by default (eoh) and 
	 * milter_command_timeout is 30s (data)
	 * so we have enough time to retry 3 spamassassin connection
	 */ 
	if (mmctxp->spamassfd < 0) {
		char *myhostname = smfi_getsymval(ctx, "j");

	        if ((mmctxp->spamassfd = spamd_getfd(spamdaddr, spamdport)) < 0) 
                	return spamderror;

 	       	if (spamd_prepare(mmctxp, myhostname, spamduser) < 0) {
		       msg(LOG_ERR, "[mm_header] spamd_prepare() error");
        	       spamd_cleanup(mmctxp);

 	               return spamderror;
        	}
	}

	mmctxp->gothdr++;

	if (strcasecmp(headerf, "Subject") == 0 && mmctxp->subject == NULL &&
	    (mmctxp->subject = strdup(headerv)) == NULL) 
		return SMFIS_TEMPFAIL;

	if (fdwrite(mmctxp->spamassfd, "%s: %s\r\n", headerf, headerv) < 0) {
		msg(LOG_ERR, "[mm_header] error writing %s field\n", headerf);
		spamd_cleanup(mmctxp);

		return spamderror;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
mm_eoh(SMFICTX *ctx)
{
	struct mmctx *mmctxp;
       
	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL)
		return SMFIS_TEMPFAIL;

	/* 	
	 * if there are no headers in mail and spamderror is set to 
	 * SMFIS_TEMPFAIL we avoid to spend sender resources and our too..
	 */
	if (mmctxp->spamassfd < 0) { 
		if (spamderror == SMFIS_TEMPFAIL && !mmctxp->gothdr) {
			smfi_setreply(ctx, "554", "5.7.1", "no headers sent");

			return SMFIS_REJECT;
		}
		
		return spamderror;
	}

        if (fdwrite(mmctxp->spamassfd, "\r\n") != 2) {
		msg(LOG_ERR, "[mm_eoh] unable to send eoh to spamd");
		spamd_cleanup(mmctxp);

		return spamderror;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
mm_body(SMFICTX *ctx, unsigned char *chunk, size_t size)
{
	struct mmctx *mmctxp;
	ssize_t n;

	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL)
		return SMFIS_TEMPFAIL;

	if (mmctxp->spamassfd < 0)  
		return spamderror;	

	/* limit body size for spamd to approximately bodysize */ 
	if (bodysize > 0 && mmctxp->bodysize >= bodysize)
		/* XXX: time to implement SMFIS_SKIP ? */
		return SMFIS_CONTINUE;

        mmctxp->bodysize += size;

	if ((n = writen(mmctxp->spamassfd, chunk, size)) < 0) {
		msg(LOG_ERR, "[mm_body] error writen() to spamd: %s)", 
			strerror(errno));

		spamd_cleanup(mmctxp);

		return spamderror;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
mm_eom(SMFICTX *ctx)
{
        struct mmctx *mmctxp;
	sfsistat action = SMFIS_ACCEPT;
	
	msg(LOG_DEBUG, "[mm_eom] called");

	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL)
		return SMFIS_TEMPFAIL;

	if (mmctxp->spamassfd < 0)
		return spamderror;

	spam_t reply = spamd_reply(mmctxp);

	if (reply == SPAM_FAIL || reply == SPAM_UNCLEAR) {
		msg(LOG_ERR, "[mm_eom] spamd_reply returns %s", 
			(reply == SPAM_FAIL) ? "fail" : "unclear");
		return spamderror; 
	}

	if (mopt == MMILTER_DISCARD)
		action = SMFIS_DISCARD;
	else {
		if (mopt == MMILTER_REJECT || (ropt > 0 && mmctxp->score > ropt)) {
			smfi_setreply(ctx, "554", "5.7.1", "no spam please");

			action = SMFIS_REJECT;
		}
	}

	if (mmctxp->isspam) {
		if (lopt) {
			char *mailaddr = smfi_getsymval(ctx, "{mail_addr}");
			char *sact; 

			switch (action) {
				case SMFIS_ACCEPT:
					sact = "tag"; 
					break;
				case SMFIS_REJECT:
					sact = "reject";
					break;
				case SMFIS_DISCARD:
					sact = "drop";
					break;
			}
				
			msg(LOG_NOTICE, "from: %s to %s  [score: %.1f/%.1f, action: %s, bs: %zu, sym: %s]",
				(mailaddr == NULL) ? "unknown" : mailaddr,
				mmctxp->rcpt, mmctxp->score, mmctxp->threshold, sact, 
				mmctxp->bodysize, mmctxp->symbols);  
		}

		if (action != SMFIS_ACCEPT)
			return action;

		if (spamsubject != NULL) {
			char subj[2048];

			snprintf(subj, sizeof(subj), "%s ", spamsubject);

			if (mmctxp->subject != NULL) { 
				/* leaving space for null */
				if (strlen(subj) + strlen(mmctxp->subject) < sizeof(subj)) { 
					strncat(subj, mmctxp->subject, sizeof(subj)-1);
					subj[sizeof(subj)-1] = '\0';

					smfi_chgheader(ctx, "Subject", 1, subj);
				}
			} else  
				smfi_addheader(ctx, "Subject", subj);
		}
	}

	if (headers) {
		char tests[2048];
		char spamlvl[100];
		int line = 70;
		char testfield[] = " tests=";
		char prefield[] = "\n       ";
		char *psym = mmctxp->symbols;
		int cut = 0;
		int opos;  
		int len;
		int preline;
		int i = 0;


		if (smfi_chgheader(ctx, "X-Spam-Flag", 1, 
			mmctxp->isspam ? "YES" : "NO") == MI_FAILURE)
				smfi_addheader(ctx, "X-Spam-Flag", mmctxp->isspam ? "YES" : "NO"); 

		while (i <= ((int)mmctxp->score)-1 && i < sizeof(spamlvl)-1) 
			spamlvl[i++] = '*'; 
		spamlvl[i] = '\0';

		if (smfi_chgheader(ctx, "X-Spam-Level", 1, spamlvl) == MI_FAILURE) 
			smfi_addheader(ctx, "X-Spam-Level", spamlvl);

		snprintf(tests, sizeof(tests), "%s, score=%.1f required=%.1f\n", 
			mmctxp->isspam ? "Yes" : "No", mmctxp->score, mmctxp->threshold); 

		opos = strlen(tests);
		preline = strlen(testfield);

		if (*psym != '\0' && opos+preline+1 < sizeof(tests)) {
			strncat(tests, testfield, sizeof(tests)-1);
			tests[sizeof(tests)-1] = '\0';

			while (*psym != '\0') {
				if (cut > 0) {
					strncat(tests, prefield, sizeof(tests-1));
					tests[sizeof(tests)-1] = '\0';
					preline = strlen(prefield);
				}
					
				/* getting last symbol for this line */
				for (i=0, cut =0; psym[i] != '\0' && i<(line - preline); i++) 
					if (psym[i] == ',')
						cut = i;

				/* adding ',' if not end of string */
				cut = psym[i] == '\0' ? i : cut + 1;

				len = strlen(tests);

				if (len+cut+1 <= sizeof(tests)) { 
					memcpy(tests+len, psym, cut);
					tests[len+cut] = '\0';
				} else {
					/* delete \n (rollback) */
					tests[opos-1] = '\0';
					break;
				}

				psym += cut; 
			}	
		}

		if (smfi_chgheader(ctx, "X-Spam-Status", 1, tests) == MI_FAILURE)
			smfi_addheader(ctx, "X-Spam-Status", tests);

	}

	return SMFIS_CONTINUE;
}

static sfsistat
mm_abort(SMFICTX *ctx)
{
	struct mmctx *mmctxp;
	
	msg(LOG_DEBUG, "[mm_abort] called");
	
	/*
	 * we call cleanup with freecontext=0 by leaving connection
	 * variables allocated 
	 */
	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) != NULL)
		cleanup(ctx, 0);

	return SMFIS_CONTINUE;
}

static sfsistat
mm_close(SMFICTX *ctx)
{
	struct mmctx *mmctxp;

	msg(LOG_DEBUG, "[mm_close] called");
	
	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) != NULL)
		cleanup(ctx, 1);
	
	return SMFIS_CONTINUE;
}

static sfsistat
mm_data(SMFICTX *ctx)
{
	struct mmctx *mmctxp;
	int i = 0;

	msg(LOG_DEBUG, "[mm_data] called");
	
	if ((mmctxp = (struct mmctx *)smfi_getpriv(ctx)) == NULL)
		return SMFIS_TEMPFAIL;

	/* cleaning fields for new mail */
	cleanup(ctx, 0);

	return SMFIS_CONTINUE;
}

static sfsistat
mm_unknown(SMFICTX *ctx, const char *cmd)
{
        return SMFIS_CONTINUE;
}

static sfsistat
mm_negotiate(SMFICTX *ctx, unsigned long f0, unsigned long f1, unsigned long f2, unsigned long f3, unsigned long *pf0, unsigned long *pf1, unsigned long *pf2, unsigned long *pf3)
{
	return SMFIS_ALL_OPTS;
}

static struct 
smfiDesc mmfilter =
{
	PACKAGE_NAME,
	SMFI_VERSION,
	SMFIF_ADDHDRS|SMFIF_CHGHDRS,
	mm_connect,
	mm_helo,
	mm_envfrom,
	mm_envrcpt,
	mm_header,
	mm_eoh,
	mm_body,
	mm_eom,
	mm_abort,
	mm_close,
	mm_unknown,
	mm_data,
	mm_negotiate	
};

static void
mmilter_opts(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "a:b:de:g:hlm:p:r:s:u:U:")) != -1) 
		switch (ch) {
			case 'a':
			{	
				char *pos = NULL;

				if ((pos = strchr(optarg, ':')) == NULL || *(pos + 1) == '\0' || 
				     (spamdport = (int)strtol(pos+1, (char **)NULL, 10)) == 0) {
					fprintf(stderr, "Unable to parse port in -a parameter %d\n", spamdport);	
					exit(1);
				}

				if ((spamdaddr = strndup(optarg, pos - optarg)) == NULL) {
					fprintf(stderr, "Error strdup() in -a parameter (host)\n");
					exit(1);
				}

				break;
			}
			case 'b':
				if (sscanf(optarg, "%zu", &bodysize) != 1) {
					fprintf(stderr, "Unable to parse -b size\n");
					exit(1);	
				} 

				break;
			case 'd':
				debug++;
				break;
			case 'e':
				if (strcmp(optarg, "accept") != 0 && 
				    strcmp(optarg, "tempfail") != 0)
				{
					fprintf(stderr, "invalid -e paramater\n");
					exit(1);
				}
			
				if (strcmp(optarg, "tempfail") == 0)
					spamderror = SMFIS_TEMPFAIL;			
				
				break;
			case 'g':
				dropgroup = optarg;
				break;
			case 'h':
				headers++;
				break;
			case 'l':
				lopt++;
				break;
			case 'm':
				if (strcmp(optarg, "reject") == 0)
					mopt = MMILTER_REJECT;
				else {
					if (strcmp(optarg, "discard") == 0)
						mopt = MMILTER_DISCARD;
					else {
						if (strcmp(optarg, "tag") == 0) {
							mopt = MMILTER_TAG;
							headers++;
						}
					}
				}
				if (mopt == -1) {
					fprintf(stderr, "unknown -m type\n");
					exit(1);
				}
				break;
			case 'p':
				if (strncmp(optarg, "unix:", 5) != 0 &&
				    strncmp(optarg, "local:", 6) != 0 &&
				    strncmp(optarg, "inet:", 5) != 0 &&
				    strncmp(optarg, "inet6:", 6) != 0 &&
				    *optarg != '/') {
					fprintf(stderr, "error in -p parameter: unknown communication socket\n"
							"If you mean a local socket please use absolute path\n");
					exit(1);
				}
				if (*optarg == '/') 
				{
					int len = sizeof("local:") + strlen(optarg) + 1;

					if ((oconn = (char *)malloc(len)) == NULL) { 
						fprintf(stderr, "unable to allocate memory for %s\n", optarg);
						exit(1);
					}
		
					snprintf(oconn, len, "local:%s", optarg);
				} else { 
					oconn = optarg;
				}
				break;
			case 'r':
				if (sscanf(optarg, "%f", &ropt) != 1|| ropt <= 0) {
					fprintf(stderr, "invalid -r parameter %d\n", ropt);
					exit(1);
				}
				break;
			case 's':
				spamsubject = optarg;
				headers++;
				break;
			case 'u':
				dropuser = optarg;
				break;
			case 'U':
				spamduser = optarg;
				break;
			default:
				usage(argv[0]);
		}


	if (dropuser == NULL || dropgroup == NULL || oconn == NULL || mopt == -1)
		usage(argv[0]);

	if (spamdaddr == NULL) {
		struct servent *sp;

		spamdaddr = "127.0.0.1";
		spamdport = ((sp = getservbyname("spamd", "tcp")) == NULL) ? 783 : htons(sp->s_port);
	
		if (spamdport != 783)
			fprintf(stdout, "Trying %s with port %d as spamd server (use -a ipaddr:port to overwrite this behaviour)\n", spamdaddr, spamdport);
	}
}

static void
usage(char *name)
{
        printf( "%s\n\n"
		"usage: "
                "%s -m {tag, reject, discard} -u username -g groupname -p socket [-a address:port] [-b size] [-r threshold] [-e {accept,tempfail}] [-d] [-h] [-l] [-s subjtag] [-U username]\n\n"
	 	"* -u username .. drop privileges to this username\n"
		"* -g groupname .. drop privileges to this group name\n"
		"* -p sockpath .. socket path\n"
		"* -m mode .. {tag, reject, discard}\n" 
		"\n"
		"! -a address:port connect to this ip address / port\n"
		"! -b size ..  limit body size for spamd approximately to size value +/- 1 smfi_body() chunk\n" 
		"  -d .. debug mode\n"
		"  -e {accept, tempfail} what to do when there is a communication problem with spamd while processing a message\n\t(default behaviour: accept)\n"
		"  -l log spam messages to syslog\n"
		"  -h .. add spam headers for each message\n"
		"  -r threshold reject messages if spam score is >= threshold (useful only in tag mode)\n" 
		"  -s tagname ... tag spam message with tagname in the subject (ex. [SPAM])\n" 	
		"  -U username .. pass this username to spamd\n"
		"\n\n! = recommended\n",
			PACKAGE_STRING, name);
        exit(0);
}

inline void
msg(int priority, const char *fmt, ...)
{
	char msg[2048];
	va_list ap;

	if (priority == LOG_DEBUG && !debug)
		return; 

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);

	if (debug)
		printf("%s\n", msg);
	else
		syslog(priority, "%s", msg);

	va_end(ap);
} 

int 
main(int argc, char *argv[])
{
	sfsistat r;
	struct passwd *pw;
	struct group *gr;
	char *filename;
	int islocal = 0;
	mode_t msk;

	mmilter_opts(argc, argv);

	if ((pw = getpwnam(dropuser)) == NULL) {
		fprintf(stderr, "Unable to find user %s\n", dropuser);
		exit(1);
	}

	if ((gr = getgrnam(dropgroup)) == NULL) {
		fprintf(stderr, "Unable to find group %s\n", dropgroup);
		exit(1);
	}
	
	if (smfi_setconn(oconn) != MI_SUCCESS) {
                fprintf(stderr, "smfi_setconn: %s: failed\n", oconn);
		exit(1);
        }

	if (smfi_register(mmfilter) != MI_SUCCESS) {
                fprintf(stderr, "smfi_register: failed\n");
		exit(1);
        }

	if (smfi_opensocket(1) == MI_FAILURE) {
		fprintf(stderr, "smfi_opensocket: failed\n");
		exit(1); 
	}

	if (strncmp(oconn, "unix:", 5) == 0 ||
	    strncmp(oconn, "local:", 6) == 0) {
		filename = oconn + (*oconn == 'u' ? 5 : 6);
		islocal = 1;
	} else {
		if (*oconn == '/')
			islocal = 1;
	}	

	if (islocal) {
		if (chown(filename, pw->pw_uid, gr->gr_gid) < 0) {
			fprintf(stderr, "chown(): %s\n", strerror(errno));
			exit(1);
		}
                if (chmod(filename, 0760) < 0) {
			fprintf(stderr, "chmod(): %s\n", strerror(errno));
			exit(1);
		}
	}

	drop_priv(pw->pw_uid, gr->gr_gid);

    	if (!debug && daemon(0, 0) != 0) {
                fprintf(stderr, "daemon: %s\n", strerror(errno));
		exit(1);
        }

	/* catching the signal to avoid being involuntary terminated */
        signal(SIGPIPE, SIG_IGN);

        if ((r = smfi_main()) != MI_SUCCESS) {
		msg(LOG_ERR, "error calling smfi_main(): %s\n", 
			strerror(errno));
		exit(1);
	}

	return 0;
}
