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


typedef enum spam_t {   SPAM_UNCLEAR, SPAM_FAIL, SPAM_CLEAN, SPAM_ISSPAM        } spam_t;
typedef enum mmilter_t {	MMILTER_REJECT, MMILTER_DISCARD, MMILTER_TAG } mmilter_t ;

struct mmctx {
        char *addr;
        char *host;
        char *helo;
        char *rcpt;
	char *subject;
        int spamassfd;
	int gothdr;
	float threshold;
	float score;
	char *symbols;
	int isspam;
	size_t bodysize; /* bodysize sent to spamd */
};

extern int debug;

/* milter.c */
inline void msg(int, const char *, ...);

/* spamd.c */
int spamd_getfd(const char *, in_port_t);
int spamd_prepare(const struct mmctx *, const char *, const char *);
void spamd_cleanup(struct mmctx *);
spam_t spamd_reply(struct mmctx *);

/* fdutil.c */
ssize_t writen(int, const void *, size_t);
ssize_t fdwrite(int fd, const char *, ...);

