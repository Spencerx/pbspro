/*
 * Copyright (C) 1994-2019 Altair Engineering, Inc.
 * For more information, contact Altair at www.altair.com.
 *
 * This file is part of the PBS Professional ("PBS Pro") software.
 *
 * Open Source License Information:
 *
 * PBS Pro is free software. You can redistribute it and/or modify it under the
 * terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Commercial License Information:
 *
 * For a copy of the commercial license terms and conditions,
 * go to: (http://www.pbspro.com/UserArea/agreement.html)
 * or contact the Altair Legal Department.
 *
 * Altair’s dual-license business model allows companies, individuals, and
 * organizations to create proprietary derivative works of PBS Pro and
 * distribute them - whether embedded or bundled with other software -
 * under a commercial license agreement.
 *
 * Use of Altair’s trademarks, including but not limited to "PBS™",
 * "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
 * trademark licensing policies.
 *
 */

/**
 * @file tcp_dis.c
 *
 * @brief
 *	TCP DIS related functions (used by both the client side and server side
 *	calls)
 *
 * @warning
 *
 * Functions in this file are NOT thread safe. If multiple threads
 * call different functions simultaneously with the same fd, the
 * it will corrupt global data.\n
 *
 * Thread safety has to be ensured at the caller level.\n
 *
 * In this case the the client connection layer is synchronized on
 * each connection, so multiple theads calling these routines from the IFL is
 * okay. The connection lock (ch_mutex) used by upper level callers
 * (from IFL API).\n
 *
 * @see tcp_get_readbuf\n tcp_get_writebuf
 * These routines are synchronized using the tcp lock (global lock) so that
 * access to the global array of read/write buffers (struct tcp_chan **)
 * is synchronized.
 *
 * Calls to these routines from the daemons are not synchronized currently as
 * the daemons are single threaded.
 *
 */



#include <pbs_config.h>   /* the master config generated by configure */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include "libpbs.h"
#include "libsec.h"
#include "rpp.h"

#include <poll.h>

#include "dis.h"
#include "dis_init.h"

#include "pbsgss.h"

#define THE_BUF_SIZE 1024

struct tcpdisbuf {
	size_t	tdis_lead;
	size_t	tdis_trail;
	size_t	tdis_eod;
	size_t	tdis_bufsize;
	char	*tdis_thebuf;
};

struct	tcp_chan {
	struct	tcpdisbuf	readbuf;
	struct	tcpdisbuf	writebuf;

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)
        struct tcpdisbuf gssrdbuf;   /* incoming wrapped data */
        gss_buffer_desc  unwrapped;  /* release after copying to readbuf */
        gss_ctx_id_t     gssctx;     /* GSS context */
        int              Confidential;        /* (boolean) */
#endif
};

/* resize of following global variables are protected by a mutex */
static int			tcparraymax = 0;
static struct	tcp_chan	**tcparray = NULL;

/**
 * @brief
 *	Synchronize access to readbuf location
 *
 * @par Functionality:
 *	This routine is used by all other (read) routines to synchronously
 *	retrieve the location of the tcp read buffer for the supplied fd. It
 *	uses the tcp lock (defined in pbs_client_thread.c) to synchronize
 *	access to the array of tcp_chans.\n
 *
 *	The reason that this has to be synchronized, is that the global array of
 *	read/write buffers (struct tcp_chan **) could be realloc'd by routine
 *	@see DIS_tcp_setup - resulting in the whole array to get relocated
 *	elsewhere in memory. However, while the whole array can be relocated
 *	the individual pointers in the array continue to point to the same
 *	address of the read/write buffers. Thus only the point of access to the
 *	global array is synchronized, not the actual read/writes using the
 *	retrieved read/write buffers.
 *
 * @param[in] fd - The file handle for the socket for which the buffer is to be
 *		   accessed
 *
 * @retval - address of the read buffer to use for readers
 *
 * @par Side-effects:
 *	Uses assert to ensure that the buffer address retrieved is not NULL
 */
struct tcpdisbuf * tcp_get_readbuf(int fd)
{
	struct	tcpdisbuf	*tp;
	int rc;

	rc = pbs_client_thread_lock_tcp();
	assert(rc == 0);
	tp = &tcparray[fd]->readbuf;
	rc = pbs_client_thread_unlock_tcp();
	assert(rc == 0);

	assert(tp != NULL);
	return (tp);
}

/**
 * @brief
 *	Synchronize access to writebuf location
 *
 * @par Functionality:
 *	This routine is used by all other (write) routines to synchronously
 *	retrieve the location of the tcp write buffer for the supplied fd. It
 *	uses the tcp lock (defined in pbs_client_thread.c) to synchronize
 *	access to the array of tcp_chans.\n
 *
 *	The reason that this has to be synchronized, is that the global array of
 *	read/write buffers (struct tcp_chan **) could be realloc'd by routine
 *	@see DIS_tcp_setup - resulting in the whole array to get relocated
 *	elsewhere in memory. However, while the whole array can be relocated
 *	the individual pointers in the array continue to point to the same
 *	address of the read/write buffers. Thus only the point of access to the
 *	global array is synchronized, not the actual read/writes using the
 *	retrieved read/write buffers.
 *
 * @param[in] fd - The file handle for the socket for which the buffer is to be
 *		   accessed
 *
 * @retval - address of the write buffer to use for writers
 *
 * @par Side-effects:
 *	Uses assert to ensure that the buffer address retrieved is not NULL
 */
struct tcpdisbuf * tcp_get_writebuf(int fd)
{
	struct	tcpdisbuf	*tp;
	int rc;

	rc = pbs_client_thread_lock_tcp();
	assert(rc == 0);
	tp = &tcparray[fd]->writebuf;
	rc = pbs_client_thread_unlock_tcp();
	assert(rc == 0);

	assert(tp != NULL);
	return (tp);
}


/**
 * @brief
 * 	-tcp_pack_buff - pack existing data into front of buffer
 *
 *	Moves "uncommited" data to front of buffer and adjusts pointers.
 *	Does a character by character move since data may over lap.
 * 
 * @param[in] tp - tcp data buffer
 *
 * @return	Void
 *
 */

static void
tcp_pack_buff(struct tcpdisbuf *tp)
{
	size_t amt;
	size_t start;
	size_t i;

	start = tp->tdis_trail;
	if (start != 0) {
		amt  = tp->tdis_eod - start;
		for (i=0; i<amt; ++i) {
			*(tp->tdis_thebuf + i) =
				*(tp->tdis_thebuf + i + start);
		}
		tp->tdis_lead  -= start;
		tp->tdis_trail -= start;
		tp->tdis_eod   -= start;
	}
}


/**
 * @brief
 * 	-tcp_buff_resize - resize existing buffer
 *
 * 
 * @param[in] tp - tcp data buffer
 *
 * @return	int
 * @retval	0 on success
 * @retval	-1 on error
 */
static int tcp_buff_resize(struct tcpdisbuf *tp, size_t newsize)
{
	/* no need to lock mutex here, this is per fd resize
	 * needing a larger buffer area for the data */

	char *newbuf = realloc(tp->tdis_thebuf, newsize);

	if (newbuf != NULL)
	{
		tp->tdis_bufsize = newsize;
		tp->tdis_thebuf = newbuf;
		return 0;
	} else {
		return -1;
	}
}

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)

/**
 * @brief
 * 	-tcp_get_confidential_flag - check whether associated connection should
 *	be treated as confidential
 *
 * 
 * @param[in] fd - socket descriptor
 *
 * @return	int
 * @retval	True if confidential
 * @retval	0 otherwise
 */
static int tcp_get_confidential_flag(int fd)
{
    int conf;
    int rc;

    rc = pbs_client_thread_lock_tcp();
    assert(rc == 0);
    conf = tcparray[fd]->Confidential;
    rc = pbs_client_thread_unlock_tcp();
    assert(rc == 0);

    return conf;
}

/**
 * @brief
 * 	-tcp_get_decryptbuf - get decrypt buffer associated with connection.
 *	This buffer is used for unwrapped message.
 *
 * @param[in] fd - socket descriptor
 *
 * @return	gss_buffer_desc
 * @retval	decrypt buffer
 */
static gss_buffer_desc * tcp_get_decryptbuf(int fd)
{
    gss_buffer_desc *tp;
    int rc;

    rc = pbs_client_thread_lock_tcp();
    assert(rc == 0);
    tp = &tcparray[fd]->unwrapped;
    rc = pbs_client_thread_unlock_tcp();
    assert(rc == 0);

    assert(tp != NULL);
    return (tp);
}

/**
 * @brief
 * 	-tcp_get_encryptbuf - get encrypt buffer associated with connection.
 *	This buffer is used for wrapped message.
 *
 * @param[in] fd - socket descriptor
 *
 * @return	tcpdisbuf
 * @retval	encrypt buffer
 */
static struct tcpdisbuf * tcp_get_encryptbuf(int fd)
{
    struct	tcpdisbuf	*tp;
    int rc;

    rc = pbs_client_thread_lock_tcp();
    assert(rc == 0);
    tp = &tcparray[fd]->gssrdbuf;
    rc = pbs_client_thread_unlock_tcp();
    assert(rc == 0);

    assert(tp != NULL);
    return (tp);
}

/**
 * @brief
 * 	-tcp_get_seccontext - get security context associated with connection.
 *
 * @param[in] fd - socket descriptor
 *
 * @return	gss_ctx_id_t
 * @retval	security context
 */
static gss_ctx_id_t tcp_get_seccontext(int fd)
{
    gss_ctx_id_t    sec_ctx;
    int rc;

    rc = pbs_client_thread_lock_tcp();
    assert(rc == 0);
    sec_ctx = tcparray[fd]->gssctx;
    rc = pbs_client_thread_unlock_tcp();
    assert(rc == 0);

    return (sec_ctx);
}

/**
 * @brief
 * 	-tcp_fillbuffer - fill in tcp buffer from gss buffer
 *
 * @param[out] to - tcp buffer to be filled in
 * @param[in] from - gss buffer - source of data
 *
 * @return	int
 * @retval	length of remaining data
 */
static int tcp_fillbuffer(struct tcpdisbuf *to, gss_buffer_desc *from)
{
    size_t remaining_data = from->length;
    OM_uint32 minor;

    if (remaining_data == 0)
        return 0;

    tcp_pack_buff(to);

    ssize_t remaining_cap = to->tdis_bufsize - to->tdis_eod;
    if ((size_t)remaining_cap < remaining_data) // remove first f bytes from unwrapped values
      {
      tcp_buff_resize(to, remaining_data - remaining_cap + to->tdis_bufsize);
      remaining_cap = remaining_data;
      }
    memcpy(&to->tdis_thebuf[to->tdis_eod], from->value, remaining_data);
    to->tdis_eod += remaining_data;
    gss_release_buffer(&minor, from);
    return remaining_data;	/* for simplicity */
}

/**
 * @brief
 * 	-raw_timed_read - read data from socket if any available
 *
 * @param[in]  fd	- socket descriptor
 * @param[out] buff	- buffer to be read into
 * @param[in]  max_size	- maximum amount of data
 * @param[in]  timeout_sec - timeout in seconds
 *
 * @return int
 * @retval >0 number of characters read
 * @retval 0  no data on socket
 * @retval -1 system error
 */
static int raw_timed_read(int fd, char *buff, size_t max_size, int timeout_sec)
{
	struct	pollfd pollfds[1];
	int i;

	/*
	 * we don't want to be locked out by an attack on the port to
	 * deny service, so we time out the read, the network had better
	 * deliver promptly
	 */
	do {
		pollfds[0].fd = fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		i = poll(pollfds, 1, timeout_sec * 1000);
		if (i == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (pbs_tcp_interrupt)
			break;
	} while ((i == -1) && (errno == EINTR));

	if (i <= 0) // no data on socket or error
		return i;

	while ((i = read(fd, buff, max_size)) == -1) {

		if (errno != EINTR)
			break;
	}

	return i;
}

/**
 * @brief
 * 	-tcp_read_buff - read data from tcp stream to "fill" the buffer
 *	Update the various buffer pointers.
 *
 * @param[in] fd - socket descriptor
 * @param[out] tp - tcp buffer to read into
 * @param[in] max - max > 0: max read size
 *		    max <= 0: read as much as read buffer allows
 *
 * @return	int
 * @retval	>0 	number of characters read
 * @retval	0 	if EOD (no data currently avalable)
 * @retval	-1 	if error
 * @retval	-2 	if EOF (stream closed)
 */
static int tcp_read_buff(int fd, struct	tcpdisbuf *tp, size_t max)
{
	int i;

	/* compact (move to the front) the uncommitted data */

	tcp_pack_buff(tp);

	if ((tp->tdis_bufsize - tp->tdis_eod) < 64) {
		if (tcp_buff_resize(tp, tp->tdis_bufsize + THE_BUF_SIZE) != 0)
			return -1;
	}

	if (max <= 0 || max > tp->tdis_bufsize - tp->tdis_eod)
		max = tp->tdis_bufsize - tp->tdis_eod;

	i = raw_timed_read(fd, &tp->tdis_thebuf[tp->tdis_eod],
				max, pbs_tcp_timeout);

	if (i == 0) // EOF
		return -2;

	if (i > 0)
		tp->tdis_eod += i;

	return i;
}


/**
 * @brief
 * 	-tcp_read - read data from tcp stream to "fill" the buffer
 *	Update the various buffer pointers.
 *
 * @param[in] fd - socket descriptor
 * @param[in] max - max read size for cleartext
 *		    max > 0: max read size
 *		    max <= 0: read as much as read buffer allows
 *
 * @return	int
 * @retval	>0 	number of characters read
 * @retval	0 	if EOD (no data currently avalable)
 * @retval	-1 	if error
 * @retval	-2 	if EOF (stream closed)
 */
static int tcp_read(int fd, size_t max)
{
	gss_ctx_id_t		sec_ctx;
	struct	tcpdisbuf	*out;
	int i;

	sec_ctx = tcp_get_seccontext(fd);
	out = tcp_get_readbuf(fd);

	// if this connection is not unsecured, use simple tcp read
	if (sec_ctx == GSS_C_NO_CONTEXT)
            return tcp_read_buff(fd, out, max);

	int read;
	gss_buffer_desc        *dec;
	dec = tcp_get_decryptbuf(fd);

	// we do not have decoded data, we need to read new data into coded buffer
	struct	tcpdisbuf	*enc;
	enc = tcp_get_encryptbuf(fd);

	read = 1;
	while (enc->tdis_eod - enc->tdis_lead < 4 && read > 0)
		read = tcp_read_buff(fd, enc, 0);

	if (read <= 0) // EOF or read error
		return read;

	if (enc->tdis_eod - enc->tdis_lead >= 4) {

		// decode the header with packet size
		int l = 0;
		for (i=0; i<4; i++)
		{
	                l = l<<8 | (enc->tdis_thebuf[enc->tdis_lead] & 0xff);
			enc->tdis_lead++;
		}

		/*
		 * if the buffer is to small to have read the entire gss token,
		 * make the buffer bigger and call read again to read the rest from the
		 * socket. Then proceed.
		 */
		if (l+4 > enc->tdis_bufsize)
			tcp_buff_resize(enc, l+4);

		// try to read the encrypted message (on error, fail)

		while (enc->tdis_eod - enc->tdis_lead < l) {
			if ((read = tcp_read_buff(fd, enc, 0)) < 0)
				return read;
                }

		if (enc->tdis_eod - enc->tdis_lead >= l) {
			OM_uint32 major, minor;
			gss_buffer_desc msg_in;

			msg_in.length = l;
			msg_in.value = &enc->tdis_thebuf[enc->tdis_lead];

			major = gss_unwrap(&minor, sec_ctx, &msg_in, dec, NULL, NULL);

			enc->tdis_lead += l;
			enc->tdis_trail = enc->tdis_lead;	/* commit */

			if (major != GSS_S_COMPLETE) {
				gss_release_buffer(&minor, dec);
				return(-1);
			}

			if (dec->length == 0)
				return -2;

			if ((read = tcp_fillbuffer(out, dec)) > 0)
				return read;

			return -2;
		}
	}
	// we were not able to read enough data to read the message header
	return -2; // EOF
}

/**
 * @brief
 * 	-DIS_tcp_set_gss - Associate GSSAPI information with a TCP connection
 *	and resize gssrdbuf to appropriate size.
 *
 * @param[in] fd - socket descriptor
 * @param[in] ctx - GSS context to be associate with fd
 * @param[in] flags - flags containing info whether is confidential
 *
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int DIS_tcp_set_gss(int fd, gss_ctx_id_t ctx, OM_uint32 flags)
{
	int rc;
	rc = pbs_client_thread_lock_tcp();
	assert(rc == 0);

	tcparray[fd]->gssctx = ctx;
	tcparray[fd]->Confidential = (flags & GSS_C_CONF_FLAG);
	struct tcpdisbuf *tp = &tcparray[fd]->gssrdbuf;

	rc = pbs_client_thread_unlock_tcp();
	assert(rc == 0);

	OM_uint32 major, minor, bufsize;
	major = gss_wrap_size_limit(&minor, ctx, (flags & GSS_C_CONF_FLAG), GSS_C_QOP_DEFAULT, THE_BUF_SIZE, &bufsize);

	/* reallocate the gss buffer if it's too small to handle the wrapped
	 * version of the largest unwrapped message
	 */
	if (major == GSS_S_COMPLETE)
	{
		if (tp->tdis_bufsize < bufsize)
			tcp_buff_resize(tp, bufsize);

		return PBSGSS_OK;
	} else {
		return PBSGSS_ERR_WRAPSIZE;
	}
}

/**
 * @brief
 * 	-ensured_write - Ensure true failure or full write on file descriptor
 *
 * @param[in] fd - socket descriptor
 * @param[in] buff - data to be written to the fd
 * @param[in] buff_size - size of the data
 *
 * @return	int
 * @retval	buff_size on success
 * @retval	-1 on error
 */
int ensured_write(int fd, char *buff, size_t buff_size)
{
	char *pb = buff;
	size_t ct = buff_size;
	struct	pollfd pollfds[1];

	int	i,j;

	while ((ct > 0) && (i = write(fd, pb, ct)) != ct) {

		if (i < 0) {
			if (errno == EINTR)
				continue;

			if (errno != EAGAIN) {
				/* fatal error on write, abort output */
				pbs_tcp_errno = errno;
				return (-1);
			}

			/* write would have blocked (EAGAIN returned) */
			/* poll for socket to be ready to accept, if  */
			/* not ready in TIMEOUT_SHORT seconds, fail   */
			/* redo the poll if EINTR		      */
			do {

			    pollfds[0].fd = fd;
			    pollfds[0].events = POLLOUT;
			    pollfds[0].revents = 0;
			    j = poll(pollfds, 1, PBS_DIS_TCP_TIMEOUT_SHORT * 1000);

			} while ((j == -1) && (errno == EINTR));

			if (j == 0) {
				/* never came ready, return error */
				/* pbs_tcp_errno will add to log message */
				pbs_tcp_errno = EAGAIN;
				return (-1);
			} else if (j == -1) {
				/* some other error - fatal */
				pbs_tcp_errno = errno;
				return (-1);
			}

			continue;	/* socket ready, retry write */
		}

		/* write succeeded, do more if needed */
		ct -= i;
		pb += i;
	}

	return buff_size;
}

/**
 * @brief
 * 	-DIS_tcp_wflush - flush tcp/dis write buffer
 *
 * @par Functionality:
 *	Writes "committed" data in buffer to file discriptor,
 *	packs remaining data (if any), resets pointers
 *
 * @return	int
 * @retval	0	success
 * @retval	-1	error
 *
 */
int DIS_tcp_wflush(int fd)
{
	size_t	ct;
	char	*pb;
	int i;

	gss_ctx_id_t context  = tcp_get_seccontext(fd);
	struct	tcpdisbuf *tp = tcp_get_writebuf(fd);

	pb = tp->tdis_thebuf;
	ct = tp->tdis_trail;
	if (ct == 0) // no data to write
		return 0;

	OM_uint32 major, minor = 0;
	gss_buffer_desc msg_in, msg_out;

        // encode the message and send it out
        msg_out.value = NULL;
        msg_out.length = 0;
        if (context != GSS_C_NO_CONTEXT)
        {
		int confidential_flag = tcp_get_confidential_flag(fd);
		int conf_state = 0;

		msg_in.value  = pb;
		msg_in.length = ct;
		major = gss_wrap(&minor, context, confidential_flag, GSS_C_QOP_DEFAULT, &msg_in, &conf_state, &msg_out);
		if (major != GSS_S_COMPLETE)
		{
			gss_release_buffer(&minor, &msg_out);
			return(-1);
		}

		if (confidential_flag && !conf_state)
		{
			gss_release_buffer(&minor, &msg_out);
			return(-1);
		}

		// encode header with the coded message size
		unsigned char nct[4];
		ct = msg_out.length;
		for (i = sizeof(nct); i > 0; ct>>=8)
			nct[--i] = ct & 0xff;

		pbs_tcp_errno = 0;
		int ret = ensured_write(fd, (char*)nct, sizeof(nct));
		if (ret != sizeof(nct))
		{
			gss_release_buffer(&minor, &msg_out);
			return -1;
		}

		pb = msg_out.value;
		ct = msg_out.length;
	}

	pbs_tcp_errno = 0;
        int ret = ensured_write(fd, pb, ct);
        if (ret != ct)
        {
            gss_release_buffer(&minor, &msg_out);
            return -1;
        }

	tp->tdis_eod = tp->tdis_lead;
	tcp_pack_buff(tp);
	gss_release_buffer(&minor, &msg_out);
	return 0;
}

#else

/**
 * @brief
 * 	-tcp_read - read data from tcp stream to "fill" the buffer
 *	Update the various buffer pointers.
 *
 * @param[in] fd - socket descriptor
 *
 * @return	int
 * @retval	>0 	number of characters read
 * @retval	0 	if EOD (no data currently avalable)
 * @retval	-1 	if error
 * @retval	-2 	if EOF (stream closed)
 */

static int
tcp_read(int fd)
{
	int i;
	struct	pollfd pollfds[1];
	int	timeout;
	struct	tcpdisbuf	*tp;
	/*char   *tmcp;*/

	tp = tcp_get_readbuf(fd);

	/* compact (move to the front) the uncommitted data */

	tcp_pack_buff(tp);

	if ((tp->tdis_bufsize - tp->tdis_eod) < 64) {
		if (tcp_buff_resize(tp,tp->tdis_bufsize + THE_BUF_SIZE) != 0)
			return -1;
	}

	/*
	 * we don't want to be locked out by an attack on the port to
	 * deny service, so we time out the read, the network had better
	 * deliver promptly
	 */
	do {
		timeout = pbs_tcp_timeout;

		pollfds[0].fd = fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		i = poll(pollfds, 1, timeout * 1000);
		if (pbs_tcp_interrupt)
			break;
	} while ((i == -1) && (errno == EINTR));

	if ((i == 0) || (i < 0))
		return i;

	while ((i = CS_read(fd, &tp->tdis_thebuf[tp->tdis_eod],
		tp->tdis_bufsize - tp->tdis_eod)) == CS_IO_FAIL) {

		if (errno != EINTR)
			break;
	}
	if (i > 0)
		tp->tdis_eod += i;

	return ((i == 0) ? -2 : i);
}

/**
 * @brief
 * 	-DIS_tcp_wflush - flush tcp/dis write buffer
 *
 * @par Functionality:
 *	Writes "committed" data in buffer to file discriptor,
 *	packs remaining data (if any), resets pointers
 *
 * @return	int
 * @retval	0	success
 * @retval	-1	error
 *
 */
int
DIS_tcp_wflush(int fd)
{
	size_t	ct;
	int	i;
	int	j;
	char	*pb;
	struct	tcpdisbuf	*tp;
	struct	pollfd pollfds[1];

	pbs_tcp_errno = 0;
	tp = tcp_get_writebuf(fd);
	pb = tp->tdis_thebuf;

	ct = tp->tdis_trail;
	if (ct == 0)
		return 0;

	while ((i = CS_write(fd, pb, ct)) != ct) {
		if (i == CS_IO_FAIL) {
			if (errno == EINTR) {
				continue;
			}
			if (errno != EAGAIN) {
				/* fatal error on write, abort output */
				pbs_tcp_errno = errno;
				return (-1);
			}

			/* write would have blocked (EAGAIN returned) */
			/* poll for socket to be ready to accept, if  */
			/* not ready in TIMEOUT_SHORT seconds, fail   */
			/* redo the poll if EINTR		      */
			do {
				pollfds[0].fd = fd;
				pollfds[0].events = POLLOUT;
				pollfds[0].revents = 0;
				j = poll(pollfds, 1, PBS_DIS_TCP_TIMEOUT_SHORT * 1000);
			} while ((j == -1) && (errno == EINTR));

			if (j == 0) {
				/* never came ready, return error */
				/* pbs_tcp_errno will add to log message */
				pbs_tcp_errno = EAGAIN;
				return (-1);
			} else if (j == -1) {
				/* some other error - fatal */
				pbs_tcp_errno = errno;
				return (-1);
			}
			continue;	/* socket ready, retry write */
		}
		/* write succeeded, do more if needed */
		ct -= i;
		pb += i;
	}
	tp->tdis_eod = tp->tdis_lead;
	tcp_pack_buff(tp);
	return 0;
}

#endif

/**
 * @brief
 * 	-DIS_wflush - Wrapper function to do a tcp or TPP write buffer
 *
 * @par	Functionality:
 * 	calls DIS_tcp_wflush or rpp_flush based on input parameter rpp
 *
 * @param[in] sock - socket descriptor
 * @param[in] rpp - indication to use rpp or not
 *
 * @return	int
 * @retval	0	success
 * @retval	-1	error
 *
 */
int
DIS_wflush(int sock, int rpp)
{
	if (rpp)
		return (rpp_flush(sock));
	else
		return (DIS_tcp_wflush(sock));
}

/**
 * @brief
 * 	DIS_buf_clear - reset tpc/dis buffer to empty
 *
 * @param[in] tp - pointer to tcpdisbuf struct
 *
 * @return	Void
 *
 */

static void
DIS_tcp_clear(struct  tcpdisbuf *tp)
{
	tp->tdis_lead  = 0;
	tp->tdis_trail = 0;
	tp->tdis_eod   = 0;
}

/**
 * @brief
 * 	-wrapper function for DIS_tcp_clear.
 *
 * @param[in] fd - file descriptor
 * @param[in] i - read or write buf to clear
 *
 * @return	Void
 *
 */
void
DIS_tcp_reset(int fd, int i)
{
	DIS_tcp_clear(i==0 ? tcp_get_readbuf(fd) : tcp_get_writebuf(fd));
}

/**
 * @brief
 * 	-tcp_rskip - tcp/dis suport routine to skip over data in read buffer
 *
 * @param[in] fd - file descriptor
 * @param[in] ct - count
 *
 * @return	int
 * @retval	number of characters skipped
 *
 */

static int
tcp_rskip(int fd, size_t ct)
{
	struct	tcpdisbuf	*tp;

	tp = tcp_get_readbuf(fd);
	if (tp->tdis_lead - tp->tdis_eod < ct)
		ct = tp->tdis_lead - tp->tdis_eod;
	tp->tdis_lead += ct;
	return (int)ct;
}

/**
 * @brief
 * 	-tcp_getc - tcp/dis support routine to get next character from read buffer
 *
 * @param[in] fd - file descriptor
 *
 * @return	int
 * @retval	>0 	number of characters read
 * @retval	-1 	if EOD or error
 * @retval	-2 	if EOF (stream closed)
 *
 */

static int
tcp_getc(int fd)
{
	int	x;
	struct	tcpdisbuf	*tp;

	tp = tcp_get_readbuf(fd);
	if (tp->tdis_lead >= tp->tdis_eod) {
		/* not enought data, try to get more */
#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)
		x = tcp_read(fd, 1);
#else
		x = tcp_read(fd);
#endif
		if (x <= 0)
			return ((x == -2) ? -2 : -1);	/* Error or EOF */
	}
	return ((int)tp->tdis_thebuf[tp->tdis_lead++]);
}

/**
 * @brief
 * 	-tcp_gets - tcp/dis support routine to get a string from read buffer
 *
 * @param[in] fd - file descriptor
 * @param[in] str - string to be written
 * @param[in] ct - count
 *
 * @return	int
 * @retval	>0 	number of characters read
 * @retval	0 	if EOD (no data currently avalable)
 * @retval	-1 	if error
 * @retval	-2 	if EOF (stream closed)
 */

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)
static int
tcp_gets(int fd, char *str, size_t ct)
{
	int	x;
	struct	tcpdisbuf	*tp;
	size_t	read_ct;

	read_ct = ct;

	tp = tcp_get_readbuf(fd);
	while (tp->tdis_eod - tp->tdis_lead < ct) {
		/* not enought data, try to get more */
		x = tcp_read(fd, read_ct);
		if (x <= 0)
			return x;	/* Error or EOF */
		read_ct -= x;
	}
	(void)memcpy(str, &tp->tdis_thebuf[tp->tdis_lead], ct);
	tp->tdis_lead += ct;
	return (int)ct;
}
#else
static int
tcp_gets(int fd, char *str, size_t ct)
{
	int	x;
	struct	tcpdisbuf	*tp;

	tp = tcp_get_readbuf(fd);
	while (tp->tdis_eod - tp->tdis_lead < ct) {
		/* not enought data, try to get more */
		x = tcp_read(fd);
		if (x <= 0)
			return x;	/* Error or EOF */
	}
	(void)memcpy(str, &tp->tdis_thebuf[tp->tdis_lead], ct);
	tp->tdis_lead += ct;
	return (int)ct;
}
#endif

/**
 * @brief
 * 	tcp_puts - tcp/dis support routine to put a counted string of characters
 *	into the write buffer.
 *
 * @param[in] fd - file descriptor
 * @param[in] str - string to be written
 * @param[in] ct - count
 *
 * @return	int
 * @retval	>= 0	the number of characters placed
 * @retval	-1 	if error
 */

static int
tcp_puts(int fd, const char *str, size_t ct)
{
	struct	tcpdisbuf	*tp;

	tp = tcp_get_writebuf(fd);
	if ((tp->tdis_bufsize - tp->tdis_lead) < ct) {
		/* not enough room, try to flush committed data */
		if (DIS_tcp_wflush(fd) < 0)
			return -1;		/* error */

		if ((tp->tdis_bufsize - tp->tdis_lead) < ct) {	/* add room */

			/* no need to lock mutex here, per fd resize */
			size_t	ru = (ct + tp->tdis_lead) / THE_BUF_SIZE;

			if (tcp_buff_resize(tp,(ru+1)*THE_BUF_SIZE) != 0)
				return -1;
		}
	}
	(void)memcpy(&tp->tdis_thebuf[tp->tdis_lead], str, ct);
	tp->tdis_lead += ct;
	return ct;
}

/**
 * @brief
 * 	-tcp_rcommit - tcp/dis support routine to commit/uncommit read data
 *
 * @param[in] fd - file descriptor
 * @param[in] commit_flag - indication for commit or uncommit
 *
 * @return      int     
 * @retval      0       success
 *
 */

static int
tcp_rcommit(int fd, int commit_flag)
{
	struct	tcpdisbuf	*tp;

	tp = tcp_get_readbuf(fd);
	if (commit_flag) {
		/* commit by moving trailing up */
		tp->tdis_trail = tp->tdis_lead;
	} else {
		/* uncommit by moving leading back */
		tp->tdis_lead = tp->tdis_trail;
	}
	return 0;
}

/**
 * @brief
 * 	tcp_wcommit - tcp/dis support routine to commit/uncommit write data
 *
 * @param[in] fd - file descriptor
 * @param[in] commit_flag - indication for commit or uncommit
 *
 * @return	int
 * @retval	0	success
 */

static int
tcp_wcommit(int fd, int commit_flag)
{
	struct	tcpdisbuf	*tp;

	tp = tcp_get_writebuf(fd);
	if (commit_flag) {
		/* commit by moving trailing up */
		tp->tdis_trail = tp->tdis_lead;
	} else {
		/* uncommit by moving leading back */
		tp->tdis_lead = tp->tdis_trail;
	}
	return 0;
}

/**
 * @brief
 *	-sets tcp related functions.
 *
 */
void
DIS_tcp_funcs()
{
	if (dis_getc != tcp_getc) {
		dis_getc = tcp_getc;
		dis_puts = tcp_puts;
		dis_gets = tcp_gets;
		disr_skip = tcp_rskip;
		disr_commit = tcp_rcommit;
		disw_commit = tcp_wcommit;
	}
}

/**
 * @brief
 * 	-DIS_tcp_setup - setup supports routines for dis, "data is strings", to
 * 	use tcp stream I/O.  Also initializes an array of pointers to
 *	buffers and a buffer to be used for the given fd.
 *
 * @param[in] fd - socket descriptor
 * 
 * @return	Void
 *
 */

void
DIS_tcp_setup(int fd)
{
	struct	tcp_chan	*tcp;
	struct  tcp_chan	**tmpa;
	int	rc;

	/* check for bad file descriptor */
	if (fd < 0)
		return;

	rc = pbs_client_thread_lock_tcp();
	assert(rc == 0);

	/* set DIS function pointers */
	DIS_tcp_funcs();

	if (fd >= tcparraymax) {
		int	hold = tcparraymax;
		tcparraymax = fd+10;
		if (tcparray == NULL) {
			tcparray = (struct tcp_chan **)
				calloc(tcparraymax,
				sizeof(struct tcp_chan *));
			assert(tcparray != NULL);
		}
		else {
			tmpa = (struct tcp_chan **)realloc(tcparray,
				tcparraymax *
				sizeof(struct tcp_chan *));
			assert(tmpa != NULL);
			tcparray = tmpa;
			memset(&tcparray[hold], '\0',
				(tcparraymax-hold) *
				sizeof(struct tcp_chan *));
		}
	}
	tcp = tcparray[fd];
	if (tcp == NULL) {
		tcp = tcparray[fd] =
			(struct tcp_chan *)malloc(sizeof(struct tcp_chan));
		assert(tcp != NULL);
		tcp->readbuf.tdis_thebuf = malloc(THE_BUF_SIZE);
		assert(tcp->readbuf.tdis_thebuf != NULL);
		tcp->readbuf.tdis_bufsize = THE_BUF_SIZE;
		tcp->writebuf.tdis_thebuf = malloc(THE_BUF_SIZE);
		assert(tcp->writebuf.tdis_thebuf != NULL);
		tcp->writebuf.tdis_bufsize = THE_BUF_SIZE;

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)
		tcp->gssrdbuf.tdis_thebuf = malloc(THE_BUF_SIZE);
		assert(tcp->gssrdbuf.tdis_thebuf != NULL);
		tcp->gssrdbuf.tdis_bufsize = THE_BUF_SIZE;

		tcp->gssctx = GSS_C_NO_CONTEXT;
		tcp->unwrapped.value = NULL;
		tcp->unwrapped.length = 0;
#endif
	}

	/* initialize read and write buffers */
	DIS_tcp_clear(&tcp->readbuf);
	DIS_tcp_clear(&tcp->writebuf);

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)
        DIS_tcp_clear(&tcp->gssrdbuf);

        OM_uint32 minor;
        if (tcp->unwrapped.value)
            gss_release_buffer (&minor, &tcp->unwrapped);
#endif

	rc = pbs_client_thread_unlock_tcp();
	assert(rc == 0);
}

/**
 * @brief
 * 	-DIS_tcp_release - release GSS structures associated with fd
 *
 * @param[in] fd - socket descriptor
 * 
 * @return	Void
 *
 */
void DIS_tcp_release(int fd)
{
#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)
	int rc;
	rc = pbs_client_thread_lock_tcp();
	assert(rc == 0);

	if (tcparray != NULL && tcparray[fd] != NULL)
	{
		OM_uint32 minor;
		if (tcparray[fd]->gssctx != GSS_C_NO_CONTEXT)
		{
			(void)gss_delete_sec_context (&minor, &tcparray[fd]->gssctx, GSS_C_NO_BUFFER);
			tcparray[fd]->gssctx = GSS_C_NO_CONTEXT;
		}

		if (tcparray[fd]->unwrapped.value)
			gss_release_buffer (&minor, &tcparray[fd]->unwrapped);
	}

	rc = pbs_client_thread_unlock_tcp();
	assert(rc == 0);
#endif
}