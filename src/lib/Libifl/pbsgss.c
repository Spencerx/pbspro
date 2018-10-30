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
 * @file	pbsgss.c
 *
 * @brief
 *  Routines providing GSS layer over TCP.
 */

#include <pbs_config.h>   /* the master config generated by configure */

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <time.h>
#include <stdlib.h>

#include <krb5.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi.h>

#ifdef HAVE_AFS_PARAM_H
#include <afs/param.h>
extern afs_int32 setpag();
#endif

#include "portability.h"
#include "pbsgss.h"
#include "log.h"

#include "pbs_assert.h"
#include "dis.h"
#include "dis_init.h"

int DIS_tcp_set_gss(int fd, gss_ctx_id_t ctx, OM_uint32 flags);
static void display_status_1(const char *m, OM_uint32 code, int type);

/* sending gss token */
int pbsgss_recv_token(int s, int *flags, gss_buffer_t tok);
int pbsgss_send_token(int s, int flags, gss_buffer_t tok);
int write_all_new(int fildes, char *buf, unsigned int nbyte);

/**
 * @brief
 *	 pass buffer and its size for writing to file descriptor
 *
 * @param[in] fildes - socket descriptor
 * @param[in] buf - data
 * @param[in] nbyte - size of data
 *
 * @return	int
 * @retval	>= 0	the number of characters placed
 * @retval	-1 	if error
 *
 */
int write_all(int fildes, void *buf, unsigned int nbyte) {
	return write_all_new(fildes, (char*)(buf), nbyte);
}

/**
 * @brief
 *	 place buffer of specific size, commit and wirte to file descriptor
 *
 * @param[in] fildes - socket descriptor
 * @param[in] buf - data
 * @param[in] nbyte - size of data
 *
 * @return	int
 * @retval	>= 0	the number of characters placed
 * @retval	-1 	if error
 *
 */
int write_all_new(int fildes, char *buf, unsigned int nbyte) {
	int i;
	i = (*dis_puts)(fildes, buf, nbyte);
	(*disw_commit)(fildes,1);
	DIS_tcp_wflush(fildes);
	return i;
}

/**
 * @brief
 *	Display GSS-API messages associated with maj_stat or min_stat to the
 *	stderr
 *
 * @param[in] m - error message followed by GSS maj or min message
 * @param[in] code - gss error code
 * @param[in] type - type of gss error code
 */
static void display_status_1(const char *m, OM_uint32 code, int type) {
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;
	msg_ctx = 0;

	do {
		maj_stat = gss_display_status(&min_stat, code, type, GSS_C_NULL_OID, &msg_ctx, &msg);
		fprintf(stderr, "%s : %.*s\n", m, (int)msg.length, (char *)msg.value);
		(void) gss_release_buffer(&min_stat, &msg);
	} while (msg_ctx != 0);

	(void)maj_stat;
	(void)min_stat;
  }

/**
 * @brief
 *	The GSS-API messages associated with maj_stat and min_stat are
 *	displayed on stderr, each preceeded by "GSS-API error <msg>: " and
 *	followed by a newline.
 *
 * @param[in] msg - a error string to be displayed with the message
 * @param[in] maj_stat - the GSS-API major status code
 * @param[in] min_stat - the GSS-API minor status code
 */
void pbsgss_display_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {
	display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
	display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

/** 
 * @brief
 *	Establishes a GSS-API context as a specified service with an incoming
 *	client, and returns the context handle and associated client name.
 *	Any valid client request is accepted.  If a context is established,
 *	its handle is returned in context and the client name is returned.
 *
 * @param[in] s - an established TCP connection to the client
 * @param[in] service_creds - server credentials, from gss_acquire_cred
 * @param[in] client_creds - optional client credentials, can be set to NULL
 * @param[out] context - the established GSS-API context
 * @param[out] client_name - the client's ASCII name
 * 
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 *
 */
int pbsgss_server_establish_context(int s, gss_cred_id_t server_creds, gss_cred_id_t* client_creds, gss_ctx_id_t* context, gss_buffer_t client_name, OM_uint32* ret_flags) {
	gss_buffer_desc send_tok, recv_tok;
	gss_name_t client;
	gss_OID doid;
	OM_uint32 maj_stat, min_stat, acc_sec_min_stat;
	int token_flags;

	*context = GSS_C_NO_CONTEXT;
	recv_tok.value = NULL;
	recv_tok.length = 0;

	do {
		if (pbsgss_recv_token(s, &token_flags, &recv_tok) != PBSGSS_OK) {
			if (recv_tok.value != NULL)
				free(recv_tok.value);

			return PBSGSS_ERR_RECVTOKEN;
		}

		maj_stat = gss_accept_sec_context(&acc_sec_min_stat, context, server_creds, &recv_tok, GSS_C_NO_CHANNEL_BINDINGS, &client, &doid, &send_tok, ret_flags, NULL, client_creds);

		if(recv_tok.value != NULL) {
			free(recv_tok.value);
			recv_tok.value = NULL;
		}

		if (send_tok.length != 0) {
			if (pbsgss_send_token(s, TOKEN_CONTEXT, &send_tok) != PBSGSS_OK)
				return PBSGSS_ERR_SENDTOKEN;

			if (gss_release_buffer(&min_stat, &send_tok) != GSS_S_COMPLETE)
				return PBSGSS_ERR_INTERNAL;
		}

		if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
			pbsgss_display_status("GSS - pbsgss_server_establish_context/accepting context", maj_stat, acc_sec_min_stat);
			if (*context != GSS_C_NO_CONTEXT)
				if (gss_delete_sec_context(&min_stat, context, GSS_C_NO_BUFFER) != GSS_S_COMPLETE)
					return PBSGSS_ERR_INTERNAL;

			return PBSGSS_ERR_ACCEPT_TOKEN;
		}

	} while (maj_stat == GSS_S_CONTINUE_NEEDED);

	maj_stat = gss_display_name(&min_stat, client, client_name, &doid);
	if (maj_stat != GSS_S_COMPLETE) {
		pbsgss_display_status("GSS - pbsgss_server_establish_context/displaying name", maj_stat, min_stat);
		return PBSGSS_ERR_NAME_CONVERT;
	}

	maj_stat = gss_release_name(&min_stat, &client);
	if (maj_stat != GSS_S_COMPLETE) {
		pbsgss_display_status("GSS - pbsgss_server_establish_context/releasing name", maj_stat, min_stat);
		return PBSGSS_ERR_INTERNAL;
	}

	DIS_tcp_setup(s);

	return 0;
}

/** @brief
 *	Determines whether GSS credentials can be acquired
 *
 * @return	int
 * @retval	true if creds can be acquired
 * @retval	false if creds can not be acquired
 */
int pbsgss_can_get_creds() {
	OM_uint32 maj_stat, min_stat, valid_sec = 0;
	gss_cred_id_t creds;

	maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE, &creds, NULL, &valid_sec);
	if (maj_stat == GSS_S_COMPLETE && creds != NULL)
		gss_release_cred(&min_stat, &creds);

/* There is a bug in old MIT implementation causes valid_sec is always 0
 * the problem is fixed in version >= 1.14 */
	return (maj_stat == GSS_S_COMPLETE && valid_sec > 10);
}

/** @brief
 *	Establishes a GSS-API context with a specified service and returns
 *	the context handle.
 *	Service_name is imported as a GSS-API name and a GSS-API context is
 *	established with the corresponding service; the service should be
 *	listening on the TCP connection s.  The default GSS-API mechanism
 *	is used, and mutual authentication and replay detection are
 *	requested.
 *
 *	If successful, the context handle is returned in context.
 *
 * @param[in] s - an established TCP connection to the service
 * @param[in] service_name - the service name of the service
 * @param[in] creds - client GSS credentials
 * @param[in] gss_flags - GSS-API delegation flag (if any)
 * @param[in] oid - OID of the mechanism to use
 * @param[in] gss_flags - whether to actually do authentication
 * @param[out] gss_context the established GSS-API context
 * @param[out] ret_flags - the returned flags from init_sec_context
 *
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int pbsgss_client_establish_context(int s, char * service_name, gss_cred_id_t creds, gss_OID oid, OM_uint32 gss_flags, gss_ctx_id_t * gss_context, OM_uint32 *ret_flags) {
	gss_buffer_desc send_tok, recv_tok, *token_ptr;
	gss_name_t target_name;
	OM_uint32 maj_stat, min_stat, init_sec_min_stat;
	int token_flags, status;

	/*
	 * Import the name into target_name.  Use send_tok to save
	 * local variable space.
	 */
	send_tok.value = service_name;
	send_tok.length = strlen(service_name) ;
	maj_stat = gss_import_name(&min_stat, &send_tok, gss_nt_service_name, &target_name);
	if (maj_stat != GSS_S_COMPLETE) {
		pbsgss_display_status("GSS - pbsgss_client_establish_context/gss_import_name", maj_stat, min_stat);
		return PBSGSS_ERR_IMPORTNAME;
	}

	send_tok.value = NULL;
	send_tok.length = 0;

	/*
	 * Perform the context-establishement loop.
	 *
	 * On each pass through the loop, token_ptr points to the token
	 * to send to the server (or GSS_C_NO_BUFFER on the first pass).
	 * Every generated token is stored in send_tok which is then
	 * transmitted to the server; every received token is stored in
	 * recv_tok, which token_ptr is then set to, to be processed by
	 * the next call to gss_init_sec_context.
	 *
	 * GSS-API guarantees that send_tok's length will be non-zero
	 * if and only if the server is expecting another token from us,
	 * and that gss_init_sec_context returns GSS_S_CONTINUE_NEEDED if
	 * and only if the server has another token to send us.
	 */

	token_ptr = GSS_C_NO_BUFFER;
	*gss_context = GSS_C_NO_CONTEXT;

	do {
		maj_stat = gss_init_sec_context(&init_sec_min_stat, creds ? creds : GSS_C_NO_CREDENTIAL, gss_context, target_name, oid, gss_flags, 0, NULL, token_ptr, NULL, &send_tok, ret_flags, NULL);

		if (token_ptr != GSS_C_NO_BUFFER && token_ptr->length && token_ptr->value) {
			free(token_ptr->value);
			token_ptr->value = NULL;
			token_ptr->length = 0;
		}

		if (send_tok.length != 0) {
			if (pbsgss_send_token(s, TOKEN_CONTEXT, &send_tok) != PBSGSS_OK) {
				if (gss_release_buffer(&min_stat, &send_tok) != GSS_S_COMPLETE)
					return PBSGSS_ERR_INTERNAL;
				if (gss_release_name(&min_stat, &target_name) != GSS_S_COMPLETE)
					return PBSGSS_ERR_INTERNAL;
				return PBSGSS_ERR_SENDTOKEN;
			}
		}

		if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
			pbsgss_display_status("GSS - pbsgss_client_establish_context/gss_init_set_context", maj_stat, init_sec_min_stat);

			if (gss_release_name(&min_stat, &target_name) != GSS_S_COMPLETE)
				return PBSGSS_ERR_INTERNAL;

			if (*gss_context != GSS_C_NO_CONTEXT)
				if (gss_delete_sec_context(&min_stat, gss_context, GSS_C_NO_BUFFER) != GSS_S_COMPLETE)
					return PBSGSS_ERR_INTERNAL;

			return PBSGSS_ERR_CONTEXT_INIT;
		}

		if (gss_release_buffer(&min_stat, &send_tok) != GSS_S_COMPLETE)
			return PBSGSS_ERR_INTERNAL;

		if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			status = pbsgss_recv_token(s, &token_flags, &recv_tok);
			if (status != 0) {
				if (gss_delete_sec_context(&min_stat, gss_context, GSS_C_NO_BUFFER) != GSS_S_COMPLETE)
					return PBSGSS_ERR_INTERNAL;

				if (gss_release_name(&min_stat, &target_name) != GSS_S_COMPLETE)
					return PBSGSS_ERR_INTERNAL;

				return status;
			}

			token_ptr = &recv_tok;
		}
	} while (maj_stat == GSS_S_CONTINUE_NEEDED);

	if (token_ptr != GSS_C_NO_BUFFER && token_ptr->length && token_ptr->value) {
		free(token_ptr->value);
		token_ptr->value = NULL;
		token_ptr->length = 0;
	}

	if (gss_release_name(&min_stat, &target_name) != GSS_S_COMPLETE)
		return PBSGSS_ERR_INTERNAL;

	DIS_tcp_setup(s);

	return PBSGSS_OK;
}

/** @brief
 *	Reads a token from a file descriptor.
 *	recv_token reads the token flags (a single byte, even though they're
 *	stored into an integer, then reads the token length (as a network long),
 *	allocates memory to hold the data, and then reads the token data from
 *	the file descriptors. It blocks to read the length and data,
 *	if necessary. On a successful return, the token should be freed with
 *	gss_release_buffer.
 *
 * @param[in] s - an open file descriptor
 * @param[out] flags - the read flags
 * @param[out] tok - the read token
 *
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int pbsgss_recv_token(int s, int *flags, gss_buffer_t tok) {
	int ret;
	unsigned char char_flags;
	unsigned char lenbuf[4];

	ret = (*dis_gets)(s, (char *)(&char_flags), 1);
	if (ret < 0) {
		perror("GSS - pbsgss_recv_token/reading token flags");
		return PBSGSS_ERR_READ;
	} else if (ret == 0) {
		(*disr_commit)(s,0);
		return PBSGSS_ERR_READ_TEMP;
	} else {
		*flags = (int) char_flags;
	}

	if (char_flags == 0) {
		lenbuf[0] = 0;
		ret = (*dis_gets)(s, (char *)(&lenbuf[1]), 3);
		if (ret < 0) {
			perror("GSS - pbsgss_recv_token/reading token length");
			return PBSGSS_ERR_READ;
		} else if (ret != 3) {
			(*disr_commit)(s, 0);
			return PBSGSS_ERR_READ_TEMP;
		}
	} else {
		ret = (*dis_gets)(s, (char *)(lenbuf), 4);
		if (ret < 0) {
			perror("GSS - pbsgss_recv_token/reading token length");
			return PBSGSS_ERR_READ;
		} else if (ret != 4) {
			(*disr_commit)(s, 0);
			return PBSGSS_ERR_READ_TEMP;
		}
	}

	tok->length = ((lenbuf[0] << 24) | (lenbuf[1] << 16) | (lenbuf[2] << 8) | lenbuf[3]);
	if (tok->length == 0) {
		tok->value = NULL;
		return PBSGSS_OK;
	}

	tok->value = (char *)(malloc(tok->length ? tok->length : 1));
	if (tok->length && tok->value == NULL) {
		tok->length = 0;
		return PBSGSS_ERR_INTERNAL;
	}

	ret = (*dis_gets)(s, (char *)(tok->value), tok->length);
	if (ret < 0) {
		perror("GSS - pbsgss_recv_token/reading token data");
		fprintf(stderr, "Returned: %d\n", ret);
		free(tok->value);
		tok->length = 0;
		tok->value = NULL;
		return PBSGSS_ERR_READ;
	} else if ((unsigned)ret != tok->length) {
		free(tok->value);
		tok->length = 0;
		tok->value = NULL;
		(*disr_commit)(s, 0);
		return PBSGSS_ERR_READ_TEMP;
	}

	(*disr_commit)(s, 1);
	return PBSGSS_OK;
}

/* @brief
 *	Writes a token to a file descriptor. If the flags are non-null,
 *	send_token writes the token flags (a single byte, even though they're
 *	passed in in an integer). Next, the token length (as a network long) 
 *	and then the token data are written to the file descriptor s.
 *
 * @param[in] s - an open file descriptor
 * @param[in] flags - the flags to write
 * @param[in] tok - the token to write
 *
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int pbsgss_send_token(int s, int flags, gss_buffer_t tok) {
	int ret;
	unsigned char char_flags = (unsigned char) flags;
	unsigned char lenbuf[4];

	DIS_tcp_wflush(s);

	if (char_flags) {
		ret = write_all(s, (char *)&char_flags, 1);
		if (ret != 1) {
			perror("GSS pbsgss_send_token/sending token flags");
			return PBSGSS_ERR_INTERNAL;
		}
	}

	if (tok->length > 0xffffffffUL)
		abort();

	lenbuf[0] = (tok->length >> 24) & 0xff;
	lenbuf[1] = (tok->length >> 16) & 0xff;
	lenbuf[2] = (tok->length >> 8) & 0xff;
	lenbuf[3] = tok->length & 0xff;

	ret = write_all(s, (char *)lenbuf, 4);
	if (ret < 0) {
		perror("GSS pbsgss_send_token/sending token length");
		return PBSGSS_ERR_INTERNAL;
	}

	ret = write_all(s, tok->value, tok->length);
	if (ret < 0) {
		perror("GSS pbsgss_send_token/sending token data");
		return PBSGSS_ERR_INTERNAL;
	} else if ((unsigned)ret != tok->length) {
		return PBSGSS_ERR_INTERNAL;
	}

	return PBSGSS_OK;
}

/** @brief
 *  Authenticate a client connection using GSS
 *
 * @param hostname - target hostname
 * @param psock - socket with established connection
 * @param delegate - delegate credentials
 * @param wrap - ensure message integrity
 *
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int pbsgss_client_authenticate(char *hostname, int psock, int delegate, int wrap) {
	char *service_name;
	OM_uint32 gss_flags, ret_flags, maj_stat, min_stat;
	gss_OID oid;
	gss_ctx_id_t gss_context;
	gss_cred_id_t creds;
	int retval;

	maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE, &creds, NULL, NULL);

	if (maj_stat != GSS_S_COMPLETE) {
		pbsgss_display_status("GSS - pbsgss_client_authenticate/gss_acquire_cred", maj_stat, min_stat);
		return PBSGSS_ERR_ACQUIRE_CREDS;
	}

	size_t strl = strlen(hostname) + strlen("host@") + 1;
	service_name = (char*)(malloc(strl));
	snprintf(service_name, strl, "host@%s", hostname);

	gss_flags = GSS_C_MUTUAL_FLAG | (delegate ? GSS_C_DELEG_FLAG : 0) | (wrap ? (GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG) : 0);
	oid = GSS_C_NULL_OID;
	retval = pbsgss_client_establish_context(psock, service_name, creds, oid, gss_flags, &gss_context, &ret_flags);
	free(service_name);

	if (creds != NULL)
		if (gss_release_cred(&min_stat, &creds) != GSS_S_COMPLETE)
			return PBSGSS_ERR_INTERNAL;

	if (retval != PBSGSS_OK)
		return retval;

	if (wrap) {
		if (pbsgss_save_sec_context(&gss_context, ret_flags, psock) != PBSGSS_OK)
			return PBSGSS_ERR_CONTEXT_SAVE;
	} else {
		if (gss_delete_sec_context(&min_stat, &gss_context, GSS_C_NO_BUFFER) != PBSGSS_OK)
			return PBSGSS_ERR_CONTEXT_DELETE;
	}

	return PBSGSS_OK;
}

/** @brief
 *	Save current context. If the context supports integrity, save it for
 *	later use by gss_wrap() and gss_unwrap(). Otherwise delete it.
 *
 * @param[in] context - context to be saved
 * @param[in] flags - GSS flags
 * @param[in] fd - network handler
 * 
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int pbsgss_save_sec_context(gss_ctx_id_t *context, OM_uint32 flags, int fd) {
	OM_uint32 major, minor;

	if (flags & (GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG)) {
		if (DIS_tcp_set_gss(fd, *context, flags) != PBSGSS_OK)
			return PBSGSS_ERR_CONTEXT_SAVE;
	} else if (*context != GSS_C_NO_CONTEXT) {
		major = gss_delete_sec_context(&minor, context, GSS_C_NO_BUFFER);
		if (major != GSS_S_COMPLETE) {
			pbsgss_display_status("GSS - pbsgss_save_sec_context/gss_delete_sec_context", major, minor);
			return PBSGSS_ERR_CONTEXT_DELETE;
		}
	}

	return PBSGSS_OK;
}

/** @brief
 *	Imports a service name and acquires credentials for it. The service name
 *	is imported with gss_import_name, and service credentials are acquired 
 *	with gss_acquire_cred.
 *
 * @param[in] service_name - the service name
 * @param[out] server_creds - the GSS-API service credentials
 * 
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int pbsgss_server_acquire_creds(char *service_name, gss_cred_id_t* server_creds) {
	gss_name_t server_name;
	OM_uint32 maj_stat, min_stat;

	gss_buffer_desc name_buf;
	name_buf.value = service_name;
	name_buf.length = strlen(service_name) + 1;

	maj_stat = gss_import_name(&min_stat, &name_buf, gss_nt_service_name, &server_name);

	if (maj_stat != GSS_S_COMPLETE) {
		pbsgss_display_status("GSS - pbsgss_server_acquire_creds/gss_import_name", maj_stat, min_stat);
		return PBSGSS_ERR_IMPORT_NAME;
	}

	maj_stat = gss_acquire_cred(&min_stat, server_name, 0, GSS_C_NULL_OID_SET, GSS_C_ACCEPT, server_creds, NULL, NULL);

	if (maj_stat != GSS_S_COMPLETE) {
		pbsgss_display_status("GSS - pbsgss_server_acquire_creds/gss_acquire_creds", maj_stat, min_stat);
		if (gss_release_name(&min_stat, &server_name) != GSS_S_COMPLETE) {
			pbsgss_display_status("GSS - pbsgss_server_acquire_creds/gss_release_name", maj_stat, min_stat);
			return PBSGSS_ERR_INTERNAL;
		}

		return PBSGSS_ERR_ACQUIRE_CREDS;
	}

	if (gss_release_name(&min_stat, &server_name) != GSS_S_COMPLETE) {
		pbsgss_display_status("GSS - pbsgss_server_acquire_creds/gss_release_name", maj_stat, min_stat);
		return PBSGSS_ERR_INTERNAL;
	}

	return PBSGSS_OK;
}

#endif /* GSSAPI */
