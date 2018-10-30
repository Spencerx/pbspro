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
 * @file	req_gssauthenuser.c
 *
 * @brief
 *  Batch request routines for starting GSS handshake over TCP.
 */

#include <pbs_config.h>   /* the master config generated by configure */

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)

#include <time.h>
#include <sys/utsname.h>
#include <stdio.h>

#include "dis.h"
#include "log.h"
#include "pbsgss.h"
#include "pbs_ifl.h"
#include "server_limits.h"
#include "net_connect.h"
#include "credential.h"
#include "list_link.h"
#include "attribute.h"
#include "batch_request.h"

/* default lifetime for the credential, if infinite lifetime is provided */
#define DEFAULT_CREDENTIAL_LIFETIME 7200

extern time_t time_now;
extern char server_host[];

/* @brief
 *	This should be called on a socket after readauth() (in net_server.c) but
 *	goes before process request.  It copies the principal from the svr_conn
 *	structure (in net_server) to conn_credent.
 *
 * @param[in] preq - batch request structure
 * @param[in] s - tcp socket
 *
 * @return	int
 * @retval	0 on success
 * @retval	!= 0 on error
 */
int gss_conn_credent (struct batch_request *preq, int s) {
	char *client_name;
	int i, length;
        conn_t          *conn;

        conn = get_conn(s);

	client_name = conn->cn_principal;
	if (!client_name) {
		log_err(0,"gss_conn_credent","couldn't get client_name");
		return -1;
	}

	for (i = 0; client_name[i] != '\0' && i < PBS_MAXUSER; i++) {
		if (client_name[i] == '@') {break;}
	}

	length = strlen(client_name);
	strncpy(conn->cn_username,client_name,i);
	conn->cn_username[i] = '\0';

	strcpy(conn->cn_physhost, conn->cn_hostname); // store the original physical host

	strncpy(conn->cn_hostname, client_name + i + 1, length - i -1);
	conn->cn_hostname[length - i -1] = '\0';

	conn->cn_timestamp = time_now;

	strcpy(preq->rq_user, conn->cn_username);
	strcpy(preq->rq_host, conn->cn_hostname);

	return 0;
}

/* @brief
 *	Process PBS_BATCH_GSSAuthenUser batch request and do GSS handshake in
 *	order to establish GSS context for TCP
 *
 * @param[in] preq - batch request structure
 * @param[in] sock - tcp socket
 *
 * @return	int
 * @retval	0 on success
 * @retval	!= 0 on error
 */
int req_gssauthenuser (struct batch_request *preq) {
	static time_t lastcredstime = 0;
	static char *service_name = NULL;
	static gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
	static time_t credlifetime = 0;
	conn_t               *conn;
	int sock;

	sock = preq->rq_conn;

	conn = get_conn(sock);

	if (service_name == NULL)
		asprintf(&service_name,"host@%s",server_host);

	time_t now = time((time_t *)NULL);

	gss_ctx_id_t context;
	gss_buffer_desc client_name;
	OM_uint32 majstat, ret_flags, lifetime;

	log_event(PBSEVENT_ERROR | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, "Entered encrypted communication.");
	int status;

	/* if credentials are old, try to get new ones. If we can't, keep the old
	    ones since they're probably still valid and hope that
	    we can get new credentials next time */
	if (now - lastcredstime > credlifetime) {
		gss_cred_id_t new_creds;

		/* if we can't get new creds, try again in a few minutes */
		if (pbsgss_server_acquire_creds(service_name, &new_creds) != PBSGSS_OK) {
			log_event(PBSEVENT_SECURITY | PBSEVENT_FORCE,PBS_EVENTCLASS_SERVER, LOG_ERR,
				__func__,"Unable to acquire fresh KRB5 pbs server credentials.");
			lastcredstime = now + 120; // try again in 2 minutes
		} else {
			/* if we got new creds, free the old ones and use the new ones */
			lastcredstime = now;
			snprintf(log_buffer,LOG_BUF_SIZE,"Refreshing KRB5 pbs server credentials at %ld\n", (long)now);
			log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_DEBUG, __func__, log_buffer);

			if (server_creds != GSS_C_NO_CREDENTIAL)
				gss_release_cred(&ret_flags, &server_creds);

			server_creds = new_creds;
			/* fetch information about the fresh credentials */
			majstat = gss_inquire_cred(&ret_flags, server_creds, NULL, &lifetime, NULL, NULL);
			if (majstat == GSS_S_COMPLETE) {
				if (lifetime == GSS_C_INDEFINITE) {
					credlifetime = DEFAULT_CREDENTIAL_LIFETIME;
					snprintf(log_buffer, LOG_BUF_SIZE, "KRB5 pbs server credentials received with indefinite lifetime, using %d.\n", DEFAULT_CREDENTIAL_LIFETIME);
					log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_DEBUG, __func__, log_buffer);
				} else {
					snprintf(log_buffer, LOG_BUF_SIZE,"KRB5 pbs server credentials received with lifetime as %u.\n", lifetime);
					log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_DEBUG, __func__, log_buffer);
					credlifetime = lifetime;
				}
			} else {
				/* could not read information from credential */
				credlifetime = 0;
			}
		}
	}

	if ((status = pbsgss_server_establish_context(sock, server_creds, NULL, &context, &client_name, &ret_flags)) != PBSGSS_OK) {
		snprintf(log_buffer,LOG_BUF_SIZE,"Unable to establish a secure context : %d",status);
		log_event(PBSEVENT_SECURITY | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_ERR,__func__, log_buffer);
		return -1;
	}

	if (context == GSS_C_NO_CONTEXT) {
		log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_INFO, __func__, "Received an unauthenticated connection.");
		return -1;
	}

	free(conn->cn_principal);

	conn->cn_principal = malloc(client_name.length + 1);
	memcpy(conn->cn_principal, client_name.value, client_name.length);
	conn->cn_principal[client_name.length] = '\0';

	free(client_name.value);

	conn->cn_authen = PBS_NET_CONN_GSSAPIAUTH | PBS_NET_CONN_AUTHENTICATED;
	if (!(ret_flags & GSS_C_INTEG_FLAG)) {
		log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, "Integrity protection not available on connection.");
		return -1;
	}

	pbsgss_save_sec_context(&context, ret_flags, sock); // TODO Handle error

	if ((status = gss_conn_credent(preq, sock)) < 0) {
		log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, "Couldn't propagate connection credentials.");
		return -1;
	}

	return 0;
}

#endif // GSSAPI
