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
 * @file	gss_handshake.c
 *
 * @brief
 *  Routines providing GSS handshake over TPP.
 */

#include <pbs_config.h>

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)

#include <stdio.h>
#include <stdlib.h>
#include <pbs_ifl.h>

#include "net_connect.h"
#include "dis.h"
#include "rpp.h"
#include "log.h"
#include "pbsgss.h"

/* default lifetime for the credential, if infinite lifetime is provided */
#define DEFAULT_CREDENTIAL_LIFETIME 7200

extern int init_pbs_client_ccache_from_keytab();

char gss_err_buffer[LOG_BUF_SIZE];
char *gss_err_msg_tpp = "GSS (TPP) - %s/%s";

/**
 * @brief
 *	Log GSS-API messages associated with maj_stat or min_stat
 *
 * @param[in] m - error message followed by GSS maj or min message
 * @param[in] code - gss error code
 * @param[in] type - type of gss error code
 */
static void log_status_1(const char *m, OM_uint32 code, int type) {
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;
	msg_ctx = 0;

	do {
		maj_stat = gss_display_status(&min_stat, code, type, GSS_C_NULL_OID, &msg_ctx, &msg);
		snprintf(log_buffer, LOG_BUF_SIZE, "%s : %.*s\n", m, (int)msg.length, (char *)msg.value);
		log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR,
			msg_daemonname, log_buffer);
		(void) gss_release_buffer(&min_stat, &msg);
	} while (msg_ctx != 0);

	(void)maj_stat;
	(void)min_stat;
}

/**
 * @brief
 *	The GSS-API messages associated with maj_stat and min_stat are
 *	logged, each preceeded by "GSS-API error <msg>: ".
 *
 * @param[in] msg - a error string to be displayed with the message
 * @param[in] maj_stat - the GSS-API major status code
 * @param[in] min_stat - the GSS-API minor status code
 */
void gss_log_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {
	log_status_1(msg, maj_stat, GSS_C_GSS_CODE);
	log_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

/**
 * @brief - Compose a gss handshake message for IS or IM protocol
 *
 * @param[in] stream  - The TPP stream
 * @param[in] value  - gss token data
 * @param[in] length  - gss token data length
 * @param[in] to_server - True if the receiver is gss server, False for client receiver
 * @param[in] target_host  - target host fqdn
 *  *
 * @return error code
 * @retval  DIS_SUCCESS - Success
 * @retval !DIS_SUCCESS - Failure
 */
int gss_compose(int stream, char* value, int length, int to_server, char* target_host) {
	int	ret;

	if (stream < 0)
		return DIS_EOF;

	DIS_rpp_reset();

	ret = diswsi(stream, HS_PROTOCOL);
	if (ret != DIS_SUCCESS)
		goto done;

	ret = diswsi(stream, HS_PROTOCOL_VER);
	if (ret != DIS_SUCCESS)
		goto done;

	ret = diswsi(stream, GSS_HANDSHAKE);
	if (ret != DIS_SUCCESS)
		goto done;

	ret = diswsi(stream, to_server);
	if (ret != DIS_SUCCESS)
		goto done;

	ret = diswcs(stream, target_host, strlen(target_host));
	if (ret != DIS_SUCCESS)
		goto done;

	ret = diswcs(stream, value, length);
	if (ret != DIS_SUCCESS)
		goto done;

	return DIS_SUCCESS;

done:
	return ret;
}

/* @brief
 *	Sends a GSS token via TPP stream during GSS handshake.
 *
 * @param[in] stream - TPP channel
 * @param[in] tok - the token to write
 * @param[in] to_server - True if the receiver is gss server, False for client receiver
 * @param[in] target_host  - target host fqdn
 *
 * @return	int
 * @retval	PBSGSS_OK on success
 * @retval	!= PBSGSS_OK on error
 */
int gss_send_token(int stream, gss_buffer_t tok, int to_server, char* target_host) {
	if (gss_compose(stream, (char *)tok->value, tok->length, to_server, target_host) != DIS_SUCCESS)
		return PBSGSS_ERR_SENDTOKEN;

	if (rpp_flush(stream))
		return PBSGSS_ERR_SENDTOKEN;

	return PBSGSS_OK;
}

/* @brief
 *	Server part of GSS hadshake
 *
 * @param[in] stream - TPP channel
 * @param[in] data - received GSS token
 * @param[in] length - length of token data
 * @param[in] target_host  - target host fqdn
 * @param[in] server_creds - server credentials
 * @param[in] client_creds - optional credentials, can be NULL
 * @param[in/out] context - this context is being established here
 * @param[out] ret_flags - Flags indicating additional services or parameters requested for the context.
 *
 * @return	int
 * @retval	GSS_S_CONTINUE_NEEDED if we need more data for gss context
 * @retval	GSS_S_COMPLETE if the context has been established
 * @retval	otherwise on error
 */
int gss_server_establish_context(int stream, char* data, int length, char* target_host, gss_cred_id_t server_creds, gss_cred_id_t* client_creds, gss_ctx_id_t* context, OM_uint32* ret_flags) {
	gss_buffer_desc send_tok, recv_tok;
	//gss_buffer_t client_name;
	gss_name_t client;
	gss_OID doid;
	OM_uint32 maj_stat, min_stat, acc_sec_maj_stat, acc_sec_min_stat;

	recv_tok.value = (void *)data;
	recv_tok.length = length;

	if (recv_tok.length == 0) {
		sprintf(log_buffer,"Establishing gss context failed. Failed to receive gss token.");
		log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
		return GSS_S_FAILURE;
	}

	acc_sec_maj_stat = gss_accept_sec_context(&acc_sec_min_stat, context, server_creds, &recv_tok, GSS_C_NO_CHANNEL_BINDINGS, &client, &doid, &send_tok, ret_flags, NULL, client_creds);

	if(recv_tok.value != NULL) {
		free(recv_tok.value);
		recv_tok.value = NULL;
	}

	if (send_tok.length != 0) {
		if (gss_send_token(stream, &send_tok, 0, target_host) != PBSGSS_OK) {
			sprintf(log_buffer,"Establishing gss context failed. Failed to send gss token.");
			log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
			return GSS_S_FAILURE;
		}

		maj_stat = gss_release_buffer(&min_stat, &send_tok);
		if (maj_stat != GSS_S_COMPLETE) {
			sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_release_buffer");
			gss_log_status(gss_err_buffer, maj_stat, min_stat);
			return maj_stat;
		}
	}

	if (acc_sec_maj_stat != GSS_S_COMPLETE && acc_sec_maj_stat != GSS_S_CONTINUE_NEEDED) {
		sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_accept_sec_context");
		gss_log_status(gss_err_buffer, acc_sec_maj_stat, acc_sec_min_stat);
		if (*context != GSS_C_NO_CONTEXT) {
			if ((maj_stat = gss_delete_sec_context(&min_stat, context, GSS_C_NO_BUFFER)) != GSS_S_COMPLETE) {
				sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_delete_sec_context");
				gss_log_status(gss_err_buffer, maj_stat, min_stat);
				return maj_stat;
			}
		}

		return acc_sec_maj_stat;
	}

	return acc_sec_maj_stat;
}

/* @brief
 *	Client part of GSS hadshake
 *
 * @param[in] stream - TPP channel
 * @param[in] data - optional - received GSS token
 * @param[in] length - length of token data
 * @param[in] target_host  - target host fqdn
 * @param[in] service_name - The name of the principal to connect to
 * @param[in] creds - client credentials
 * @param[in] oid - The security mechanism to use. GSS_C_NULL_OID for default
 * @param[in] gss_flags - Flags indicating additional services or parameters requested for the context.
 * @param[in/out] gss_context - this context is being established here
 * @param[out] ret_flags - Flags indicating additional services or parameters requested for the context.
 *
 * @return	int
 * @retval	GSS_S_CONTINUE_NEEDED if we need more data for gss context
 * @retval	GSS_S_COMPLETE if the context has been established
 * @retval	otherwise on error
 */
int gss_client_establish_context(int stream, char* data, int length, char* target_host, char *service_name, gss_cred_id_t creds, gss_OID oid, OM_uint32 gss_flags, gss_ctx_id_t * gss_context, OM_uint32 *ret_flags) {
	gss_buffer_desc send_tok, recv_tok, *token_ptr;
	gss_name_t target_name;
	OM_uint32 maj_stat, min_stat, init_sec_maj_stat, init_sec_min_stat;

	send_tok.value = service_name;
	send_tok.length = strlen(service_name) ;
	maj_stat = gss_import_name(&min_stat, &send_tok, gss_nt_service_name, &target_name);
	if (maj_stat != GSS_S_COMPLETE) {
		sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_import_name");
		gss_log_status(gss_err_buffer, maj_stat, min_stat);
		return maj_stat;
	}

	send_tok.value = NULL;
	send_tok.length = 0;

	recv_tok.value = (void *)data;
	recv_tok.length = length;

	if (recv_tok.length > 0) {
		token_ptr = &recv_tok;
	} else {
		token_ptr = GSS_C_NO_BUFFER;
	}

	init_sec_maj_stat = gss_init_sec_context(&init_sec_min_stat, creds ? creds : GSS_C_NO_CREDENTIAL, gss_context, target_name, oid, gss_flags, 0, NULL, token_ptr, NULL, &send_tok, ret_flags, NULL);

	if (token_ptr != GSS_C_NO_BUFFER && token_ptr->length && token_ptr->value) {
		free(token_ptr->value);
		token_ptr->value = NULL;
		token_ptr->length = 0;
	}

	if (send_tok.length != 0) {
		if (gss_send_token(stream, &send_tok, 1, target_host) != PBSGSS_OK) {

			maj_stat = gss_release_buffer(&min_stat, &send_tok);
			if (maj_stat != GSS_S_COMPLETE) {
				sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_release_buffer");
				gss_log_status(gss_err_buffer, maj_stat, min_stat);
				return maj_stat;
			}

			maj_stat = gss_release_name(&min_stat, &target_name);
			if (maj_stat != GSS_S_COMPLETE) {
				sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_release_name");
				gss_log_status(gss_err_buffer, maj_stat, min_stat);
				return maj_stat;
			}

			sprintf(log_buffer,"Establishing gss context failed. Failed to send gss token.");
			log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
			return GSS_S_FAILURE;
		}
	}

	if (init_sec_maj_stat != GSS_S_COMPLETE && init_sec_maj_stat != GSS_S_CONTINUE_NEEDED) {
		sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_init_sec_context");
		gss_log_status(gss_err_buffer, init_sec_maj_stat, init_sec_min_stat);

		maj_stat = gss_release_name(&min_stat, &target_name);
		if (maj_stat != GSS_S_COMPLETE) {
			sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_release_name");
			gss_log_status(gss_err_buffer, maj_stat, min_stat);
			return maj_stat;
		}

		if (*gss_context != GSS_C_NO_CONTEXT) {
			maj_stat = gss_delete_sec_context(&min_stat, gss_context, GSS_C_NO_BUFFER);
			if (maj_stat != GSS_S_COMPLETE) {
				sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_delete_sec_context");
				gss_log_status(gss_err_buffer, maj_stat, min_stat);
				return maj_stat;
			}
		}

		return init_sec_maj_stat;
	}

	maj_stat = gss_release_buffer(&min_stat, &send_tok);
	if (maj_stat != GSS_S_COMPLETE) {
		sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_release_buffer");
		gss_log_status(gss_err_buffer, maj_stat, min_stat);
		return maj_stat;
	}

	if (token_ptr != GSS_C_NO_BUFFER && token_ptr->length && token_ptr->value) {
		free(token_ptr->value);
		token_ptr->value = NULL;
		token_ptr->length = 0;
	}

	maj_stat = gss_release_name(&min_stat, &target_name);
	if (maj_stat != GSS_S_COMPLETE) {
		sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_release_name");
		gss_log_status(gss_err_buffer, maj_stat, min_stat);
		return maj_stat;
	}

	return init_sec_maj_stat;
}

/* @brief
 *	Once the GSS token has been received, this function is called and
 *	we decide whether we call client or server side of gss handshake here.
 *	If the GSS token is not supplied we assume this is a client side and
 *	the GSS handshake is about to start.
 *
 * @param[in] stream  - The TPP stream
 * @param[in] target_host  - target host fqdn
 * @param[in] data  - gss token data
 * @param[in] len  - gss token data length
 * @param[in] is_server - True if we are the gss server, False for client
 *
 * @return
 */
void gss_establish_context(int stream, char *target_host, char* data, int len, int is_server) {
	OM_uint32 maj_stat, min_stat;
	char *service_name = NULL;
	gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
	gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
	OM_uint32 gss_flags, ret_flags;
	gss_OID oid;

	static time_t lastcredstime = 0;
	static time_t credlifetime = 0;
	time_t now = time((time_t *)NULL);
	static gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
	OM_uint32 lifetime;

	if (DIS_tpp_has_ctx(stream)) {
		sprintf(log_buffer, "GSS context already established (stream %d)", stream);
		log_event(PBSEVENT_SYSTEM, PBS_EVENTCLASS_SERVER, LOG_INFO, __func__, log_buffer);
		return;
	}

	gss_context = DIS_tpp_get_ctx(stream);

	if (service_name == NULL) {
		service_name = (char *) malloc(strlen(KRB5_SERVICE_NAME) + 1 + strlen(target_host) + 1);
		if (service_name == NULL) {
			sprintf(log_buffer, "malloc failure");
			log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
			return;
		}
		sprintf(service_name, "%s@%s", KRB5_SERVICE_NAME, target_host);
	}

	if (is_server) { /* I am gss server */
		if (now - lastcredstime > credlifetime) {
			gss_cred_id_t new_server_creds;

			if (pbsgss_server_acquire_creds(service_name, &new_server_creds) != PBSGSS_OK) {
				sprintf(log_buffer, "Failed to acquire server credentials for %s", service_name);
				log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
				lastcredstime = now + 120; // try again in 2 minutes
			} else {
				lastcredstime = now;
				snprintf(log_buffer,LOG_BUF_SIZE,"Refreshing server credentials at %ld\n",(long)now);
				log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_DEBUG, __func__, log_buffer);

				if (server_creds != GSS_C_NO_CREDENTIAL)
					gss_release_cred(&ret_flags,&server_creds);

				server_creds = new_server_creds;

				/* fetch information about the fresh credentials */
				if (gss_inquire_cred(&ret_flags,server_creds, NULL,&lifetime,NULL,NULL) == GSS_S_COMPLETE){
					if (lifetime == GSS_C_INDEFINITE) {
						credlifetime = DEFAULT_CREDENTIAL_LIFETIME;
						snprintf(log_buffer,LOG_BUF_SIZE,"Server credentials renewed with indefinite lifetime, using %d.\n", DEFAULT_CREDENTIAL_LIFETIME);
						log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_DEBUG, __func__, log_buffer);
					} else {
						snprintf(log_buffer,LOG_BUF_SIZE,"Server credentials renewed with lifetime as %u.\n", lifetime);
						log_event(PBSEVENT_DEBUG | PBSEVENT_FORCE, PBS_EVENTCLASS_SERVER, LOG_DEBUG, __func__, log_buffer);
						credlifetime = lifetime;
					}
				} else {
					/* could not read information from credential */
					credlifetime = 0;
				}
			}
		}

		maj_stat = gss_server_establish_context(stream, data, len, target_host, server_creds, NULL, &gss_context, &ret_flags);
	} else { /* I am gss client */
		if (init_pbs_client_ccache_from_keytab()) {
			sprintf(log_buffer, "Failed to initialize client's ccache");
			log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
			return;
		}

		maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE, &creds, NULL, NULL);
		if (maj_stat != GSS_S_COMPLETE) {
			sprintf(gss_err_buffer, gss_err_msg_tpp, __func__, "gss_acquire_cred");
			gss_log_status(gss_err_buffer, maj_stat, min_stat);
			return;
		}

		gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG;
		oid = GSS_C_NULL_OID;

		maj_stat = gss_client_establish_context(stream, data, len, target_host, service_name, creds, oid, gss_flags, &gss_context, &ret_flags);
	}

	if (service_name != NULL)
		free(service_name);

	if (gss_context == GSS_C_NO_CONTEXT) {
		sprintf(log_buffer,"Failed to establish gss context");
		log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
		return;
	}

	if (maj_stat == GSS_S_CONTINUE_NEEDED) {
	    if (DIS_tpp_set_gss(stream, gss_context, ret_flags, 0) != PBSGSS_OK) {
		sprintf(log_buffer,"Failed to bound gss context with stream");
		log_event(PBSEVENT_DEBUG, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
	    }
	    return;
	}

	if (maj_stat == GSS_S_COMPLETE && DIS_tpp_set_gss(stream, gss_context, ret_flags, 1) == PBSGSS_OK) {
		if (is_server) {
			sprintf(log_buffer,"Entered encrypted communication with client");
		} else {
			sprintf(log_buffer,"Entered encrypted communication with server %s", target_host);
		}
		log_event(PBSEVENT_DEBUG, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
	} else {
		if (is_server) {
			sprintf(log_buffer,"Failed to enter encrypted communication with client");
		} else {
			sprintf(log_buffer,"Failed to enter encrypted communication with server %s", target_host);
		}
		log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
	}

	return;
}

/**
 * @brief
 *      This message is received during establishing GSS context
 *	on IS or IM stream.
 *
 * @param[in]       stream	IS or IM TPP stream
 * @param[in]       version	GSS handshake version
 * @return		void
 *
 */
void gss_handshake(int stream) {
	char *data = NULL;
	char *target_host = NULL;
	size_t len;
	int ret, to_server;

	to_server = disrsi(stream, &ret);
	if (ret != DIS_SUCCESS) {
		rpp_close(stream);
		return;
	}

	target_host = disrcs(stream, &len, &ret);
	if (ret != DIS_SUCCESS) {
		rpp_close(stream);
		return;
	}

	data = disrcs(stream, &len, &ret);
	if (ret != DIS_SUCCESS) {
		rpp_close(stream);
		return;
	}

	gss_establish_context(stream, target_host, data, len, to_server);

	rpp_eom(stream);
	return;
}

#endif
