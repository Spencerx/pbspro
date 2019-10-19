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

#ifndef PBS_GSS_H
#define PBS_GSS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pbs_config.h>   /* the master config generated by configure */

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)

#include <gssapi.h>

#define GSS_NT_SERVICE_NAME GSS_C_NT_HOSTBASED_SERVICE
#define DIS_GSS_BUF_SIZE 4096 /* default DIS buffer size */

enum PBS_GSS_ROLE {
	PBS_GSS_ROLE_UNKNOWN = 0,
	PBS_GSS_CLIENT,
	PBS_GSS_SERVER,
	PBS_GSS_ROLE_LAST
};

typedef struct {
	gss_ctx_id_t gssctx; /* gss security context */
	int gssctx_established; /* true if gss context has been established */
	int ready; /* true if ready to wrap/unwrap message */
	int confidential; /* wrapping includes encryption */
	enum PBS_GSS_ROLE role; /* value is client or server */
	char *hostname; /* server name */
	char *clientname; /* client name in string */
	gss_buffer_desc client_name; /* client name in gss buffer */
	int init_client_ccache; /* if true the client ccache is attempted to be created from keytab */
	int req_output_size; /* used to determine the wrap_size */
	OM_uint32 max_input_size; /*  maximum size of an unwrapped message */

	/* TCP only */
	int establishing; /* true if handshake in progress */

	/* TPP only */
	char *cleartext; /* saves cleartext for postsend_handler() */
	int cleartext_len;
} pbs_gss_extra_t;

struct gss_disbuf {
	size_t tdis_lead; /* pointer to the lead of the data */
	size_t tdis_trail; /* pointer to the trailing char of the data */
	size_t tdis_eod; /* variable to use to calculate end of data */
	size_t tdis_bufsize;/* size of this dis buffer */
	char *tdis_thebuf; /* pointer to the dis buffer space */
};

struct gssdis_chan {
	struct gss_disbuf readbuf; /* the dis read buffer */
	struct gss_disbuf writebuf; /* the dis write buffer */
	struct gss_disbuf gss_readbuf;   /* incoming wrapped data */
	struct gss_disbuf cleartext;   /* incoming pre-read data - this buffer survives DIS_tcp_setup() */
	unsigned short read_properties;
	pbs_gss_extra_t* gss_extra;
};

enum PBS_GSS_ERRORS {
	PBS_GSS_OK = 0,
	PBS_GSS_CONTINUE_NEEDED,
	PBS_GSS_ERR_INTERNAL,
	PBS_GSS_ERR_IMPORT_NAME,
	PBS_GSS_ERR_ACQUIRE_CREDS,
	PBS_GSS_ERR_CONTEXT_INIT,
	PBS_GSS_ERR_CONTEXT_ACCEPT,
	PBS_GSS_ERR_CONTEXT_DELETE,
	PBS_GSS_ERR_CONTEXT_ESTABLISH,
	PBS_GSS_ERR_SENDTOKEN,
	PBS_GSS_ERR_RECVTOKEN,
	PBS_GSS_ERR_NAME_CONVERT,
	PBS_GSS_ERR_INIT_CLIENT_CCACHE,
	PBS_GSS_ERR_WRAPSIZE,
	PBS_GSS_ERR_WRAP,
	PBS_GSS_ERR_UNWRAP,
	PBS_GSS_ERR_CONTEXT_SAVE,
	PBS_GSS_ERR_LAST
};

int pbs_gss_can_get_creds();
pbs_gss_extra_t* pbs_gss_alloc_gss_extra();
void pbs_gss_free_gss_extra(pbs_gss_extra_t *gss_extra);
int pbs_gss_establish_context(pbs_gss_extra_t *gss_extra, char *target_host, char *data_in, int len_in, char **data_out, int *len_out);
int pbs_gss_wrap(pbs_gss_extra_t *gss_extra, char *data_in, int len_in, char **data_out, int *len_out);
int pbs_gss_unwrap(pbs_gss_extra_t *gss_extra, char *data_in, int len_in, char **data_out, int *len_out);

void pbs_gss_set_log_handlers(void (*log_gss_status)(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat),
	void (*logerror)(const char *func_name, const char* msg),
	void (*logdebug)(const char *func_name, const char* msg));

/* TCP related */
int tcp_gss_client_authenticate(int sock, char *hostname, char *ebuf, int ebufsz);
extern int DIS_tcp_gss_wflush(int fd);
extern void DIS_gss_funcs(void);
extern int DIS_tcp_gss_set(int fd, pbs_gss_extra_t *gss_extra);
extern struct gssdis_chan *(*gss_get_chan)(int stream);


#endif

#ifdef __cplusplus
}
#endif
#endif /* PBS_GSS_H */

