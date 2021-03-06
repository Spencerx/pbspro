/*
 * Copyright (C) 1994-2020 Altair Engineering, Inc.
 * For more information, contact Altair at www.altair.com.
 *
 * This file is part of both the OpenPBS software ("OpenPBS")
 * and the PBS Professional ("PBS Pro") software.
 *
 * Open Source License Information:
 *
 * OpenPBS is free software. You can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * OpenPBS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Commercial License Information:
 *
 * PBS Pro is commercially licensed software that shares a common core with
 * the OpenPBS software.  For a copy of the commercial license terms and
 * conditions, go to: (http://www.pbspro.com/agreement.html) or contact the
 * Altair Legal Department.
 *
 * Altair's dual-license business model allows companies, individuals, and
 * organizations to create proprietary derivative works of OpenPBS and
 * distribute them - whether embedded or bundled with other software -
 * under a commercial license agreement.
 *
 * Use of Altair's trademarks, including but not limited to "PBS™",
 * "OpenPBS®", "PBS Professional®", and "PBS Pro™" and Altair's logos is
 * subject to Altair's trademark licensing policies.
 */

#include <pbs_config.h>   /* the master config generated by configure */
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <io.h>
#include <windows.h>
#include "win.h"
#include "pbs_ifl.h"
#include "list_link.h"
#include "attribute.h"
#include "job.h"
#include "credential.h"
#include "ticket.h"
#include "libpbs.h"
#include "batch_request.h"
#include "pbs_version.h"
#include "pbs_ecl.h"
#include "net_connect.h"
#include  "pbs_nodes.h"
#include "mom_func.h"
#include "log.h"

/**
 * @file	mom_stage_file.c
 */
/* Global Data Items */
char *path_log = NULL;
char *path_spool = NULL;
char *path_undeliv = NULL;
char *path_checkpoint = NULL;
char *path_jobs = NULL;
char *log_file = NULL;
time_t time_now = 0;
char rcperr[MAXPATHLEN] = {'\0'};	/* file to contain rcp error */
char *pbs_jobdir = NULL;		/* path to staging and execution dir of current job */
char *cred_buf = NULL;
size_t cred_len = 0;
char mom_host[PBS_MAXHOSTNAME+1] = {'\0'};
struct cphosts *pcphosts = 0;
int cphosts_num = 0;
static int is_file_open;
static char id[] = "pbs_stage_file";

/**
 * @brief
 * 	print_or_log_err - log/print error messages
 *
 *  @param[in]	err_msg	 - error message to log
 *
 * @return	void
 */
void
print_or_log_err(char *err_msg)
{
	if (is_file_open)
		log_err(-1, id, err_msg);
	else
		fprintf(stderr, "%s:%s\n", id, err_msg);
}

/**
 * @brief
 * 	main - the initialization and main loop of pbs_stage_file
 */
int
main(int argc, char *argv[])
{
	char buf[CPY_PIPE_BUFSIZE] = {'\0'};
	char *param_name = NULL;
	char *param_val = NULL;
	int rc = -1;
	time_t copy_start = 0;
	time_t copy_stop = 0;
	int dir = 0;
	int num_copies = 0;
	struct rqfpair *pair = NULL;
	int i = -1;
	int rmtflag = -1;
	struct rq_cpyfile rqcpf_buf = {0};
	struct rq_cpyfile *rqcpf = &rqcpf_buf;
	struct passwd *pw = NULL;
	char *actual_homedir = NULL;
	cpy_files stage_inout = {0};
	char *prmt = NULL;
	char mom_log_path[MAXPATHLEN + 1] = {'\0'};

	PRINT_VERSION_AND_EXIT(argc, argv);

	if(set_msgdaemonname("PBS_stage_file")) {
		fprintf(stderr, "Out of memory\n");
		return 1;
	}

	pbs_loadconf(0);

	set_log_conf(pbs_conf.pbs_leaf_name, pbs_conf.pbs_mom_node_name,
			pbs_conf.locallog, pbs_conf.syslogfac,
			pbs_conf.syslogsvr, pbs_conf.pbs_log_highres_timestamp);

	if (pbs_conf.pbs_home_path != NULL) {
		snprintf(mom_log_path, sizeof(mom_log_path), "%s\\mom_logs", pbs_conf.pbs_home_path);
		if ((log_open_main(NULL, mom_log_path, 1)) == 0) /* silent open */
			is_file_open = 1;
	}

	pbs_client_thread_set_single_threaded_mode();
	/* disable attribute verification */
	set_no_attribute_verification();

	/* initialize the thread context */
	if (pbs_client_thread_init_thread_context() != 0) {
		print_or_log_err("Unable to initialize thread context");
		exit(STAGEFILE_FATAL);
	}

	if (winsock_init()) {
		print_or_log_err("winsock_init failed!");
		return 1;
	}

	connection_init();

	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		buf[strlen(buf)-1] = '\0';	/* gets rid of newline */

		param_name = buf;
		param_val = strchr(buf, '=');
		if (param_val) {
			*param_val = '\0';
			param_val++;
		} else {	/* bad param_val */
			break;
		}

		if (strcmp(param_name, "path_log") == 0) {
			path_log = strdup(param_val);
		} else if (strcmp(param_name, "path_spool") == 0) {
			path_spool = strdup(param_val);
		} else if (strcmp(param_name, "path_undeliv") == 0) {
			path_undeliv = strdup(param_val);
		} else if (strcmp(param_name, "path_checkpoint") == 0) {
			path_checkpoint = strdup(param_val);
		} else if (strcmp(param_name, "pbs_jobdir") == 0) {
			pbs_jobdir = strdup(param_val);
		} else if (strcmp(param_name, "actual_homedir") == 0) {
			actual_homedir = strdup(param_val);
		} else if (strcmp(param_name, "mom_host") == 0) {
			strncpy_s(mom_host, sizeof(mom_host), param_val, _TRUNCATE);
		} else if (strcmp(param_name, "log_file") == 0) {
			log_file = strdup(param_val);
		} else if (strcmp(param_name, "log_event_mask") == 0) {
			*log_event_mask = atol(param_val);
		} else if (strcmp(param_name, "direct_write") == 0) {
			stage_inout.direct_write = atoi(param_val);
		} else if (strcmp(param_name, "pcphosts") == 0) {
			if (!recv_pcphosts()) {
				print_or_log_err("error while receiving pcphosts");
				if (actual_homedir)
					unmap_unc_path(actual_homedir);
				net_close(-1);
				exit(STAGEFILE_FATAL);
			}
		} else if (strcmp(param_name, "rq_cpyfile") == 0) {
			if (!recv_rq_cpyfile_cred(rqcpf)) {
				print_or_log_err("error while receiving rq_cpyfile info and cred");
				if (actual_homedir)
					unmap_unc_path(actual_homedir);
				net_close(-1);
				exit(STAGEFILE_FATAL);
			}
		} else {
			print_or_log_err("unrecognized parameter");
			exit(STAGEFILE_FATAL);
		}
	}

	if ((path_log == NULL) || (path_spool == NULL) || (path_undeliv == NULL) ||
		(path_checkpoint == NULL) || (pbs_jobdir == NULL) || (actual_homedir == NULL) ||
		(*mom_host == '\0') || (log_file == NULL)) {
		print_or_log_err("error in one or more parameters");
		if (actual_homedir)
			unmap_unc_path(actual_homedir);
		net_close(-1);
		exit(STAGEFILE_FATAL);
	}

	time(&time_now);

	if(!is_file_open)
		(void)log_open_main(log_file, path_log, 1); /* silent open */

	if ((cred_len > 0) && (cred_buf != NULL)) {
		pw = logon_pw(rqcpf->rq_user, cred_buf, cred_len, pbs_decrypt_pwd, 0, log_buffer);
		log_event(PBSEVENT_DEBUG2, PBS_EVENTCLASS_JOB, LOG_DEBUG, rqcpf->rq_jobid, log_buffer);
		if ((pw != NULL) && (pw->pw_userlogin != INVALID_HANDLE_VALUE)) {
			if (!impersonate_user(pw->pw_userlogin)) {
				snprintf(log_buffer, sizeof(log_buffer), "ImpersonateLoggedOnUser failed for %s", rqcpf->rq_user);
				log_err(-1, id, log_buffer);
				unmap_unc_path(actual_homedir);
				log_close(0);	/* silent close */
				net_close(-1);
				exit(STAGEFILE_BADUSER);
			}
		} else {
			SetLastError(ERROR_INVALID_HANDLE);
			snprintf(log_buffer, sizeof(log_buffer), "logon_pw failed for %s", rqcpf->rq_user);
			log_err(-1, id, log_buffer);
			unmap_unc_path(actual_homedir);
			log_close(0);	/* silent close */
			net_close(-1);
			exit(STAGEFILE_BADUSER);
		}
	}

	dir  = (rqcpf->rq_dir & STAGE_DIRECTION)? STAGE_DIR_OUT : STAGE_DIR_IN;
	stage_inout.sandbox_private = (rqcpf->rq_dir & STAGE_JOBDIR)? TRUE : FALSE;

	if (stage_inout.sandbox_private) {
		/* chdir to job staging and execution directory if
		 * "PRIVATE" or "O_WORKDIR" mode is requested
		 */
		chdir(pbs_jobdir);
	} else {
		/* chdir to user's home directory */
		(void)chdir(actual_homedir);
	}

	/*
	 * Now running in the user's home or job directory as the user.
	 * Build up cp/rcp command(s), one per file pair
	 */

	copy_start = time(0);
	for (pair=(struct rqfpair *)GET_NEXT(rqcpf->rq_pair);
		pair != 0;
		pair = (struct rqfpair *)GET_NEXT(pair->fp_link)) {

		stage_inout.from_spool = 0;
		prmt = pair->fp_rmt;
		num_copies++;

		if (local_or_remote(&prmt) == 0) {
			/* destination host is this host, use cp */
			rmtflag = 0;
		} else {
			/* destination host is another, use (pbs_)rcp */
			rmtflag = 1;
		}

		rc = stage_file(dir, rmtflag, rqcpf->rq_owner, pair, 0, &stage_inout, prmt);
		if (rc != 0) {
			snprintf(log_buffer, sizeof(log_buffer), "%s;%s stage%s failed, user=%s, owner=%s, status=%d",
				id, (rmtflag == 1) ? "remote" : "local", (dir == STAGE_DIR_OUT) ? "out" : "in", rqcpf->rq_user, rqcpf->rq_owner, rc);
			log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_JOB, LOG_ERR, rqcpf->rq_jobid, log_buffer);
			break;
		}
	}
	copy_stop = time(0);

	/*
	 * If there was a stage in failure, remove the job directory.
	 * There is no guarantee we'll run on this mom again,
	 * So we need to cleanup.
	 */
	if ((dir == STAGE_DIR_IN) && stage_inout.sandbox_private && stage_inout.bad_files) {
		/* cd to user's home to be out of   */
		/* the sandbox so it can be deleted */
		chdir(actual_homedir);
		rmjobdir(rqcpf->rq_jobid, pbs_jobdir, NULL, NULL);
	}

	/* if operation is successful, log the number of files/directories copied and the time it took */
	if (!rc) {
		copy_stop = copy_stop - copy_start;
		sprintf(log_buffer, "staged %d items %s over %d:%02d:%02d",
			num_copies, (dir == STAGE_DIR_OUT) ? "out" : "in",
			copy_stop/3600, (copy_stop%3600)/60, copy_stop%60);
		log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_JOB, LOG_ERR, rqcpf->rq_jobid, log_buffer);
	}

	if ((stage_inout.bad_files) || (stage_inout.sandbox_private && stage_inout.stageout_failed)) {
		if (stage_inout.bad_files) {
			sprintf(log_buffer, "%s;stage%s failed for the file %s", id, (dir == STAGE_DIR_OUT) ? "out" : "in", stage_inout.bad_list);
			log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_JOB, LOG_ERR, rqcpf->rq_jobid, log_buffer);
		}
		unmap_unc_path(actual_homedir);
		log_close(0);	/* silent close */
		net_close(-1);
		exit(STAGEFILE_NOCOPYFILE);
	}

	unmap_unc_path(actual_homedir);
	log_close(0);	/* silent close */
	net_close(-1);
	exit(STAGEFILE_OK);
}
