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

/**
 * @file    mom_interactive_shell.c
 *
 * @brief
 *  Handles running of interactive batch job at Mom
 *
 */
#include <pbs_config.h>
#include <pbs_internal.h>
#include <windows.h>
#include "win.h"
#include "log.h"
#include "win_remote_shell.h"

int
main(int argc, char *argv[])
{
	int                     num_nodes = 0;
	char                    *momjobid = NULL;
	char                    pipename_append[PIPENAME_MAX_LENGTH] = {'\0'};
	char                    cmdline[PBS_CMDLINE_LENGTH] = {'\0'};
	char                    cmd_shell[MAX_PATH] = {'\0'};
	char					gui_app[MAX_PATH] = {'\0'};
	char					*user_name = NULL;
	DWORD                   exit_code = 0;
	STARTUPINFO             si;
	PROCESS_INFORMATION		pi_demux = { 0 };
	DWORD                   rc = 0;
	HANDLE					hJob = INVALID_HANDLE_VALUE;
	int						i = 0;
	int						show_window = SW_HIDE;
	int						is_gui_job = 0;

	if (argc < 4) {
		exit(-1);
	}
	/*
	 * argv[1] is jobid
	 * argv[2] is number of nodes
	 * argv[3] is whether it is a GUI job
	 * argv[4] is GUI app to be launched
	 */
	/* A non-GUI job only takes 4 arguments */
	momjobid = argv[1];
	num_nodes = atoi(argv[2]);
	is_gui_job = atoi(argv[3]);
	/* A GUI job must have minimum 5 arguments */
	if(is_gui_job && argc < 5) {
		fprintf(stderr, "mom_shell: GUI job must have minimum 5 arguments");
		exit(-1);
	}
	/* If it's a GUI job, argv[4] is username */
	if(is_gui_job) {
		user_name = argv[4];
	}
	/* 6th argument is optional for GUI job */
	if(is_gui_job && argc > 5) {
		strncpy(gui_app, argv[5], _countof(gui_app) -1);
	}

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	/*
	 * Create std pipes and wait for qsub to connect to these pipes
	 */
	strncpy(pipename_append, momjobid, PIPENAME_MAX_LENGTH - 1);
	if ((rc = create_std_pipes(&si, pipename_append, 1)) != 0) {
		fprintf(stderr, "mom_shell: Failed to create pipe with error=%lu\n", rc);
		exit(-1);
	}
	if ((rc = connectstdpipes(&si, 1)) != 0) {
		fprintf(stderr, "mom_shell: Failed to connect to std pipe with error=%lu\n", rc);
		/*
		 * Close the standard out/in/err handles before returning
		 */
		close_valid_handle(&(si.hStdOutput));
		close_valid_handle(&(si.hStdError));
		close_valid_handle(&(si.hStdInput));
		exit(-1);
	}

	hJob = CreateJobObject(NULL, NULL);
	if ((hJob == NULL) || (hJob == INVALID_HANDLE_VALUE)) {
		fprintf(stderr, "mom_shell: CreateJobObject() failed with error=%lu\n", GetLastError());
		exit(-1);
	}

	/*
	 * invoke pbs_demux to redirect any demux output to the interactive shell
	 */
	if (pbs_loadconf(0) == 0) {
		fprintf(stderr, "mom_shell: Could not load pbs configuration\n");
		exit(-1);
	}

	sprintf(cmdline, "cmd /c %s/sbin/pbs_demux.exe %s %d", pbs_conf.pbs_exec_path, momjobid, num_nodes);
	rc = CreateProcess(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi_demux);
	if (rc == 0) {
		fprintf(stderr, "mom_shell: failed to create demux proces\n");
	}
	/* Attach pbs_demux process tree to the job object */
	rc = AssignProcessToJobObject(hJob, pi_demux.hProcess);
	if (!rc) {
		fprintf(stderr, "mom_shell: AssignProcessToJobObject failed with error=%lu\n",
			GetLastError());
	}

	rc = ResumeThread(pi_demux.hThread);
	if (rc == (DWORD)-1)
		log_err(-1, __func__, "ResumeThread failed");

	/*
	 * Initialize the interactive command shell
	 * cmd.exe /q turns echo off
	 */
	cmdline[0] = '\0';
	/* If we fail to get cmd shell(unlikely), use "cmd.exe" as shell */
	if (0 != get_cmd_shell(cmd_shell, _countof(cmd_shell)))
		(void)snprintf(cmd_shell, _countof(cmd_shell) - 1, "cmd.exe");

	if(gui_app[0] != '\0')
	{

		snprintf(cmdline, _countof(cmd_shell) + _countof(gui_app) - 1, "%s", gui_app);
		show_window = SW_SHOW;
	}
	else {
		snprintf(cmdline, _countof(cmd_shell) - 1, "%s /q", cmd_shell);
		show_window = SW_HIDE;
	}
	/*
	 * Run an interactive command shell, flush the file buffers
	 */
	rc = run_command_si_blocking(&si, cmdline, &exit_code, is_gui_job, show_window, user_name);
	if (rc == 0) {
		if (si.hStdOutput != INVALID_HANDLE_VALUE)
			if (!FlushFileBuffers(si.hStdOutput))
				log_err(-1, __func__, "FlushFileBuffers failed for stdout");
		if (si.hStdError != INVALID_HANDLE_VALUE)
			if(!FlushFileBuffers(si.hStdError))
				log_err(-1, __func__, "FlushFileBuffers failed for stderr");
	} else
		fprintf(stderr, "mom_shell: Failed to run interactive shell command %s with error %lu", cmdline, rc);

	/*
	 * Disconnect all named pipes and close handles
	 */
	disconnect_close_pipe(si.hStdInput);
	disconnect_close_pipe(si.hStdOutput);
	disconnect_close_pipe(si.hStdError);
	/*
	 * Exit with shell's exit code.
	 * Terminate pbs_demux process tree.
	 */
	rc = TerminateJobObject(hJob, 0);
	if (!rc) {
		fprintf(stderr, "mom_shell: TerminateJobObject() failed with error=%lu\n",
			GetLastError());
	}
	exit(exit_code);
}
