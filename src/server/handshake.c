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
 * @file	handshake.c
 *
 * @brief
 *  Routines providing general handshake over TPP.
 */

#include <pbs_config.h>

#if defined(PBS_SECURITY) && (PBS_SECURITY == KRB5)

#include <pbs_ifl.h>

#include "net_connect.h"
#include "log.h"
#include "dis.h"
#include "rpp.h"

/**
 * @brief
 *      This handshake message is received in order to do security handshake
 *	on IS or IM stream.
 *
 * @param[in]       stream	IS or IM TPP stream
 * @param[in]       version	GSS handshake version
 * @return		void
 *
 */
void hs_request(int stream, int version) {
	void gss_handshake(int);
	int ret, hs_protocol;

	DBPRT(("%s: stream %d version %d\n", __func__, stream, version))
	if (version != HS_PROTOCOL_VER) {
		sprintf(log_buffer, "handshake version %d unknown", version);
		log_event(PBSEVENT_ERROR, PBS_EVENTCLASS_SERVER, LOG_ERR, __func__, log_buffer);
		rpp_close(stream);
		return;
	}

	hs_protocol = disrsi(stream, &ret);
	if (ret != DIS_SUCCESS) {
		rpp_close(stream);
		return;
	}

	switch (hs_protocol) {
		case	GSS_HANDSHAKE:
			gss_handshake(stream);
			break;
		default:
			DBPRT(("%s: unknown handshake %d\n", __func__, hs_protocol))
			break;
	}

	rpp_eom(stream);
	return;
}

#endif
