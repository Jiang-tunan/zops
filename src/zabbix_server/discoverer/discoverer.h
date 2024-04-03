/*
** Zabbix
** Copyright (C) 2001-2023 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

#ifndef ZABBIX_DISCOVERER_H
#define ZABBIX_DISCOVERER_H

#include "zbxthreads.h"

#include "zbxcomms.h"
#include "zbxdbhigh.h"

#include "zbxdiscovery.h"


#include "zbxalgo.h"
#include "zbxdiscovery.h"


typedef struct
{
	zbx_config_tls_t	*zbx_config_tls;
	zbx_get_program_type_f	zbx_get_program_type_cb_arg;
	int			config_timeout;
}
zbx_thread_discoverer_args;

ZBX_THREAD_ENTRY(discoverer_thread, args); 

int	discover_service(zbx_db_drule *drule, const DB_DCHECK *dcheck, char *ip, int port, int config_timeout, char **value, size_t *value_alloc);
void DB_dcheck_free(DB_DCHECK *dcheck);
void notify_discover_thread();
#endif
