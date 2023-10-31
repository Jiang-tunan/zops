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

#ifndef ZABBIX_DISCOVERY_H
#define ZABBIX_DISCOVERY_H

#include "zbxdbhigh.h"

typedef struct
{
	zbx_uint64_t	dcheckid;
	unsigned short	port;
	char		dns[ZBX_INTERFACE_DNS_LEN_MAX];
	char		value[ZBX_MAX_DISCOVERED_VALUE_SIZE];
	int		status;
	time_t		itemtime;
}
zbx_dservice_t;

typedef struct
{
	zbx_uint64_t	dcheckid;
	char		*ports;
	char		*key_;
	char		*snmp_community;
	char		*snmpv3_securityname;
	char		*snmpv3_authpassphrase;
	char		*snmpv3_privpassphrase;
	char		*snmpv3_contextname;
	int		type;
	unsigned char	snmpv3_securitylevel;
	unsigned char	snmpv3_authprotocol;
	unsigned char	snmpv3_privprotocol;
	int		       houseid;
	zbx_uint64_t   druleid;
	char		*ip;
}
DB_DCHECK;

void	zbx_discovery_update_host(zbx_db_dhost *dhost, int status, int now);
void	zbx_discovery_update_service(const zbx_db_drule *drule, zbx_uint64_t dcheckid, zbx_db_dhost *dhost,
		const char *ip, const char *dns, int port, int status, const char *value, int now, const DB_DCHECK *dcheck);

void vector_to_str(zbx_vector_str_t *v, char **out, const char *split);
void str_to_vector(zbx_vector_str_t *out, const char *str, const char *split);
void discovery_parsing_macs(const char *data, zbx_vector_str_t *out);
void discovery_parsing_value(const char *data, const char *field, char **out);
void discovery_parsing_value_model(const char *entphysicalmodelname, const char *sysdesc, const int dcheck_type, int *groupid, int *manufacturerid, int *templateid);
void discovery_parsing_value_os(const char *sysdesc, char **out);

#endif
