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

#ifndef ZABBIX_CHECKS_DB_H
#define ZABBIX_CHECKS_DB_H

#include "zbxcacheconfig.h"
#include "zbxdiscovery.h"

#ifdef HAVE_UNIXODBC

#define MAX_FILE_SIZE 1024 * 1024  // 配置文件大小

#define ODBCINI_PATH        "/etc/odbc.ini"
#define MYSQL_DRIVER        "TOGNIX_MYSQL_ODBC"
#define MSSQL_DRIVER        "TOGNIX_MSSQL_ODBC"
#define ORACLE_DRIVER       "TOGNIX_ORACLE_ODBC"
#define POSTGRESQL_DRIVER       "TOGNIX_POSTGRESQL_ODBC"
#define SAPHANA_DRIVER          "TOGNIX_SAPHANA_ODBC"

int	get_value_db(const DC_ITEM *item, int config_timeout, AGENT_RESULT *result);
int write_odbc_config(DB_DCHECK *dcheck, long *file_size);
int restore_file_size(const char *file_path, long size);
#endif

#endif
