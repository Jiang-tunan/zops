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

#include "checks_db.h"

#ifdef HAVE_UNIXODBC

#include "log.h"
#include "zbxsysinfo.h"

#include "../odbc/odbc.h"

/******************************************************************************
 *                                                                            *
 * Purpose: retrieve data from database                                       *
 *                                                                            *
 * Parameters: item           - [IN] item we are interested in                *
 *             config_timeout - [IN]                                          *
 *             result         - [OUT] check result                            *
 *                                                                            *
 * Return value: SUCCEED - data successfully retrieved and stored in result   *
 *               NOTSUPPORTED - requested item is not supported               *
 *                                                                            *
 ******************************************************************************/
int	get_value_db(const DC_ITEM *item, int config_timeout, AGENT_RESULT *result)
{
	AGENT_REQUEST		request;
	const char		*dsn, *connection = NULL;
	zbx_odbc_data_source_t	*data_source;
	zbx_odbc_query_result_t	*query_result;
	char			*error = NULL;
	int			(*query_result_to_text)(zbx_odbc_query_result_t *query_result, char **text, char **error),
				ret = NOTSUPPORTED;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() key_orig:'%s' query:'%s'", __func__, item->key_orig, item->params);

	zbx_init_agent_request(&request);

	if (SUCCEED != zbx_parse_item_key(item->key, &request))
	{
		SET_MSG_RESULT(result, zbx_strdup(NULL, "Invalid item key format."));
		goto out;
	}

	if (0 == strcmp(request.key, "db.odbc.select"))
	{
		query_result_to_text = zbx_odbc_query_result_to_string;
	}
	else if (0 == strcmp(request.key, "db.odbc.discovery"))
	{
		query_result_to_text = zbx_odbc_query_result_to_lld_json;
	}
	else if (0 == strcmp(request.key, "db.odbc.get"))
	{
		query_result_to_text = zbx_odbc_query_result_to_json;
	}
	else
	{
		SET_MSG_RESULT(result, zbx_strdup(NULL, "Unsupported item key for this item type."));
		goto out;
	}

	if (2 > request.nparam || 3 < request.nparam)
	{
		SET_MSG_RESULT(result, zbx_strdup(NULL, "Invalid number of parameters."));
		goto out;
	}

	/* request.params[0] is ignored and is only needed to distinguish queries of same DSN */

	dsn = request.params[1];

	if (2 < request.nparam)
		connection = request.params[2];

	if ((NULL == dsn || '\0' == *dsn) && (NULL == connection || '\0' == *connection))
	{
		SET_MSG_RESULT(result, zbx_strdup(NULL, "Invalid database connection settings."));
		goto out;
	}

	if (NULL != (data_source = zbx_odbc_connect(dsn, connection, item->username, item->password, config_timeout,
			&error)))
	{
		if (NULL != (query_result = zbx_odbc_select(data_source, item->params, &error)))
		{
			char	*text = NULL;

			if (SUCCEED == query_result_to_text(query_result, &text, &error))
			{
				SET_TEXT_RESULT(result, text);
				ret = SUCCEED;
			}

			zbx_odbc_query_result_free(query_result);
		}

		zbx_odbc_data_source_free(data_source);
	}

	if (SUCCEED != ret)
		SET_MSG_RESULT(result, error);
out:
	zbx_free_agent_request(&request);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}


int write_odbc_config(DB_DCHECK *dcheck, long *file_size) 
{
    char odbc_dsn[MAX_STRING_LEN]; 
    char file_content[MAX_FILE_SIZE];
    FILE *file;
    int ret = 0;

    zbx_snprintf(odbc_dsn, sizeof(odbc_dsn),
                 "[%s]\nDriver=%s\nServer=%s\nPort=%s\n\n",
                 dcheck->dsn_name, dcheck->driver, dcheck->ip, dcheck->ports);

    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#ODBC %s() odbc_dsn=%s", __func__, odbc_dsn);

    // 打开文件
    file = fopen(ODBCINI_PATH, "r+");
    if (file == NULL) {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#ODBC %s() Failed to open file [%s]", __func__, dcheck->dsn_name);
        return FAIL;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    if (*file_size == -1L) {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#ODBC %s() Failed to get file size [%s]", __func__, dcheck->dsn_name);
        fclose(file);
        return FAIL;
    }


    rewind(file);
    fread(file_content, sizeof(char), *file_size, file);

    // 检查配置是否已存在
    if (strstr(file_content, odbc_dsn) != NULL) 
	{
        zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#ODBC %s() Configuration already exists, updating [%s]", __func__, dcheck->dsn_name);
    } 
	else 
	{
        // 配置不存在，追加新配置
        fseek(file, 0, SEEK_END);
        if (fputs(odbc_dsn, file) == EOF) {
            zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#ODBC %s() Failed to write to file [%s]", __func__, dcheck->dsn_name);
            fclose(file);
            return FAIL;
        }
    }

    fclose(file);
    return ret;
}


int restore_file_size(const char *file_path, long size) 
{
    FILE *file;

    file = fopen(file_path, "r+");
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#ODBC %s() file[%s] size[%ld]", __func__, file_path, size);
    if (file == NULL) 
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#ODBC %s() Error opening file [%s]", __func__, file_path);
        return FAIL;
    }

    // 移动文件指针到指定的大小位置
    if (fseek(file, size, SEEK_SET) != 0) 
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#ODBC %s() Error seeking in file [%s]", __func__, file_path);
        fclose(file);
        return FAIL;
    }

    // 截断文件到指定的大小
    if (fflush(file) != 0) 
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#ODBC %s()Error flushing file [%s]", __func__, file_path);
        fclose(file);
        return FAIL;
    }

    int fd = fileno(file);
    if (ftruncate(fd, size) != 0) 
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#ODBC %s() Error truncating file [%s]", __func__, file_path);
        fclose(file);
        return FAIL;
    }

    fclose(file);
    return SUCCEED;
}
#endif	/* HAVE_UNIXODBC */
