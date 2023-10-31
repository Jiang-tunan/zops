/*
** Zops
** Copyright (C) 2001-2023 Zops SIA
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

#include "checks_agent.h"

#include "log.h"
#include "zbxsysinfo.h"

#if !(defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL))
extern unsigned char	program_type;
#endif

/******************************************************************************
 *                                                                            *
 * Purpose: retrieve data from Zops agent                                   *
 *                                                                            *
 * Parameters: item - item we are interested in                               *
 *                                                                            *
 * Return value: SUCCEED - data successfully retrieved and stored in result   *
 *                         and result_str (as string)                         *
 *               NETWORK_ERROR - network related error occurred               *
 *               NOTSUPPORTED - item not supported by the agent               *
 *               AGENT_ERROR - uncritical error on agent side occurred        *
 *               FAIL - otherwise                                             *
 *                                                                            *
 * Comments: error will contain error message                                 *
 *                                                                            *
 ******************************************************************************/
int	get_value_agent(const DC_ITEM *item, AGENT_RESULT *result)
{
	zbx_socket_t	s;
	const char	*tls_arg1, *tls_arg2;
	int		ret = SUCCEED;
	ssize_t		received_len;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() host:'%s' addr:'%s' key:'%s' conn:'%s'", __func__, item->host.host,
			item->interface.addr, item->key, zbx_tcp_connection_type_name(item->host.tls_connect));

	switch (item->host.tls_connect)
	{
		case ZBX_TCP_SEC_UNENCRYPTED:
			tls_arg1 = NULL;
			tls_arg2 = NULL;
			break;
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
		case ZBX_TCP_SEC_TLS_CERT:
			tls_arg1 = item->host.tls_issuer;
			tls_arg2 = item->host.tls_subject;
			break;
		case ZBX_TCP_SEC_TLS_PSK:
			tls_arg1 = item->host.tls_psk_identity;
			tls_arg2 = item->host.tls_psk;
			break;
#else
		case ZBX_TCP_SEC_TLS_CERT:
		case ZBX_TCP_SEC_TLS_PSK:
			SET_MSG_RESULT(result, zbx_dsprintf(NULL, "A TLS connection is configured to be used with agent"
					" but support for TLS was not compiled into %s.",
					get_program_type_string(program_type)));
			ret = CONFIG_ERROR;
			goto out;
#endif
		default:
			THIS_SHOULD_NEVER_HAPPEN;
			SET_MSG_RESULT(result, zbx_strdup(NULL, "Invalid TLS connection parameters."));
			ret = CONFIG_ERROR;
			goto out;
	}

	//创建一个scoket去获取agent数据
	if (SUCCEED == zbx_tcp_connect(&s, CONFIG_SOURCE_IP, item->interface.addr, item->interface.port, 0,
			item->host.tls_connect, tls_arg1, tls_arg2))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "Sending [%s]", item->key);

		if (SUCCEED != zbx_tcp_send(&s, item->key))
			ret = NETWORK_ERROR;
		else if (FAIL != (received_len = zbx_tcp_recv_ext(&s, 0, 0)))
			ret = SUCCEED;
		else if (SUCCEED == zbx_alarm_timed_out())
			ret = TIMEOUT_ERROR;
		else
			ret = NETWORK_ERROR;
	}
	else
		ret = NETWORK_ERROR;

	if (SUCCEED == ret)
	{
		zabbix_log(LOG_LEVEL_DEBUG, "get value from agent result: '%s'", __func__, s.buffer);

		if (0 == strcmp(s.buffer, ZBX_NOTSUPPORTED))
		{
			/* 'ZBX_NOTSUPPORTED\0<error message>' */
			if (sizeof(ZBX_NOTSUPPORTED) < s.read_bytes)
				SET_MSG_RESULT(result, zbx_dsprintf(NULL, "%s", s.buffer + sizeof(ZBX_NOTSUPPORTED)));
			else
				SET_MSG_RESULT(result, zbx_strdup(NULL, "Not supported by Zops Agent"));

			ret = NOTSUPPORTED;
		}
		else if (0 == strcmp(s.buffer, ZBX_ERROR))
		{
			SET_MSG_RESULT(result, zbx_strdup(NULL, "Zops Agent non-critical error"));
			ret = AGENT_ERROR;
		}
		else if (0 == received_len)
		{
			SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Received empty response from Zops Agent at [%s]."
					" Assuming that agent dropped connection because of access permissions.",
					item->interface.addr));
			ret = NETWORK_ERROR;
		}
		else
		{
			/** 解决一个zabbix的bug,该bug agent返回的字符串为下面格式字符串
			   sudo: /etc/sudoers is world writable
				sudo: no valid sudoers sources found, quitting
				sudo: unable to initialize policy plugin
				sudo: /etc/sudoers is world writable
				sudo: no valid sudoers sources found, quitting
			   	sudo: unable to initialize policy plugin
				[
				{ "{#SYSDESC}": "", "{#IFPHYSADDRESS}": "00:50:56:8f:0d:e6", "{#ENTPHYSICALSERIALNUM}": "", "{#ENTPHYSICALMODELNAME}": "" }
				]
			    解决办法: 如果最后一个字符为'[' 并且有'[' 字符，则判断是错误格式的字符串，截取[] 2个字符之间的数据。
			*/
			int pos = 0;
			char *p_value = NULL;
			int buf_len = strlen(s.buffer);
			if(buf_len > 0 && s.buffer[buf_len - 1] == ']') 
			{
				for(int i =0; i < buf_len; i ++){
					if(s.buffer[i] == '[') 
					{
						pos = i;
						break;
					}
				}
			}
			if(pos > 0){
				int new_len = buf_len - pos + 1;
				size_t		str_alloc = 0, str_offset = 0;
				zbx_strncpy_alloc(&p_value, &str_alloc, &str_offset, s.buffer+pos, new_len);
			}else{
				p_value = s.buffer;
			}
			zbx_set_agent_result_type(result, ITEM_VALUE_TYPE_TEXT, p_value);
		}
			
	}
	else
		SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Get value from agent failed: %s", zbx_socket_strerror()));

	zbx_tcp_close(&s);
out:
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

//  Agent扫描逻辑,key的数据格式为"discovery[{#SYSNAME}|system.hostname|{#SYSDESC}|system.sw.os|{#IFPHYSADDRESS}|system.hw.macaddr[,short]"
int	get_value_agent_discovery( DC_ITEM *item, AGENT_RESULT *result)
{
	int ret = FAIL;
	struct zbx_json		js;
	char		**pvalue;

	// zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s host:'%s' key:'%s' ", __func__, item->host.host, item->key);
	

	zbx_json_initarray(&js, ZBX_JSON_STAT_BUF_LEN);
	zbx_json_addobject(&js, NULL);
	zbx_json_addstring(&js, "{#SNMPINDEX}", "0", ZBX_JSON_TYPE_STRING);

	int key_size = 20;
	char *v_keys[20] = {0}; 
	
	char *tmp_key = strdup(item->key + 10); //跳转到"discovery[" 后面字符串
	zbx_split(tmp_key, "|", v_keys, &key_size); 

	for(int i = 0; i < key_size; i += 2)
	{
		char *name = v_keys[i];
		zbx_strscpy(item->key_orig, v_keys[i + 1]);
		item->key = item->key_orig;

		//zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s host:'%s' item:%s, key:'%s' ", __func__, item->host.host, name, v_keys[i + 1]);
		AGENT_RESULT tmp_result;

		if (SUCCEED == get_value_agent(item, &tmp_result) &&
							NULL != (pvalue = ZBX_GET_TEXT_RESULT(&tmp_result)))
		{
			ret = SUCCEED;

			// // 如果是macadress地址，可能有多个，每个拆分为单独的json值
			// if(0 == strcmp(name, "{#IFPHYSADDRESS}") && strcmp(*pvalue,",") > 0)
			// {
			// 	int num = 20;
			// 	char *macaddrs[20] = {0};
			// 	zbx_split(*pvalue, ",", macaddrs, &num);
			// 	for(int k = 0; k < num; k ++)
			// 	{
			// 		zbx_lrtrim(macaddrs[k], ZBX_WHITESPACE);
			// 		zbx_json_addstring(&js, name, macaddrs[k], ZBX_JSON_TYPE_STRING);
			// 	}
			// }
			// else
			// {
			// 	zbx_json_addstring(&js, name, *pvalue, ZBX_JSON_TYPE_STRING);
			// }
			zbx_json_addstring(&js, name, *pvalue, ZBX_JSON_TYPE_STRING);
		}
		else
			break;
		zbx_free_agent_result(&tmp_result);
	}
	zbx_json_close(&js);

	SET_TEXT_RESULT(result, zbx_strdup(NULL, js.buffer));

	zbx_json_free(&js);
	zbx_free(tmp_key);
	return ret;
}