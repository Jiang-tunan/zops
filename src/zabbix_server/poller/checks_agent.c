/*
** tognix
** Copyright (C) 2001-2023 tognix SIA
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
 * Purpose: retrieve data from tognix agent                                   *
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
				SET_MSG_RESULT(result, zbx_strdup(NULL, "Not supported by tognix Agent"));

			ret = NOTSUPPORTED;
		}
		else if (0 == strcmp(s.buffer, ZBX_ERROR))
		{
			SET_MSG_RESULT(result, zbx_strdup(NULL, "tognix Agent non-critical error"));
			ret = AGENT_ERROR;
		}
		else if (0 == received_len)
		{
			SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Received empty response from tognix Agent at [%s]."
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

	// zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s host:'%s' key:'%s' ", __func__, item->host.host, item->key);
	

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

		//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s host:'%s' item:%s, key:'%s' ", __func__, item->host.host, name, v_keys[i + 1]);
		AGENT_RESULT tmp_result;
		zbx_init_agent_result(&tmp_result);
		if (SUCCEED == get_value_agent(item, &tmp_result) &&
							NULL != (pvalue = ZBX_GET_TEXT_RESULT(&tmp_result)))
		{
			ret = SUCCEED;
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

// agent 单设备添加 使用该函数进行连通性校验
int	get_value_agent_single(DC_ITEM *item, AGENT_RESULT *result)
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
	if (SUCCEED == tognix_tcp_connect(&s, CONFIG_SOURCE_IP, item->interface.addr, item->interface.port, 2,
			item->host.tls_connect, tls_arg1, tls_arg2, SOCK_STREAM))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#AGENT Sending [%s]", item->key);
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
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#AGENT ret [%d]", ret);
	if (SUCCEED == ret)
	{
		zabbix_log(LOG_LEVEL_DEBUG, "get value from agent result: '%s'", __func__, s.buffer);

		if (0 == strcmp(s.buffer, ZBX_NOTSUPPORTED))
		{
			/* 'ZBX_NOTSUPPORTED\0<error message>' */
			if (sizeof(ZBX_NOTSUPPORTED) < s.read_bytes)
				SET_MSG_RESULT(result, zbx_dsprintf(NULL, "%s", s.buffer + sizeof(ZBX_NOTSUPPORTED)));
			else
				SET_MSG_RESULT(result, zbx_strdup(NULL, "Not supported by tognix Agent"));

			ret = NOTSUPPORTED;
		}
		else if (0 == strcmp(s.buffer, ZBX_ERROR))
		{
			SET_MSG_RESULT(result, zbx_strdup(NULL, "tognix Agent non-critical error"));
			ret = AGENT_ERROR;
		}
		else if (0 == received_len)
		{
			SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Received empty response from tognix Agent at [%s]."
					" Assuming that agent dropped connection because of access permissions.",
					item->interface.addr));
			ret = NETWORK_ERROR;
		}
		else
		{
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
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#AGENT End of %s():%s", __func__, zbx_result_string(ret));
	return ret;

}

int tognix_tcp_connect(zbx_socket_t *s, const char *source_ip, const char *ip, unsigned short port, int timeout,
		unsigned int tls_connect, const char *tls_arg1, const char *tls_arg2, int type)
{
	if (ZBX_TCP_SEC_UNENCRYPTED != tls_connect && ZBX_TCP_SEC_TLS_CERT != tls_connect &&
			ZBX_TCP_SEC_TLS_PSK != tls_connect)
	{
		THIS_SHOULD_NEVER_HAPPEN;
		return FAIL;
	}

	int		ret = FAIL;
	struct addrinfo	*ai = NULL, hints;
	struct addrinfo	*ai_bind = NULL;
	char		service[8], *error = NULL;
	void		(*func_socket_close)(zbx_socket_t *s);
	struct timeval timeout_val;

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#AGENT %s() before create socket for ip [%s]:%hu", __func__, ip, port);
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
	const char	*server_name = NULL;
#endif

	memset(s, 0, sizeof(zbx_socket_t));
	s->buf_type = ZBX_BUF_TYPE_STAT;

	if (SOCK_DGRAM == type && (ZBX_TCP_SEC_TLS_CERT == tls_connect || ZBX_TCP_SEC_TLS_PSK == tls_connect))
	{
		THIS_SHOULD_NEVER_HAPPEN;
		return FAIL;
	}
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
	if (ZBX_TCP_SEC_TLS_PSK == tls_connect && '\0' == *tls_arg1)
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() cannot connect with PSK: PSK not available", __func__);
		return FAIL;
	}
#else
	if (ZBX_TCP_SEC_TLS_CERT == tls_connect || ZBX_TCP_SEC_TLS_PSK == tls_connect)
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() support for TLS was not compiled in", __func__);
		return FAIL;
	}
#endif
	zbx_snprintf(service, sizeof(service), "%hu", port);
	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = type;

	if (0 != getaddrinfo(ip, service, &hints, &ai))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() cannot resolve [%s]", __func__, ip);
		goto out;
	}

	if (FAIL == (s->socket = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol)))
	{

		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() cannot create socket [[%s]:%hu]: %s",
							 __func__, ip, port, strerror_from_system(zbx_socket_last_error()));
		goto out;
	}

	timeout_val.tv_sec = timeout;
	timeout_val.tv_usec = 0;  

	// 设置发送超时
	if (setsockopt(s->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout_val, sizeof(timeout_val)) < 0)
	{

		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() setsockopt SO_SNDTIMEO failed for [[%s]:%hu]: %s",
							 __func__, ip, port, strerror_from_system(zbx_socket_last_error()));
		func_socket_close(s);
		goto out;
	}

	// 设置接收超时 ***暂时不对接收超时做处理***
	if (setsockopt(s->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_val, sizeof(timeout_val)) < 0)
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() setsockopt SO_RCVTIMEO failed for [[%s]:%hu]: %s",
							 __func__, ip, port, strerror_from_system(zbx_socket_last_error()));
		func_socket_close(s);
		goto out;
	}

	func_socket_close = (SOCK_STREAM == type ? zbx_tcp_close : zbx_udp_close);

	if (NULL != source_ip)
	{
		memset(&hints, 0x00, sizeof(struct addrinfo));

		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = type;
		hints.ai_flags = AI_NUMERICHOST;

		if (0 != getaddrinfo(source_ip, NULL, &hints, &ai_bind))
		{
			zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() invalid source IP address [%s]", __func__, ip);
			func_socket_close(s);
			goto out;
		}

		if (ZBX_PROTO_ERROR == zbx_bind(s->socket, ai_bind->ai_addr, ai_bind->ai_addrlen))
		{
			zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() bind() failed: %s", __func__, strerror_from_system(zbx_socket_last_error()));
			func_socket_close(s);
			goto out;
		}
	}
	if (ZBX_PROTO_ERROR == connect(s->socket, ai->ai_addr, (socklen_t)ai->ai_addrlen))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#AGENT In %s() connect() failed: %s", __func__, strerror_from_system(zbx_socket_last_error()));
		goto out;
	}

	s->connection_type = ZBX_TCP_SEC_UNENCRYPTED;

#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
	if (NULL != ip && SUCCEED != zbx_is_ip(ip))
	{
		server_name = ip;
	}

	if ((ZBX_TCP_SEC_TLS_CERT == tls_connect || ZBX_TCP_SEC_TLS_PSK == tls_connect) &&
			SUCCEED != zbx_tls_connect(s, tls_connect, tls_arg1, tls_arg2, server_name, &error))
	{
		zbx_tcp_close(s);
		zbx_set_socket_strerror("TCP successful, cannot establish TLS to [[%s]:%hu]: %s", ip, port, error);
		zbx_free(error);
		goto out;
	}
#else
	ZBX_UNUSED(tls_arg1);
	ZBX_UNUSED(tls_arg2);
#endif
	zbx_strlcpy(s->peer, ip, sizeof(s->peer));
	ret = SUCCEED;
out:
	if (NULL != ai)
		freeaddrinfo(ai);

	if (NULL != ai_bind)
		freeaddrinfo(ai_bind);

	return ret;

}