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

#include "trapper_dproxy.h"


extern char	*CONFIG_SOURCE_IP;
extern int	CONFIG_TRAPPER_TIMEOUT;


int	dc_connect_to_proxy(const ZBX_DC_PROXY *proxy, zbx_socket_t *sock, int timeout)
{
	int		ret = FAIL;
	const char	*tls_arg1, *tls_arg2;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() address:%s port:%hu timeout:%d conn:%u", __func__, proxy->proxy_address,
			proxy->port, timeout, (unsigned int)proxy->tls_connect);

	switch (proxy->tls_connect)
	{
		case ZBX_TCP_SEC_UNENCRYPTED:
			tls_arg1 = NULL;
			tls_arg2 = NULL;
			break;
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
		case ZBX_TCP_SEC_TLS_CERT:
			tls_arg1 = proxy->tls_issuer;
			tls_arg2 = proxy->tls_subject;
			break;
		case ZBX_TCP_SEC_TLS_PSK:
			tls_arg1 = proxy->tls_psk_identity;
			tls_arg2 = proxy->tls_psk;
			break;
#else
		case ZBX_TCP_SEC_TLS_CERT:
		case ZBX_TCP_SEC_TLS_PSK:
			zabbix_log(LOG_LEVEL_ERR, "TLS connection is configured to be used with passive proxy \"%llu\""
					" but support for TLS was not compiled into 'TODO'.", proxy->hostid );
			ret = CONFIG_ERROR;
			goto out;
#endif
		default:
			THIS_SHOULD_NEVER_HAPPEN;
			goto out;
	}

	if (FAIL == (ret = zbx_tcp_connect(sock, CONFIG_SOURCE_IP, proxy->proxy_address, proxy->port, timeout,
			proxy->tls_connect, tls_arg1, tls_arg2)))
	{
		zabbix_log(LOG_LEVEL_ERR, "cannot connect to proxy \"%llu\": %s", proxy->hostid, zbx_socket_strerror());
		ret = NETWORK_ERROR;
	}
out:
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s connect proxy, result=%d,proxyid=%llu,ip=%s,port=%d", 
            __func__, ret, proxy->hostid, proxy->proxy_address, proxy->port);
	
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

static int	send_data_to_proxy(const ZBX_DC_PROXY *proxy, zbx_socket_t *sock, const char *data, size_t size,
		size_t reserved, int flags)
{
	int	ret;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (FAIL == (ret = zbx_tcp_send_ext(sock, data, size, reserved, flags, 0)))
	{
		zabbix_log(LOG_LEVEL_ERR, "cannot send data to proxy \"%llu\": %s", proxy->hostid, zbx_socket_strerror());

		ret = NETWORK_ERROR;
	}

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

static int	recv_data_from_proxy(const ZBX_DC_PROXY *proxy, zbx_socket_t *sock)
{
	int	ret;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (FAIL == (ret = zbx_tcp_recv(sock)))
	{
		zabbix_log(LOG_LEVEL_ERR, "cannot obtain data from proxy \"%llu\": %s", proxy->hostid,
				zbx_socket_strerror());
	}
	else
		zabbix_log(LOG_LEVEL_DEBUG, "obtained data from proxy \"%llu\": [%s]", proxy->hostid, sock->buffer);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}

static void	disconnect_proxy(zbx_socket_t *sock)
{
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	zbx_tcp_close(sock);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}
 
void dc_update_proxy_queue(ZBX_DC_PROXY *proxy)
{
	zbx_binary_heap_elem_t	elem;

	if (ZBX_LOC_POLLER == proxy->location)
		return;

	proxy->nextcheck = proxy->proxy_tasks_nextcheck;
	if (proxy->proxy_data_nextcheck < proxy->nextcheck)
		proxy->nextcheck = proxy->proxy_data_nextcheck;
	if (proxy->proxy_config_nextcheck < proxy->nextcheck)
		proxy->nextcheck = proxy->proxy_config_nextcheck;

	elem.key = proxy->hostid;
	elem.data = (const void *)proxy;

	if (ZBX_LOC_QUEUE != proxy->location)
	{
		proxy->location = ZBX_LOC_QUEUE;
		zbx_binary_heap_insert(&config->pqueue, &elem);
	}
	else
		zbx_binary_heap_update_direct(&config->pqueue, &elem);
}

int	dc_get_data_from_proxy(ZBX_DC_PROXY *proxy, const char *request, int config_timeout, 
		char **data, zbx_timespec_t *ts)
{
	
	int		ret=SUCCEED, flags = ZBX_TCP_PROTOCOL;
	char		*buffer = NULL;
	size_t		buffer_size, reserved = 0;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() request:'%s'", __func__, request);

	int request_len = strlen(request);
	if (0 != proxy->auto_compress)
	{
		if (SUCCEED != zbx_compress(request, request_len, &buffer, &buffer_size))
		{
			zabbix_log(LOG_LEVEL_ERR,"cannot compress data: %s", zbx_compress_strerror());
			ret = FAIL;
			goto out;
		}

		flags |= ZBX_TCP_COMPRESS;
		reserved = request_len;
	}
	zbx_socket_t s;
	if (SUCCEED != (ret = dc_connect_to_proxy(proxy, &s, CONFIG_TRAPPER_TIMEOUT)))
		goto out;
	zbx_socket_t *sock = &s;

	if (SUCCEED == (ret))
	{
		/* get connection timestamp if required */
		if (NULL != ts)
			zbx_timespec(ts);

		if (0 != proxy->auto_compress)
		{
			ret = send_data_to_proxy(proxy, sock, buffer, buffer_size, reserved, flags);
			zbx_free(buffer);
		}
		else
		{
			ret = send_data_to_proxy(proxy, sock, request, request_len, 0, flags);
		}

		if (SUCCEED == ret)
		{
			if (SUCCEED == (ret = recv_data_from_proxy(proxy, sock)))
			{
				if (0 != (sock->protocol & ZBX_TCP_COMPRESS))
					proxy->auto_compress = 1;

				if (!ZBX_IS_RUNNING())
				{
					int	flags_response = ZBX_TCP_PROTOCOL;

					if (0 != (sock->protocol & ZBX_TCP_COMPRESS))
						flags_response |= ZBX_TCP_COMPRESS;

					zbx_send_response_ext(sock, FAIL, "tognix server shutdown in progress", NULL,
							flags_response, config_timeout);

					zabbix_log(LOG_LEVEL_WARNING, "cannot process proxy data from passive proxy at"
							" \"%s\": tognix server shutdown in progress", sock->peer);
					ret = FAIL;
				}
				else
				{
					ret = zbx_send_proxy_data_response(proxy, sock, NULL, SUCCEED,
							ZBX_PROXY_UPLOAD_UNDEFINED);

					if (SUCCEED == ret)
						*data = zbx_strdup(*data, sock->buffer);
				}
			}
		}

		disconnect_proxy(sock);
	}
out:
	zbx_free(buffer);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));

	return ret;
}


void dc_get_proxy(DC_PROXY *dst_proxy, const ZBX_DC_PROXY *src_proxy)
{
	const ZBX_DC_HOST	*host;
	ZBX_DC_INTERFACE_HT	*interface_ht, interface_ht_local;

	dst_proxy->hostid = src_proxy->hostid;
	dst_proxy->proxy_config_nextcheck = src_proxy->proxy_config_nextcheck;
	dst_proxy->proxy_data_nextcheck = src_proxy->proxy_data_nextcheck;
	dst_proxy->proxy_tasks_nextcheck = src_proxy->proxy_tasks_nextcheck;
	dst_proxy->last_cfg_error_time = src_proxy->last_cfg_error_time;
	zbx_strlcpy(dst_proxy->version_str, src_proxy->version_str, sizeof(dst_proxy->version_str));
	dst_proxy->version_int = src_proxy->version_int;
	dst_proxy->compatibility = src_proxy->compatibility;
	dst_proxy->lastaccess = src_proxy->lastaccess;
	dst_proxy->auto_compress = src_proxy->auto_compress;
	dst_proxy->last_version_error_time = src_proxy->last_version_error_time;

	dst_proxy->revision = src_proxy->revision;
	dst_proxy->macro_revision = config->um_cache->revision;

	if (NULL != (host = (const ZBX_DC_HOST *)zbx_hashset_search(&config->hosts, &src_proxy->hostid)))
	{
		zbx_strscpy(dst_proxy->host, host->host);
		zbx_strscpy(dst_proxy->proxy_address, src_proxy->proxy_address);

		dst_proxy->tls_connect = host->tls_connect;
		dst_proxy->tls_accept = host->tls_accept;
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
		zbx_strscpy(dst_proxy->tls_issuer, host->tls_issuer);
		zbx_strscpy(dst_proxy->tls_subject, host->tls_subject);

		if (NULL == host->tls_dc_psk)
		{
			*dst_proxy->tls_psk_identity = '\0';
			*dst_proxy->tls_psk = '\0';
		}
		else
		{
			zbx_strscpy(dst_proxy->tls_psk_identity, host->tls_dc_psk->tls_psk_identity);
			zbx_strscpy(dst_proxy->tls_psk, host->tls_dc_psk->tls_psk);
		}
#endif
	}
	else
	{
		/* DCget_proxy() is called only from DCconfig_get_proxypoller_hosts(), which is called only from */
		/* process_proxy(). So, this branch should never happen. */
		*dst_proxy->host = '\0';
		*dst_proxy->proxy_address = '\0';
		dst_proxy->tls_connect = ZBX_TCP_SEC_TLS_PSK;	/* set PSK to deliberately fail in this case */
#if defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
		*dst_proxy->tls_psk_identity = '\0';
		*dst_proxy->tls_psk = '\0';
#endif
		THIS_SHOULD_NEVER_HAPPEN;
	}

	interface_ht_local.hostid = src_proxy->hostid;
	interface_ht_local.type = INTERFACE_TYPE_UNKNOWN;

	if (NULL != (interface_ht = (ZBX_DC_INTERFACE_HT *)zbx_hashset_search(&config->interfaces_ht,
			&interface_ht_local)))
	{
		const ZBX_DC_INTERFACE	*interface = interface_ht->interface_ptr;

		zbx_strscpy(dst_proxy->addr_orig, interface->useip ? interface->ip : interface->dns);
		zbx_strscpy(dst_proxy->port_orig, interface->port);
	}
	else
	{
		*dst_proxy->addr_orig = '\0';
		*dst_proxy->port_orig = '\0';
	}

	dst_proxy->addr = NULL;
	dst_proxy->port = 0;
}

int	dc_proxy_send_configuration(ZBX_DC_PROXY *proxy, const zbx_config_vault_t *config_vault)
{
	char				*error = NULL, *buffer = NULL;
	int				ret, flags = ZBX_TCP_PROTOCOL, loglevel;
	
	struct zbx_json			j;
	struct zbx_json_parse		jp;
	size_t				buffer_size, reserved = 0;
	zbx_proxyconfig_status_t	status;
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s begin. proxy=%llu", __func__, proxy->hostid);
	
	zbx_json_init(&j, 512 * ZBX_KIBIBYTE);
	zbx_json_addstring(&j, ZBX_PROTO_TAG_REQUEST, ZBX_PROTO_VALUE_PROXY_CONFIG, ZBX_JSON_TYPE_STRING);
	
	zbx_socket_t s;
	if (SUCCEED != (ret = dc_connect_to_proxy(proxy, &s, CONFIG_TRAPPER_TIMEOUT)))
		goto out;
	zbx_socket_t *sock = &s;
	if (SUCCEED != (ret = send_data_to_proxy(proxy, sock, j.buffer, j.buffer_size, reserved, ZBX_TCP_PROTOCOL)))
		goto clean;

	if (FAIL == (ret = zbx_tcp_recv_ext(sock, 0, 0)))
	{
		zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s receive proxy config info fail. proxyid=%llu, error=%s",
				__func__, proxy->hostid, zbx_socket_strerror());
		goto clean;
	}
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s recv from proxy. proxy=%llu,  buffer: %s", __func__, proxy->hostid, sock->buffer);
	
	if (SUCCEED != (ret = zbx_json_open(sock->buffer, &jp)))
	{
		zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s parse proxy config info fail. proxyid=%llu, error=%s",
				__func__, proxy->hostid, zbx_socket_strerror());
		goto clean;
	}

	zbx_json_clean(&j);
	DC_PROXY dst_proxy;
    dc_get_proxy(&dst_proxy, proxy);
	dst_proxy.isfullsync = 1;
	if (SUCCEED != (ret = zbx_proxyconfig_get_data(&dst_proxy, &jp, &j, &status, config_vault, &error)))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s get config data fail. proxyid=%llu,ret=%d,error=%s",
				__func__, proxy->hostid, ret, error);
		goto clean;
	}
	
	if(0 == zbx_strcmp_null(j.buffer, "{}")){
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s get config data fail2. proxyid=%llu",
				__func__, proxy->hostid);
		goto clean;
	}

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s proxyconfig get data proxyid=%llu,result=%d,auto_compress=%d,bufferlen=%d", 
					__func__,proxy->hostid, ret, proxy->auto_compress, strlen(j.buffer));
	if (0 != proxy->auto_compress)
	{
		if (SUCCEED != zbx_compress(j.buffer, j.buffer_size, &buffer, &buffer_size))
		{
			zabbix_log(LOG_LEVEL_ERR,"#TOGNIX#%s cannot compress data. error=%s", __func__, zbx_compress_strerror());
			ret = FAIL;
			goto clean;
		}

		flags |= ZBX_TCP_COMPRESS;
		reserved = j.buffer_size;
		zbx_json_free(&j);	/* json buffer can be large, free as fast as possible */
	}

	loglevel = (ZBX_PROXYCONFIG_STATUS_DATA == status ? LOG_LEVEL_WARNING : LOG_LEVEL_DEBUG);

	if (0 != proxy->auto_compress)
	{
		zabbix_log(loglevel, "%s sending configuration data to proxy \"%llu\" at \"%s\", datalen "
				ZBX_FS_SIZE_T ", bytes " ZBX_FS_SIZE_T " with compression ratio %.1f", 
				__func__, proxy->hostid, sock->peer, (zbx_fs_size_t)reserved, (zbx_fs_size_t)buffer_size,
				(double)reserved / buffer_size);

		ret = send_data_to_proxy(proxy, sock, buffer, buffer_size, reserved, flags);
		zbx_free(buffer);		/* json buffer can be large, free as fast as possible */
	}
	else
	{
		zabbix_log(loglevel, "%s sending configuration data to proxy \"%llu\" at \"%s\", datalen "
				ZBX_FS_SIZE_T, __func__, proxy->hostid, sock->peer, (zbx_fs_size_t)j.buffer_size);

		ret = send_data_to_proxy(proxy, sock, j.buffer, j.buffer_size, reserved, flags);
		zbx_json_free(&j);	/* json buffer can be large, free as fast as possible */
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s sending data to proxy %llu, result=%d", 
					__func__,proxy->hostid, ret);

	 
	if (SUCCEED == ret)
	{
		if (SUCCEED != (ret = zbx_recv_response(sock, 1, &error)))
		{
			zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s cannot send configuration data to proxy." \
					"proxyid=%llu,ip=%s,error=%s", __func__, proxy->hostid, sock->peer, error);
		}
		else
		{
			if (SUCCEED != zbx_json_open(sock->buffer, &jp))
			{
				zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s invalid configuration data response received from proxy." \
						"proxyid=%llu,ip=%s,error=%s", __func__, proxy->hostid, sock->peer, zbx_json_strerror());
			}
			else
			{
				char	*version_str;

				version_str = zbx_get_proxy_protocol_version_str(&jp);
				zbx_strlcpy(proxy->version_str, version_str, sizeof(proxy->version_str));
				proxy->version_int = zbx_get_proxy_protocol_version_int(version_str);
				proxy->auto_compress = (0 != (sock->protocol & ZBX_TCP_COMPRESS) ? 1 : 0);
				proxy->lastaccess = time(NULL);
				zbx_free(version_str);
			 
			}
		}
	}
clean:
	disconnect_proxy(sock);
out:
	zbx_free(buffer);
	zbx_free(error);
	zbx_json_free(&j);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s end. proxyid=%llu,result=%d", 
					__func__,proxy->hostid, ret);
	return ret;
}


/**
 * 处理从代理端返回的数据
*/
int discovery_rules_from_proxy(zbx_socket_t *sock, char *resp, int config_timeout)
{
    int ret = SUCCEED;
    if ('{' == *resp)	/* JSON protocol */
	{
		struct zbx_json_parse	jp;
		char tstr[256]="", cmd[256] = "";
		if (SUCCEED != zbx_json_open(resp, &jp))
		{
			// zbx_send_response(sock, FAIL, zbx_json_strerror(), config_timeout);
			zabbix_log(LOG_LEVEL_WARNING, "received invalid JSON object from %s: %s",
					sock->peer, zbx_json_strerror());
			return FAIL;
		}

		zbx_json_value_by_name(&jp, ZBX_PROTO_TAG_REQUEST, cmd, sizeof(cmd), NULL);
		
        if (0 == strcmp(cmd, DISCOVERY_RULES_SINGLE_SCAN)){ // 代理端单设备扫描返回数据，必须在服务端进行处理
            discovery_rules_state(sock, resp, config_timeout);
        }else{  //代理端自动扫描返回数据，直接返回给php端
            ret == tognix_tcp_send(sock, resp, strlen(resp), config_timeout);
        }
        return ret;
    }
    zbx_tcp_close(sock);        
}

 

//用户扫描任务创建
int	user_discover_proxy_create(int proxyhostid, const char *session, const struct zbx_json_parse *jp)
{
    char			*sql = NULL;
	size_t			sql_alloc = 0, sql_offset = 0;
	DB_RESULT		result;
	DB_ROW			row;
	int             ret = SUCCEED, ipnumber=0;
	
	zbx_user_discover_drule_t *dr = NULL;
	
	ret = parse_rules_activate(jp, &dr);
	
	if (SUCCEED != ret)  goto out;
    

    // 删除超时的扫描
    zbx_db_execute("delete from proxy_dhosts where endtime<%d", time(NULL));

	zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, "select id,druleid,session,hostids,begintime" \ 
        " from proxy_dhosts where druleid=%llu and session='%s' ", \
         dr->druleid, session);
	result = zbx_db_select(sql);
	while (NULL != (row = zbx_db_fetch(result)))
	{
        return ret;
	}
 
	result = zbx_db_select("select druleid, iprange from drules where druleid=%llu", dr->druleid);
	while (NULL != (row = zbx_db_fetch(result)))
	{
		zbx_iprange_t iprange;
		if (SUCCEED != zbx_iprange_parse(&iprange, row[1]))
		{
			zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s ruleid:%s: wrong format of IP range:%s",__func__, row[0], row[1]);
			continue;
		}
		ipnumber = zbx_iprange_volume(&iprange);
	}

    int begintime = time(NULL);
    int endtime =  begintime + ipnumber*USER_DISCOVER_IP_TIME_OUT + USER_DISCOVER_EXTRA_TIME_OUT;
    zbx_db_execute("insert into proxy_dhosts (druleid,session,hostids,ipnumber,begintime,endtime) " \
                  " values(%llu, '%s', '', %d, %d, %d)", 
        dr->druleid, session, ipnumber, begintime, endtime);
out:
	return ret;
}


// proxy程序处理server的请求后返回应答
static char *build_proxy_progress_resp(char *session, char *request)
{
	int ret = FAIL, depth = 0, id = 0;
	struct zbx_json_parse jp, jp_data;
	struct zbx_json json;
    char tstr[128], *p = NULL, *response;
    DB_RESULT		result;
	DB_ROW			row;
	
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);
	if (SUCCEED != (ret = zbx_json_open(request, &jp))){
		goto out;
	}
    
    memset(tstr, 0 , sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp, "result", tstr, sizeof(tstr), NULL))
	{
        ret = zbx_atoi(tstr);
    }else{
        ret = FAIL;
    }

    if(SUCCEED != ret) return request;

    zbx_uint64_t druleid = 0;
    if (SUCCEED == zbx_json_brackets_by_name(&jp, ZBX_PROTO_TAG_DATA, &jp_data))
	{
		while (NULL != (p = zbx_json_next(&jp_data, p)))
		{
			struct zbx_json_parse jp_obj;
			if (SUCCEED == zbx_json_brackets_open(p, &jp_obj))
			{
				// 从当前对象中提取druleid的值
                memset(tstr, 0 , sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&jp_obj, "druleid", tstr, sizeof(tstr), NULL))
				{
					zbx_lrtrim(tstr, ZBX_WHITESPACE);
					zbx_is_uint64(tstr, &druleid);
                    break;
                }
            }
        }
    }
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s druleid=%d, session=%s", __func__, druleid, session);
	
    result = zbx_db_select("select id,druleid,session,hostids" \ 
                    " from proxy_dhosts where druleid=%llu and session='%s' ", \
                    druleid, session);
    char *hostids = NULL;
	while (NULL != (row = zbx_db_fetch(result)))
	{
        id = zbx_atoi(row[0]);
        hostids = zbx_strdup(NULL, row[3]);
	}
    
    if(NULL != zbx_strstr(request, "\"progress\":100,")){
        zbx_db_execute("delete from proxy_dhosts where druleid=%llu and session='%s' ",
                    druleid, session);
    }else if(NULL != hostids){
        ret = zbx_db_execute("update proxy_dhosts set hostids='' WHERE id=%d", id);
    }
    
    zbx_map_t dc_map;
    dc_map.name = "hostids";
    dc_map.value = hostids;
	copy_original_json2(ZBX_JSON_TYPE_OBJECT, &jp, &json, depth, &dc_map);

out:
	response = strdup(json.buffer);
	zbx_json_free(&json);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s response=%s", __func__, response);
	
	return response;
}

/**
 * 处理从php端发过来的请求，该请求必须发到代理服务端处理
*/
int discovery_rules_to_proxy_handle(void* arg)
{
    proxy_thread_arg *proxy_arg = (proxy_thread_arg *)arg;

    char *cmd = proxy_arg->cmd;
    char *session = proxy_arg->session;
    zbx_uint64_t proxyhostid = proxy_arg->proxyhostid;
    zbx_socket_t *sock = proxy_arg->sock;
    const char *request = proxy_arg->request;
    int config_timeout = proxy_arg->config_timeout;
    const zbx_config_vault_t *config_vault = proxy_arg->config_vault;

    int		ret = FAIL, try_count = 0;
    zbx_timespec_t	ts;
    char		*response = NULL;
    ZBX_DC_PROXY *proxy;
    zbx_socket_t *proxy_sock = NULL;

    struct zbx_json_parse	jp;
    if (SUCCEED != zbx_json_open(request, &jp))
        return FAIL;
    
 
    if(NULL != (proxy = (ZBX_DC_PROXY *)zbx_hashset_search(&config->proxies, &proxyhostid)))
    {
        zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s hostid=%llu,proxy_address=%s,request=%s",
             __func__, proxy->hostid,proxy->proxy_address,request);
        
        proxy->port = ZBX_DEFAULT_SERVER_PORT;
        proxy->tls_connect = 1; 

        if(0 == strcmp(cmd, DISCOVERY_RULES_ACTIVATE))
        {
            if(DISCOVERY_RESULT_SUCCESS != (ret = user_discover_proxy_create(proxyhostid, session, &jp)))
                goto out;
        }
 
        if(0 == strcmp(cmd, DISCOVERY_RULES_ACTIVATE) ||
			0 == strcmp(cmd, DISCOVERY_RULES_SINGLE_SCAN))
        {
			try_count = 0;
			do{
            	ret = dc_proxy_send_configuration(proxy, config_vault);
				if(SUCCEED == ret) break;
				zbx_sleep(1);
				try_count ++;
			}while (try_count < MAX_SYNC_PROXY_CONFIG_TIMES);
        }

		try_count = 0;
		do{
			ret = dc_get_data_from_proxy(proxy, request, config_timeout, &response, &ts);
			if(SUCCEED == ret) break;
			zbx_sleep(1);
			try_count ++;
		}while (try_count < MAX_SEND_PROXY_DATA_TIMES);
        

        zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s proxy response. result=%d, resp=%s", 
			__func__, ret, print_content(response));
        if (SUCCEED != (ret)){
		    goto out;
        }else if(SUCCEED == ret && NULL != response){
            if(0 == strcmp(cmd, DISCOVERY_RULES_PROGRESS)){
                response = build_proxy_progress_resp(session, response);
            }
        }
    } 

out:
    if(NULL == response){
        response = create_activate_or_stop_json(ret, cmd, session, &jp);
    }
    discovery_rules_from_proxy(sock, response, config_timeout);
    zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s ret=%d", __func__,ret);
    zbx_free(response);
    return ret;
}


int discovery_rules_proxy(char *cmd, char *session, int proxyhostid, zbx_socket_t *sock, const char *request, 
    int config_timeout, const zbx_config_vault_t *config_vault)
{
    pthread_t proxy_thread;
    proxy_thread_arg proxy_arg;

    zbx_socket_t *resp_sock = zbx_malloc(resp_sock, sizeof(zbx_socket_t));
	memcpy(resp_sock, sock, sizeof(sock));
	sock->socket = -1;

    proxy_arg.cmd = cmd;
    proxy_arg.session = session;
    proxy_arg.proxyhostid = proxyhostid;
    proxy_arg.sock = resp_sock;
    proxy_arg.request = request;
    proxy_arg.config_timeout = config_timeout;
    proxy_arg.config_vault = config_vault;
 
    if (pthread_create(&proxy_thread, NULL, discovery_rules_to_proxy_handle, &proxy_arg))
    {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s. create thread fail.",__func__);
        return FAIL;
    } 
}