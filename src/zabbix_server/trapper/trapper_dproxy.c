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
#include "../../libs/zbxcomms/comms.h"


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
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s connect proxy, result=%d, sock=%d, tls_connect=%d, timeout=%d,proxyid=%llu,ip=%s,port=%d", 
            __func__, ret, sock->socket, proxy->tls_connect,timeout, proxy->hostid, proxy->proxy_address, proxy->port);
	
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

	// if (FAIL == (ret = zbx_tcp_recv(sock)))
	if (FAIL == (ret = zbx_tcp_recv_ext(sock, CONFIG_TRAPPER_TIMEOUT, ZBX_TCP_LARGE)))
	{
		zabbix_log(LOG_LEVEL_ERR, "cannot obtain data from proxy \"%llu\": %s", proxy->hostid,
				zbx_socket_strerror());
	}
	
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
	
	int		ret=SUCCEED, flags = ZBX_TCP_PROTOCOL, recv_size = 0;
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
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s send data to proxy ret=%d, sock=%d, flags=%d, auto_compress=%d, request=%s",
			 __func__,ret, sock->socket, flags, proxy->auto_compress, request);
		if (SUCCEED == ret)
		{
			recv_size = recv_data_from_proxy(proxy, sock);
			if (0 < recv_size){
				ret = SUCCEED;
				*data = zbx_strdup(*data, sock->buffer);
			}else{
				ret = FAIL;
			}
			zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s recv data from proxy ret=%d, sock=%d, recv_size=%d, response=%s",  __func__, ret, sock->socket,  recv_size, sock->buffer);
		}
	}
	disconnect_proxy(sock);
out:
	zbx_free(buffer);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __func__, zbx_result_string(ret));
	// 转换 dc_get_data_from_proxy 返回的ret值
	switch(ret)
	{
		case SUCCEED:
			ret = DISCOVERY_RESULT_SUCCESS;
			break;
		case NETWORK_ERROR:
			ret = DISCOVERY_RESULT_PORXY_CONN_FAIL;
			break;
		default:
			ret = DISCOVERY_RESULT_PORXY_SCAN_FAIL;
			break;
	}
	return ret;
}

/**
 * 处理从代理端返回的数据
 * sock php请求连接的sock
*/
int discovery_rules_from_proxy(zbx_socket_t *sock, char *resp, int config_timeout, zbx_ipc_async_socket_t *rtc)
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
            discovery_rules_state(1, sock, resp, config_timeout, rtc);
        }else{  //代理端自动扫描返回数据，直接返回给php端
            ret == tognix_tcp_send(sock, resp, strlen(resp), config_timeout);
        }
        return ret;
    }
         
}

// 服务端处理代理端返回的进程查询应答，处理后再返回给前端显示
static char *server_build_proxy_progress_resp(int fullsync, char *session, char *proxy_resp)
{
	int ret = FAIL, depth = 0, id = 0, endtime = 0, nowtime = 0;
	struct zbx_json_parse jp, jp_data;
	struct zbx_json json;
    char tstr[128], *p = NULL, *response, *hostids = NULL;
    DB_RESULT		result;
	DB_ROW			row;

	nowtime = time(NULL);
	
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);
	if (SUCCEED != (ret = zbx_json_open(proxy_resp, &jp))){
		goto out;
	}
    
    memset(tstr, 0 , sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp, "result", tstr, sizeof(tstr), NULL))
	{
        ret = zbx_atoi(tstr);
    }else{
        ret = FAIL;
    }

    if(SUCCEED != ret) return proxy_resp;
	
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s fullsync=%d, session=%s", __func__, fullsync, session);
	
    result = zbx_db_select("select id,druleid,session,all_hostids,hostids,endtime" \ 
                    " from proxy_dhosts where session='%s' ",  session);

	while (NULL != (row = zbx_db_fetch(result)))
	{
        id = zbx_atoi(row[0]);
		if(fullsync){
			hostids = zbx_strdup(NULL, row[3]);
		}else{
			hostids = zbx_strdup(NULL, row[4]);
        }
		endtime = zbx_atoi(row[5]);
	}
	zbx_db_free_result(result);
   
    if(NULL != zbx_strstr(proxy_resp, "\"progress\":100,")){
		if(nowtime >= endtime){
       		zbx_db_execute("delete from proxy_dhosts where session='%s' ", session);
		}
		else{
			zbx_db_execute("update proxy_dhosts set progress=100 where session='%s' ", session);
		}
    }else if(NULL != hostids && strlen(hostids) > 0){
        ret = zbx_db_execute("update proxy_dhosts set hostids='' WHERE id=%d", id);
    }
    
    zbx_map_t dc_map;
    dc_map.name = "hostids";
    dc_map.value = hostids;
	copy_original_json2(ZBX_JSON_TYPE_OBJECT, &jp, &json, depth, &dc_map);

out:
	response = strdup(json.buffer);
	zbx_json_free(&json);
	zbx_free(hostids);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s response=%s", __func__, response);
	
	return response;
}
void	zbx_rtc_notify_config_fullsync(int proxyhostid, int config_timeout, zbx_ipc_async_socket_t *rtc)
{
	char data[128] = {0};
	zbx_snprintf(data,sizeof(data),"%d",proxyhostid);
	zabbix_log(LOG_LEVEL_CRIT, "#TOGNIX#%s configuration syncer notification, proxyhostid=%s", __func__, data);
	if (FAIL == zbx_ipc_async_socket_send(rtc, ZBX_RTC_PROXYPOLLER_PROCESS, data, strlen(data)))
	{
		zabbix_log(LOG_LEVEL_CRIT, "#TOGNIX#cannot send proxypoller process notification");
	}

	if (FAIL == zbx_ipc_async_socket_flush(rtc, config_timeout))
	{
		zabbix_log(LOG_LEVEL_CRIT, "cannot flush configuration syncer notification");
	}
}
 
/**
 * 处理从php端发过来的请求，该请求必须发到代理服务端处理
*/
int do_proxy_discovery_rules(void* arg)
{
    proxy_thread_arg *proxy_arg = (proxy_thread_arg *)arg;

    char *cmd = proxy_arg->cmd;
    char *session = proxy_arg->session;
    zbx_uint64_t proxyhostid = proxy_arg->proxyhostid;
    zbx_socket_t *sock = proxy_arg->sock;
    const char *request = proxy_arg->request;
    int config_timeout = proxy_arg->config_timeout;
	zbx_ipc_async_socket_t *rtc = proxy_arg->rtc;

    int		ret = DISCOVERY_RESULT_PORXY_SCAN_FAIL,ret_sync_cfg = FAIL, try_count = 0, fullsync = 0, isproxyfinish = 0;
    char		*response = NULL, *resp_session = NULL;
    ZBX_DC_PROXY *proxy;
	zbx_timespec_t	ts;
    zbx_socket_t *proxy_sock = NULL;
	zbx_uint64_t druleid = 0;

    struct zbx_json_parse	jp;
    if (SUCCEED != zbx_json_open(request, &jp))
        return FAIL;

    if(NULL != (proxy = (ZBX_DC_PROXY *)zbx_hashset_search(&config->proxies, &proxyhostid)))
    {
        zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s hostid=%llu,proxy_address=%s,request=%s",
             __func__, proxy->hostid,proxy->proxy_address, request);
        
        proxy->port = ZBX_DEFAULT_SERVER_PORT;
        proxy->tls_connect = 1; 

		// 同步到最新数据到代理服务器(现在是全量，有待优化)
        if(0 == strcmp(cmd, DISCOVERY_RULES_ACTIVATE) ||
			0 == strcmp(cmd, DISCOVERY_RULES_SINGLE_SCAN))
        {
			// 通知proxypoller进程去同步配置
			zbx_rtc_notify_config_fullsync(proxy->hostid, config_timeout, rtc);
        }

		// 查询进度，有些情况从本地查询进度，有些情况发到代理端查询进度
        if(0 == strcmp(cmd, DISCOVERY_RULES_PROGRESS))
		{
			isproxyfinish = is_proxy_discover_finish(session, &jp, &druleid, &fullsync);
			if(fullsync || isproxyfinish){
				// 如果是fullsync,直接返回服务端session对应的全量hostid
				// 如果代理服务端已经扫描处理完成，剩下部分是服务端处理，主要是Nutanix,WMWare扫描使用
				response = user_discover_progress(1, session, &jp);
				goto out;
			}
		}

		// 把数据转发到代理服务器处理
		try_count = 0;
		do{
			ret = dc_get_data_from_proxy(proxy, request, config_timeout, &response, &ts);
			if(SUCCEED == ret || try_count > MAX_SEND_PROXY_DATA_TIMES){ 
				break;
			}
			zbx_sleep(MAX_SEND_PROXY_SLEEP_TIME);
			try_count ++;
		}while (1);
		
        zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s proxy response. result=%d, resp=%s", 
			__func__, ret, print_content(response));
        if (SUCCEED != ret){
			// 进度查询不到要返回出错
			if(0 == strcmp(cmd, DISCOVERY_RULES_PROGRESS)){
				ret = DISCOVERY_RESULT_SUCCESS;
			}
			// 没有发到代理端，代理端数据没有返回，则直接返回给php端
			response = create_activate_or_stop_json(ret, cmd, session, &jp);
			goto out;
        }else if(SUCCEED == ret && NULL != response){
			// 没有代理端数据已经返回，则处理
            if(0 == strcmp(cmd, DISCOVERY_RULES_PROGRESS)){
				server_discovery_proxy_progress_finish(response, &resp_session);
                response = server_build_proxy_progress_resp(fullsync, resp_session, response);
            }
			else if(0 == strcmp(cmd, DISCOVERY_RULES_ACTIVATE))
			{
				ret = server_user_discover_create_proxy(proxyhostid, session, &jp);
				if(SUCCEED != ret ){
					response = create_activate_or_stop_json(ret, cmd, session, &jp);
				}
			} 
        }
    }else{
		// 没有发到代理端，则直接返回给php端
		ret = DISCOVERY_RESULT_PORXY_NO_EXIST;
		response = create_activate_or_stop_json(ret, cmd, session, &jp);
	}

out:
	// 这里处理代理返回或本地生成的response数据，如果是单设备扫描则转发到代discoverer进程处理，否则直接返回给php
    discovery_rules_from_proxy(sock, response, config_timeout, rtc);
    
	zbx_free(cmd);
	zbx_free(session);
	zbx_free(request);
    zbx_free(response);
	zbx_free(resp_session);
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ret=%d", __func__,ret);
    return ret;
}


int discovery_rules_proxy(char *cmd, char *session, int proxyhostid, zbx_socket_t *sock, const char *request, 
    int config_timeout, zbx_ipc_async_socket_t *rtc)
{
    pthread_t proxy_thread;
    proxy_thread_arg proxy_arg;

    zbx_socket_t *resp_sock = (zbx_socket_t *)zbx_malloc(resp_sock, sizeof(zbx_socket_t));
	copy_zbx_socket(sock, resp_sock);
	sock->socket = ZBX_SOCKET_ERROR;

    proxy_arg.cmd = zbx_strdup(NULL,cmd);
    proxy_arg.session = zbx_strdup(NULL,session);
    proxy_arg.proxyhostid = proxyhostid;
    proxy_arg.sock = resp_sock;
    proxy_arg.request = zbx_strdup(NULL,request);
    proxy_arg.config_timeout = config_timeout;
	proxy_arg.rtc = rtc;
 
    if (pthread_create(&proxy_thread, NULL, do_proxy_discovery_rules, &proxy_arg))
    {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s. create thread fail.",__func__);
        return FAIL;
    }
	// if (pthread_join(&proxy_thread, NULL))
	// {
	// 	zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s join thread fail", __func__);
	// }
}