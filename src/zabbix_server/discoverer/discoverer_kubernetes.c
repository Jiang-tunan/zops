#include "discoverer.h"
#include "discoverer_manager.h"
#include "user_discoverer.h"
#include "discoverer_single.h"
#include "discoverer_kubernetes.h"
#include "discoverer_comm.h"

#include "log.h"
#include "zbxdiscovery.h"
#include "zbxserver.h"
#include "zbxself.h"
#include "zbxrtc.h"
#include "zbxnix.h"
#include "../poller/checks_agent.h"
#include "../poller/checks_simple.h"
#include "../poller/poller.h"
#include "../events.h"
#include "zbxnum.h"
#include "zbxtime.h"
#include "zbxip.h"
#include "zbxsysinfo.h"
#include "zbx_rtc_constants.h"
#include "zbx_host_constants.h"

#ifdef HAVE_LIBEVENT
#	include <event.h>
#	include <event2/thread.h>
#endif

void free_kubernetes_node(kubernetes_node *p_node)
{ 
	if(NULL == p_node) return;
	zbx_free(p_node->name); 
    zbx_free(p_node->uuid);
	zbx_free(p_node->os);  
	zbx_free(p_node->ip);  
	zbx_free(p_node->macs);

	zbx_free(p_node);
} 

void free_kubernetes_server(kubernetes_server *p_server)
{
	if(NULL == p_server) return;
    zbx_free(p_server->ip);
	zbx_vector_ptr_clear_ext(&p_server->nodes, free_kubernetes_node);
	zbx_vector_ptr_destroy(&p_server->nodes);
	zbx_free(p_server);
}

static int kubernetes_recv(int scan_type, char **out_value, DB_DCHECK *dcheck, int maxTry)
{
	AGENT_RESULT	result; 
	DC_ITEM		item;
	char url[256]={0}, authorization[2048]={0};
	int authtype = HTTPTEST_AUTH_NONE, port = 0;

	port = zbx_atoi(dcheck->ports);
	zbx_init_agent_result(&result);

	memset(&item, 0, sizeof(DC_ITEM));

	// zbx_snprintf(url, sizeof(url), "https://%s:%d/api/v1/nodes?labelSelector=node-role.kubernetes.io/control-plane", dcheck->ip, port);
	zbx_snprintf(url, sizeof(url), "https://%s:%d/api/v1/nodes", dcheck->ip, port);
	
	// zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s,  type=%d,ip=%s,ports=%s, url=%s, authorization=%s",
	// 	__func__,  dcheck->type, dcheck->ip,dcheck->ports, url, dcheck->ssh_privatekey);	
	
	zbx_strscpy(item.key_orig, dcheck->key_); 
	item.key = item.key_orig;

	item.url = zbx_strdup(NULL,url);
	item.authtype = authtype;
	item.username = dcheck->user;
	item.password = dcheck->password;
	item.type = ITEM_TYPE_HTTPAGENT;
	item.follow_redirects = 1; 
	item.state = 1;
	item.value_type	= ITEM_VALUE_TYPE_TEXT;
	item.retrieve_mode = ZBX_RETRIEVE_MODE_CONTENT;
	item.timeout = zbx_strdup(NULL, "2s"); 
	item.status_codes = zbx_strdup(NULL, "200"); 

 	zbx_snprintf(authorization,sizeof(authorization),"Authorization: Bearer %s", dcheck->ssh_privatekey);
	item.headers = zbx_strdup(NULL, authorization);
	
	
	item.query_fields = zbx_strdup(NULL, "");
	item.posts = zbx_strdup(NULL, "");
	item.params = zbx_strdup(NULL, "");
	item.ssl_cert_file = zbx_strdup(NULL, "");
	item.ssl_key_file = zbx_strdup(NULL, "");
	item.ssl_key_password = zbx_strdup(NULL, ""); 
	
	int ret = SUCCEED, count = 0, iResult = FAIL;
	char **pvalue;
	do{
		ret = get_value_http(&item, &result);
		if(SUCCEED == ret && NULL != (pvalue = ZBX_GET_TEXT_RESULT(&result)))
		{
			iResult = SUCCEED;
			*out_value = zbx_strdup(NULL, *pvalue);
			break;
		}else{
			count ++;
			zbx_sleep(1);
		}
	}
	while (count < maxTry); 
	
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, ret=%d, url=%s, authtype=%d,user=%s, ip=%s, port=%d, recv_value=%s", 
		__func__, iResult, url, authtype, dcheck->user, dcheck->ip, port, print_content(*out_value));
	  
	zbx_free_agent_result(&result);
	return iResult;
}


static kubernetes_server * __parse_k8s_data(char *value)
{
	struct zbx_json_parse	jp;
	struct zbx_json_parse jp_items,jp_items_list, jp_status, jp_addrs, jp_addrs_list,jp_daemon,jp_endpoint;
	struct zbx_json_parse jp_metadata,jp_labels, jp_annotations;
	
	int	ret = SUCCEED; 
	char  tstr[256];
	const char	*p_items=NULL, *p_addrs=NULL; 
	kubernetes_server *p_server = NULL;

	if (SUCCEED != zbx_json_open(value, &jp)){
		zabbix_log(LOG_LEVEL_DEBUG,"%s, json open fail", __func__);
		return NULL;
	}

	if (SUCCEED != zbx_json_value_by_name(&jp, "apiVersion", tstr, sizeof(tstr), NULL)){
		zabbix_log(LOG_LEVEL_DEBUG,"%s parse apiVersion fail", __func__);
		return NULL;
	}
	 
	if (SUCCEED != zbx_json_brackets_by_name(&jp, "items", &jp_items)){
		zabbix_log(LOG_LEVEL_DEBUG,"%s parse items fail", __func__);
		return NULL;
	}

	p_server = (kubernetes_server *)zbx_malloc(NULL, sizeof(kubernetes_server));
	memset(p_server, 0, sizeof(kubernetes_server));
	zbx_vector_ptr_create(&p_server->nodes);

	while (NULL != (p_items = zbx_json_next(&jp_items, p_items)))
	{
		if (SUCCEED == zbx_json_brackets_open(p_items, &jp_items_list))
		{
			kubernetes_node *p_node = (kubernetes_node *)zbx_malloc(NULL, sizeof(kubernetes_node));
				memset(p_node, 0, sizeof(kubernetes_node));

			if (SUCCEED == zbx_json_brackets_by_name(&jp_items_list, "metadata", &jp_metadata))
			{
				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&jp_metadata, "name", tstr, sizeof(tstr), NULL))
				{
					p_node->name = zbx_strdup(NULL, tstr);
				}
				if (SUCCEED == zbx_json_value_by_name(&jp_metadata, "uid", tstr, sizeof(tstr), NULL))
				{
					p_node->uuid = zbx_strdup(NULL, tstr);
				}

				if (SUCCEED == zbx_json_brackets_by_name(&jp_metadata, "labels", &jp_labels))
				{
					if (SUCCEED == zbx_json_value_by_name(&jp_labels, "beta.kubernetes.io/os", tstr, sizeof(tstr), NULL))
					{
						p_node->os = zbx_strdup(NULL, tstr);
					}

				}

				if (SUCCEED == zbx_json_brackets_by_name(&jp_metadata, "annotations", &jp_annotations))
				{
					if (SUCCEED == zbx_json_value_by_name(&jp_annotations, "flannel.alpha.coreos.com/public-ip", tstr, sizeof(tstr), NULL))
					{
						p_node->ip = zbx_strdup(NULL, tstr);
					}
				}
				
			}

			if (SUCCEED == zbx_json_brackets_by_name(&jp_items_list, "status", &jp_status))
			{
				if (SUCCEED == zbx_json_brackets_by_name(&jp_status, "addresses", &jp_addrs))
				{
					while (NULL != (p_addrs = zbx_json_next(&jp_addrs, p_addrs)))
					{
						if (SUCCEED == zbx_json_brackets_open(p_addrs, &jp_addrs_list))
						{
							char type[128]={0}, addr[128]={0};
							zbx_json_value_by_name(&jp_addrs_list, "type", type, sizeof(type), NULL);
							zbx_json_value_by_name(&jp_addrs_list, "address", addr, sizeof(addr), NULL);

							if( 0 == zbx_strcmp_null("InternalIP", type) && strlen(addr) > 0){
								p_node->ip = zbx_strdup(p_node->ip, addr);
							}
						}
					}	
				}

				if (SUCCEED == zbx_json_brackets_by_name(&jp_status, "daemonEndpoints", &jp_daemon))
				{
					if (SUCCEED == zbx_json_brackets_by_name(&jp_daemon, "kubeletEndpoint", &jp_endpoint))
					{
						memset(tstr, 0, sizeof(tstr));
						zbx_json_value_by_name(&jp_endpoint, "Port", tstr, sizeof(tstr), NULL);

						if(strlen(tstr) > 0){
							p_node->port = zbx_atoi(tstr);
						}
					}
					 	
				} 
			}
 
			if(NULL != p_node->ip){
				zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s get node, name=%s, ip=%s, port=%d, uuid=%s", 
					__func__, p_node->name, p_node->ip,p_node->port, p_node->uuid);
				zbx_vector_ptr_append(&p_server->nodes, p_node);
			}else{
				free_kubernetes_node(p_node);
			}
			
		}
	}
	return p_server;
}
  

void kubernetes_register_hostmacro(int device_type, int hostid, char *url, char *token, char *port, char *api_url)
{
	DB_RESULT	result;
	DB_ROW		row;

	if(0 == hostid)  return;

	result = zbx_db_select("select hostmacroid,hostid,macro,value from hostmacro"
			" where hostid=" ZBX_FS_UI64, hostid);
	int apiurl_id=0,token_id=0,port_id=0,url_id=0;
	while (NULL != (row = zbx_db_fetch(result)))
	{ 
		char *macro = row[2];
		if (zbx_strcmp_null(macro, "{$KUBE.API.URL}") == 0){
			apiurl_id = zbx_atoi(row[0]);
		}
		else if (zbx_strcmp_null(macro, "{$KUBE.API.TOKEN}") == 0){
			token_id = zbx_atoi(row[0]);
		}
		else if (zbx_strcmp_null(macro, "{$KUBE.API_SERVER.PORT}") == 0){
			port_id = zbx_atoi(row[0]);
		}

		else if(zbx_strcmp_null(macro, "{$KUBE.API.SERVER.URL}") == 0){
			url_id = zbx_atoi(row[0]);
		}
		else if(zbx_strcmp_null(macro, "{$KUBE.CONTROLLER.SERVER.URL}") == 0){
			url_id = zbx_atoi(row[0]);
		}
		else if(zbx_strcmp_null(macro, "{$KUBE.SCHEDULER.SERVER.URL}") == 0){
			url_id = zbx_atoi(row[0]);
		}
		else if(zbx_strcmp_null(macro, "{$KUBE.KUBELET.URL}") == 0){
			url_id = zbx_atoi(row[0]);
		}
		  
	}
	zbx_db_free_result(result);

	update_hostmacro_data(apiurl_id, hostid, "{$KUBE.API.URL}", api_url, "");
	update_hostmacro_data(token_id, hostid, "{$KUBE.API.TOKEN}", token, "");
	update_hostmacro_data(port_id, hostid, "{$KUBE.API_SERVER.PORT}", port, "");

	switch (device_type)
	{
	case DEVICE_TYPE_KUBERNETES_API:
		update_hostmacro_data(url_id, hostid, "{$KUBE.API.SERVER.URL}", url, "");
		break;
	case DEVICE_TYPE_KUBERNETES_CONTROLLER:
		update_hostmacro_data(url_id, hostid, "{$KUBE.CONTROLLER.SERVER.URL}", url, "");
		break;
	case DEVICE_TYPE_KUBERNETES_SCHEDULER:
		update_hostmacro_data(url_id, hostid, "{$KUBE.SCHEDULER.SERVER.URL}", url, "");
		break;
	case DEVICE_TYPE_KUBERNETES_KUBELET:
		update_hostmacro_data(url_id, hostid, "{$KUBE.KUBELET.URL}", url, "");
		break;
	case DEVICE_TYPE_KUBERNETES:
	default:
		break;
	}
	//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s device_type=%d, hostid=%d, port=%s, url=%s, api_url=%s", 
	//	__func__, device_type, hostid, port, url,  api_url); 

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}


static int discovery_register_kubernetes(int device_type, void *value, DB_DCHECK *dcheck,
	zbx_vector_ptr_t *v_hstgrps, zbx_vector_str_t *v_hosts, zbx_vector_str_t *v_ports)
{ 
	DB_HOST host;
	DB_INTERFACE interface;
	DB_HOST_INVENTORY inventory;
	char *dns = zbx_strdup(NULL,"");
	// char *request = NULL, *response = NULL;
	int ret = FAIL, s_port = zbx_atoi(dcheck->ports), port = 0;
	char ip[128]={0},  k8s_url[256]={0}, server_url[256]={0}, server_port[16]={0}, uuid[128]={0}; 

	memset(&host, 0, sizeof(DB_HOST));
	memset(&interface, 0, sizeof(DB_INTERFACE));
	memset(&inventory, 0, sizeof(DB_HOST_INVENTORY));
	if(DEVICE_TYPE_KUBERNETES_KUBELET == device_type){
		kubernetes_node *p_node = (kubernetes_node *)value;
		zbx_strlcpy(ip, p_node->ip, sizeof(ip));
		host.name = zbx_strdup(NULL, p_node->name);
		host.uuid = zbx_strdup(NULL, p_node->uuid);
		zbx_snprintf(uuid, sizeof(uuid), "%s", p_node->uuid);  
		port = p_node->port;
		host.hstgrpid  = p_node->hstgrpid;
	}else{
		kubernetes_server *p_server = (kubernetes_server *)value;
		zbx_strlcpy(ip, p_server->ip, sizeof(ip));
		host.hstgrpid  = p_server->hstgrpid;
	}
	host.proxy_hostid = dcheck->proxy_hostid;
	dcheck->devicetype = device_type;
	switch (device_type)
	{
	case DEVICE_TYPE_KUBERNETES:
		port = s_port; 
		break;
	case DEVICE_TYPE_KUBERNETES_API:
		port = s_port;
		zbx_snprintf(k8s_url, sizeof(k8s_url), "https://%s:%d/metrics", ip, port);  
		break;
	case DEVICE_TYPE_KUBERNETES_CONTROLLER:
		if(v_ports->values_num > 0){
			port = zbx_atoi(v_ports->values[0]);
		} 
		if(0 == port) port = 10250;  //10257
		zbx_snprintf(k8s_url, sizeof(k8s_url), "https://%s:%d/metrics", ip, port);  
		break;
	case DEVICE_TYPE_KUBERNETES_SCHEDULER:
		if(v_ports->values_num > 1){
			port = zbx_atoi(v_ports->values[1]);
		} 
		if(0 == port) port = 10250;  //10259
		zbx_snprintf(k8s_url, sizeof(k8s_url), "https://%s:%d/metrics", ip, port);  
		break;
	case DEVICE_TYPE_KUBERNETES_KUBELET:
		zbx_snprintf(k8s_url, sizeof(k8s_url), "https://%s:%d", ip, port); 
		

		break;
	default:
		break;
	}
	
	ret = discovery_register_soft(&host, &inventory, value, ip, dns, port, DOBJECT_STATUS_UP, dcheck);
	if(SUCCEED == ret)
	{
		zbx_snprintf(server_url, sizeof(server_url), "https://%s:%d", dcheck->ip, s_port); 
		zbx_snprintf(server_port, sizeof(server_port), "%d", s_port);  
		if(strlen(uuid) == 0){
			zbx_snprintf(uuid, sizeof(uuid), "%s", host.host);  
		}
		host.groupid = update_discover_hv_groupid(v_hstgrps, HSTGRP_TYPE_KUBERNETES_SET, host.hostid, uuid, host.name, host.hstgrpid);
		
		discovery_register_interface(&host, &interface, ip, dns, port, dcheck);
 
		kubernetes_register_hostmacro(device_type, host.hostid, k8s_url, dcheck->ssh_privatekey, server_port, server_url);
		
		// 入库host_inventory对应的接口
		discovery_register_host_inventory(&inventory);

		// 如果主机和接口都是已经注册过，说明是重复添加。如果主机重复，接口不重复，是增加了监控协议
		if(HOST_STATUS_UNREACHABLE != host.status && HOST_STATUS_MONITORED == interface.status){
			ret = DISCOVERY_RESULT_DUPLICATE_FAIL;
		}else{
			// 绑定模板用最顶层的关系
			host.hstgrpid = HSTGRP_GROUPID_VIRTUALIZATION;
			discoverer_bind_templateid(&host);
			zbx_vector_str_append(v_hosts, zbx_itoa(host.hostid));
		}
	}
	db_hosts_free(&host);
	return ret;
}

 
 
void get_k8s_hstgrp(zbx_vector_ptr_t *v_hstgrps)
{
	DB_RESULT	sql_result;
	DB_ROW		row;
	sql_result = zbx_db_select("select groupid,name,uuid,type,fgroupid,hostid from hstgrp where type = %d or type = %d", 
		HSTGRP_TYPE_KUBERNETES, HSTGRP_TYPE_KUBERNETES_SET);

	while (NULL != (row = zbx_db_fetch(sql_result)))
	{
		discover_hstgrp *d_hstgrp = (discover_hstgrp *)zbx_malloc(NULL, sizeof(discover_hstgrp));
		d_hstgrp->groupid = zbx_atoi(row[0]);
		d_hstgrp->name = zbx_strdup(NULL, row[1]);
		d_hstgrp->uuid = zbx_strdup(NULL, row[2]);
		d_hstgrp->type = zbx_atoi(row[3]);
		d_hstgrp->fgroupid = zbx_atoi(row[4]);
		d_hstgrp->hostid = zbx_atoi(row[5]);
		zbx_vector_str_append(v_hstgrps, d_hstgrp);
		// zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, type=%d, groupid=%d, uuid=%s, name=%s, fgroupid=%d", 
		// 	__func__, d_hstgrp->type, d_hstgrp->groupid , d_hstgrp->uuid, d_hstgrp->name, d_hstgrp->fgroupid);
	}
	zbx_db_free_result(sql_result);
}

 

static char* build_k8s_resp_json(int result, char *session, char *hostid, char* templateids)
{ 
	struct zbx_json	json;
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);

	zbx_json_addstring(&json, "response", DISCOVERY_CMD_SINGLE_SCAN, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json, "session", session, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&json, "result", result);
	zbx_json_addarray(&json, "data");
	
	if (DISCOVERY_RESULT_SUCCESS == result)
	{
		zbx_json_addobject(&json, NULL);
		zbx_json_addstring(&json, "hostid", hostid, ZBX_JSON_TYPE_STRING);
		if(NULL != templateids)
			zbx_json_addstring(&json, "templateid", templateids, ZBX_JSON_TYPE_STRING);
	}  
 	zbx_json_close(&json);
	char *sjson = strdup(json.buffer);
	zbx_json_free(&json);
	return sjson;
}


static void do_discover_kubernetes(int recv_type, char * session, const DB_DCHECK *dcheck, int from_proxy)
{
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s", __func__);
	int ret = DISCOVERY_RESULT_SCAN_FAIL;
	int top_groupid = HSTGRP_GROUPID_VIRTUALIZATION; // 扫描的最顶层群组id，默认是容器/虚拟化的groupid
	char *value = NULL, *p_hosts = NULL;
	kubernetes_server *p_server = NULL;

	zbx_vector_ptr_t v_hstgrps;
	zbx_vector_ptr_create(&v_hstgrps);

	zbx_vector_str_t v_hosts;
	zbx_vector_str_create(&v_hosts);

	zbx_vector_str_t v_ports;
	zbx_vector_str_create(&v_ports);

	if(from_proxy)
	{
		value = dcheck->resp_value;
		if(SUCCEED !=  dcheck->result)
			goto out; 
	}else{
		kubernetes_recv(0, &value, dcheck, 3);
	}
	
	if(NULL == value || strlen(value) == 0) 
		goto out; 
  
	if(NULL != (p_server = __parse_k8s_data(value)) && p_server->nodes.values_num > 0)
	{
		ret = DISCOVERY_RESULT_SUCCESS;
		p_server->ip = zbx_strdup(NULL, dcheck->ip);
		get_k8s_hstgrp(&v_hstgrps);
		if(HSTGRP_GROUPID_VIRTUALIZATION == top_groupid){
			top_groupid = get_discover_vc_groupid(HSTGRP_TYPE_KUBERNETES, p_server->ip, dcheck->proxy_hostid);
		} 
		str_to_vector(&v_ports, dcheck->path, ","); 
		p_server->hstgrpid = top_groupid; 
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s success. ip=%s, top_groupid=%d, hstgrpid=%d, ports=%s,node size=%d", 
			__func__, p_server->ip, top_groupid, p_server->hstgrpid, dcheck->path, p_server->nodes.values_num);
		
		ret = discovery_register_kubernetes(DEVICE_TYPE_KUBERNETES, p_server, dcheck, &v_hstgrps, &v_hosts, &v_ports);
		ret |= discovery_register_kubernetes(DEVICE_TYPE_KUBERNETES_API, p_server, dcheck, &v_hstgrps, &v_hosts, &v_ports);
		ret |= discovery_register_kubernetes(DEVICE_TYPE_KUBERNETES_CONTROLLER, p_server, dcheck, &v_hstgrps, &v_hosts, &v_ports);
		ret |= discovery_register_kubernetes(DEVICE_TYPE_KUBERNETES_SCHEDULER, p_server, dcheck, &v_hstgrps, &v_hosts, &v_ports);

		for(int i = 0; i < p_server->nodes.values_num; i ++){
			kubernetes_node *p_node = (kubernetes_node *)p_server->nodes.values[i];
			p_node->hstgrpid = top_groupid;
			ret |= discovery_register_kubernetes(DEVICE_TYPE_KUBERNETES_KUBELET, p_node, dcheck, &v_hstgrps, &v_hosts, &v_ports);
		}
	}  

out:
	
	// 如果添加过程中，有重复添加的并且也有新增加的一些监控，则提示成功
	if(DISCOVERY_RESULT_DUPLICATE_FAIL == ret && v_hosts.values_num > 0){
		ret = DISCOVERY_RESULT_SUCCESS;
	}
	if(v_hosts.values_num > 0){
		vector_to_str(&v_hosts, &p_hosts, ",");
	}

	char * response = build_k8s_resp_json(ret, session, p_hosts, NULL);
	discover_response_replay(recv_type, response);

	zbx_free(value); 
	zbx_free(p_hosts);
	zbx_free(response); 
	zbx_vector_str_clear_ext(&v_hosts, zbx_str_free);
	zbx_vector_str_destroy(&v_hosts);

	zbx_vector_str_clear_ext(&v_ports, zbx_str_free);
	zbx_vector_str_destroy(&v_ports);

	free_discover_hstgrp(&v_hstgrps); 

	free_kubernetes_server(p_server);

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
} 

/**
 * 服务端处理本地k8s发现
*/
void discover_kubernetes(int recv_type, char * session, const DB_DCHECK *dcheck)
{
	do_discover_kubernetes(recv_type, session, dcheck, 0);
}

/**
 * 这个函数是服务端执行代码，处理代理返回的数据
 */
void* server_discover_kubernetes_from_proxy(int recv_type, char *session, DB_DCHECK *dcheck) 
{
	do_discover_kubernetes(recv_type, session, dcheck, 1);
}

void proxy_discover_kubernetes(int recv_type, char * session, char *request, DB_DCHECK *dcheck)
{
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s", __func__);
	int ret = DISCOVERY_RESULT_SCAN_FAIL;
	char *value = NULL, *response = NULL;
	kubernetes_server *p_server = NULL;
	
	zbx_vector_ptr_t dchecks;
	zbx_vector_ptr_create(&dchecks);

	kubernetes_recv(0, &value, dcheck, 3);
	if(NULL == value || strlen(value) == 0) 
		goto out; 
  
	if(NULL != (p_server = __parse_k8s_data(value)) && p_server->nodes.values_num > 0)
	{
		ret = DISCOVERY_RESULT_SUCCESS;
	} 

out:
	dcheck->result = ret; 
	if(NULL != value){
		dcheck->resp_value = value; 
	}
	zbx_vector_ptr_append(&dchecks, dcheck);
		 
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, ret=%d, type=%d,ip=%s,ports=%s, value=%s",
		__func__, ret, dcheck->type, dcheck->ip,dcheck->ports, print_content(value));
	
	// 从代理扫描返回到服务端,这边不要注册hosts
	response = proxy_build_single_resp_json(request, &dchecks);
	
	discover_response_replay(recv_type, response);
	
	zbx_free(value);
	dcheck->resp_value = NULL;

	zbx_free(response);
	free_kubernetes_server(p_server);

	zbx_vector_ptr_destroy(&dchecks);

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
} 
