#include "discoverer_comm.h"
#include "log.h"

 
void free_discover_hstgrp_ptr(discover_hstgrp *p_hstgrp)
{
    zbx_free(p_hstgrp->uuid); 
	zbx_free(p_hstgrp->name); 
	zbx_free(p_hstgrp);
}

void free_discover_hosts_ptr(discover_hosts *p_host)
{
    zbx_free(p_host->uuid); 
	zbx_free(p_host);
}


int	dc_compare_hstgrp(const void *d1, const void *d2)
{
	const discover_hstgrp	*ptr1 = *((const discover_hstgrp * const *)d1);
	const discover_hstgrp	*ptr2 = *((const discover_hstgrp * const *)d2);
	if(ptr1->type == ptr2->type)
		return zbx_strcmp_null(ptr1->name, ptr2->name);
	return -1;
}

int	dc_compare_hstgrp_uuid(const void *d1, const void *d2)
{
	const discover_hstgrp	*ptr1 = *((const discover_hstgrp * const *)d1);
	const discover_hstgrp	*ptr2 = *((const discover_hstgrp * const *)d2);
	if(ptr1->type == ptr2->type)
		return zbx_strcmp_null(ptr1->uuid, ptr2->uuid);
	return -1;
}

int	dc_compare_hosts(const void *d1, const void *d2)
{
	const discover_hosts	*ptr1 = *((const discover_hosts * const *)d1);
	const discover_hosts	*ptr2 = *((const discover_hosts * const *)d2);
	if(ptr1->device_type == ptr2->device_type)
		return zbx_strcmp_null(ptr1->uuid, ptr2->uuid);
	return -1;
}


int update_discover_hv_groupid(zbx_vector_ptr_t *v_hstgrps, int type, int hostid, char *uuid, char *name, int fgroupid)
{
	int groupid = fgroupid;
	int index, is_find = 0; 
	discover_hstgrp d_hstgrp;
	d_hstgrp.type = type;
	d_hstgrp.uuid = uuid;
	if (FAIL != (index = zbx_vector_ptr_search(v_hstgrps, &d_hstgrp, dc_compare_hstgrp_uuid)))
	{
		discover_hstgrp *hstgrp = v_hstgrps->values[index];
		groupid = hstgrp->groupid;
		is_find = 1;
		// zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s,fgroupid %d=%d,hostid %d=%d",
		// 	 __func__, hstgrp->fgroupid,fgroupid,hstgrp->hostid , hostid );
		if(hstgrp->fgroupid != fgroupid || hstgrp->hostid != hostid){
			zbx_db_execute("update hstgrp set fgroupid=%d,fgroupids='%d',hostid=%d where groupid = %d"
					, fgroupid, fgroupid, hostid, hstgrp->groupid);
		}
	}

	if(!is_find)
	{
		groupid = zbx_db_get_maxid("hstgrp");
		zbx_db_execute("insert into hstgrp (groupid, name, uuid, type, fgroupid, fgroupids, hostid) values(%d, '%s', '%s', %d, %d, '%d', %d)",
			groupid, name, uuid, type, fgroupid, fgroupid, hostid);
	}

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, top_groupid=%d", __func__, groupid);
	return groupid;
	
}

int get_discover_vc_groupid(int type, char *ip)
{
	int groupid = HSTGRP_GROUPID_HV;
	int is_find = 0;
	DB_RESULT	sql_result;
	DB_ROW		row;
	// 数据中心2，集群3
	sql_result = zbx_db_select("select groupid from hstgrp where type = %d and uuid='%s'", type, ip);
	while (NULL != (row = zbx_db_fetch(sql_result)))
	{
		groupid = zbx_atoi(row[0]);
		is_find = 1;
		break;
	}

	if(!is_find)
	{
		char name[128];
		switch (type)
		{
		case HSTGRP_TYPE_VC:
			zbx_snprintf(name, sizeof(name),"VC[%s]", ip);
			break;
		case HSTGRP_TYPE_NTX:
			zbx_snprintf(name, sizeof(name),"NTX[%s]", ip);
			break;
		default:
			break;
		}

		char fgroupids[128];
		zbx_snprintf(fgroupids, sizeof(fgroupids),"%d,%d",HSTGRP_GROUPID_VM, HSTGRP_GROUPID_HV);

		groupid = zbx_db_get_maxid("hstgrp");
		zbx_db_execute("insert into hstgrp (groupid, name, uuid, type, fgroupid, fgroupids) values(%d, '%s', '%s', %d, %d, '%s')",
			groupid, name, ip, type, HSTGRP_GROUPID_HV, fgroupids);
	}
	zbx_db_free_result(sql_result);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, top_groupid=%d", __func__, groupid);
	return groupid;
	
}
 
// 获得数据中心、集群和服务器的 hstgrp 的数据
void get_discover_hstgrp(zbx_vector_ptr_t *v_hstgrps)
{
	DB_RESULT	sql_result;
	DB_ROW		row;
	 
	sql_result = zbx_db_select("select groupid,name,uuid,type,fgroupid,hostid from hstgrp where type = %d or type = %d or type = %d", 
		HSTGRP_TYPE_DATACENTER, HSTGRP_TYPE_CLUSTER, HSTGRP_TYPE_HV);

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

// 获得 hstgrp 的数据
void get_discover_hosts(zbx_vector_ptr_t *v_hosts)
{
	DB_RESULT	sql_result;
	DB_ROW		row;
	 
	sql_result = zbx_db_select("select hostid,uuid,device_type,hstgrpid from hosts where uuid != '' and (device_type = %d or device_type = %d)", 
		DEVICE_TYPE_CLUSTER, DEVICE_TYPE_HV);

	while (NULL != (row = zbx_db_fetch(sql_result)))
	{
		discover_hosts *d_host = (discover_hosts *)zbx_malloc(NULL, sizeof(discover_hosts));
		d_host->hostid = zbx_atoi(row[0]);
		d_host->uuid = zbx_strdup(NULL, row[1]);
		d_host->device_type = zbx_atoi(row[2]);
		d_host->hstgrpid = zbx_atoi(row[3]);
		zbx_vector_str_append(v_hosts, d_host);
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, type=%d, hostid=%d, uuid=%s, hstgrpid=%d", 
			__func__, d_host->device_type, d_host->hostid , d_host->uuid, d_host->hstgrpid);
	}
	zbx_db_free_result(sql_result);
} 

/*
for example
{
    "jsonrpc": "2.0",
    "method": "host.update",
    "params": {
        "hostid": 808,
        "templates": {"templateid":25},
        "groups": {"groupid":3},
        "status":0
    },
    "id": 1,
    "auth": "876765745f363327b337fe7cf9d7b091"
}
*/

int pack_bind_templateid_json_req(int hostid, int templateid,int groupid,int status,int id,char *auth,char* buf)
{ 
	struct zbx_json json;
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);

	zbx_json_addstring(&json, "jsonrpc", "2.0", ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json, "method", "host.update", ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&json, "id", id); 
	zbx_json_addstring(&json, "auth", auth, ZBX_JSON_TYPE_STRING);

	//
	zbx_json_addobject(&json, "params");
	zbx_json_addint64(&json, "hostid", hostid); 
	zbx_json_addint64(&json, "status", status); 

	zbx_json_addobject(&json, "templates");
	zbx_json_addint64(&json, "templateid", templateid); 
	zbx_json_close(&json);	// templates

	zbx_json_addobject(&json, "groups");
	zbx_json_addint64(&json, "groupid", groupid); 
	zbx_json_close(&json);	// groups
	
	zbx_json_close(&json);	// params
	//

	
	zbx_json_close(&json);
	//char *sjson = strdup(json.buffer);
	//char *sjson = zbx_strdup(NULL, json.buffer); 
	memcpy(buf,json.buffer,strlen(json.buffer));
	zbx_json_free(&json);

	//zabbix_log(LOG_LEVEL_DEBUG,"In %s() sjson=%u  %d,  %s",__func__, buf,strlen(buf),buf);
	
	//return sjson;
	return 0;
	
}

int bind_templateid_http_req_rsp(char* json_body_str,char **out_value, DB_DCHECK *dcheck, int maxTry)
{
	AGENT_RESULT	result; 
	DC_ITEM		item;
	char url[256] = {0};
	int authtype = HTTPTEST_AUTH_NONE, port = 0;

	port = zbx_atoi(dcheck->ports);
	zbx_init_agent_result(&result);

	memset(&item, 0, sizeof(DC_ITEM));
	// http://192.168.31.23:1618/api_jsonrpc.php	
	char* host = "127.0.0.1"; 
	port = 1618;
	zbx_snprintf(url, sizeof(url), "http://%s:%d/api_jsonrpc.php", host, port);

	zabbix_log(LOG_LEVEL_DEBUG,"In %s() req url=%s",__func__, url);
	zabbix_log(LOG_LEVEL_DEBUG,"In %s() req json_body_str=%s",__func__, json_body_str);
	
	
	item.url = url;
	item.authtype = authtype;
	item.username = dcheck->user;
	item.password = dcheck->password;
	item.type = ITEM_TYPE_HTTPAGENT;
	item.follow_redirects = 1; 
	item.state = 1;
	item.value_type	= ITEM_VALUE_TYPE_TEXT;
	item.post_type	= ZBX_POSTTYPE_JSON;
	item.retrieve_mode = ZBX_RETRIEVE_MODE_CONTENT;
	item.request_method = HTTP_REQUEST_POST;
	item.timeout = zbx_strdup(NULL, "3s"); 
	item.status_codes = zbx_strdup(NULL, "200"); 

	item.headers = zbx_strdup(NULL, "");
	item.query_fields = zbx_strdup(NULL, "");
	item.posts = json_body_str;
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

	if (item.timeout) {
		zbx_free(item.timeout);
	}
	if (item.status_codes) {
		zbx_free(item.status_codes);
	}
	if (item.headers) {
		zbx_free(item.headers);
	}
	if (item.query_fields) {
		zbx_free(item.query_fields);
	}
	if (item.ssl_cert_file) {
		zbx_free(item.ssl_cert_file);
	}
	if (item.ssl_key_file) {
		zbx_free(item.ssl_key_file);
	}
	if (item.ssl_key_password) {
		zbx_free(item.ssl_key_password);
	}

	
	zabbix_log(LOG_LEVEL_DEBUG,"End(%s), result=%d, recv value=%s", 
		__func__, iResult,  *out_value);
	
	  
	zbx_free_agent_result(&result);
	return iResult;
}



