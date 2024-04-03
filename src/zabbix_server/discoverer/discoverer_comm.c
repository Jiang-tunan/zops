#include "discoverer_comm.h"
#include "log.h"

 
void free_discover_hstgrp_ptr(discover_hstgrp *p_hstgrp)
{
	if(NULL == p_hstgrp) return;
    zbx_free(p_hstgrp->uuid); 
	zbx_free(p_hstgrp->name); 
	zbx_free(p_hstgrp);
}

void free_discover_hstgrp(zbx_vector_ptr_t *v_hstgrps)
{
	if(NULL == v_hstgrps) return;
	zbx_vector_ptr_clear_ext(v_hstgrps, (zbx_mem_free_func_t)free_discover_hstgrp_ptr);
	zbx_vector_ptr_destroy(v_hstgrps);
}


void free_discover_hosts_ptr(discover_hosts *p_host)
{
	if(NULL == p_host) return;
    zbx_free(p_host->uuid); 
	zbx_free(p_host);
}

void free_discover_hosts(zbx_vector_ptr_t *v_host)
{
	if(NULL == v_host) return;
    zbx_vector_ptr_clear_ext(v_host, (zbx_mem_free_func_t)free_discover_hosts_ptr);
	zbx_vector_ptr_destroy(v_host);
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

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, groupid=%d, fgroupid=%d", __func__, groupid, fgroupid);
	return groupid;
	
}

int get_discover_vc_groupid(int type, char *ip, int proxy_hostid)
{
	int groupid = 0, fgroupid=0, is_find = 0;
	char name[128]={0}, fgroupids[128]={0}, uuid[256]={0};
	DB_RESULT	sql_result;
	DB_ROW		row;
	
	if(HSTGRP_TYPE_KUBERNETES == type){
		groupid = HSTGRP_GROUPID_VIRTUALIZATION;
	}else{
		groupid = HSTGRP_GROUPID_SERVER;
	}
	if(proxy_hostid > 0){
		zbx_snprintf(uuid, sizeof(uuid), "%s-%d",ip, proxy_hostid);
	}else{
		zbx_snprintf(uuid, sizeof(uuid), "%s",ip);
	}

	// 数据中心2，集群3
	sql_result = zbx_db_select("select groupid from hstgrp where type = %d and uuid='%s'", type, uuid);
	while (NULL != (row = zbx_db_fetch(sql_result)))
	{
		groupid = zbx_atoi(row[0]);
		is_find = 1;
		break;
	}

	if(!is_find)
	{
		switch (type)
		{
		case HSTGRP_TYPE_VC:
			fgroupid = HSTGRP_GROUPID_SERVER;
			zbx_snprintf(name, sizeof(name),"VC[%s]", uuid);
			zbx_snprintf(fgroupids, sizeof(fgroupids),"%d,%d",HSTGRP_GROUPID_VM, HSTGRP_GROUPID_SERVER);
			break;
		case HSTGRP_TYPE_NTX:
			fgroupid = HSTGRP_GROUPID_SERVER;
			zbx_snprintf(name, sizeof(name),"NTX[%s]", uuid);
			zbx_snprintf(fgroupids, sizeof(fgroupids),"%d,%d",HSTGRP_GROUPID_VM, HSTGRP_GROUPID_SERVER);
			break;
		case HSTGRP_TYPE_KUBERNETES:
			fgroupid = HSTGRP_GROUPID_VIRTUALIZATION;
			zbx_snprintf(name, sizeof(name),"K8S[%s]", uuid);
			zbx_snprintf(fgroupids, sizeof(fgroupids),"%d",fgroupid);
			break;
		default:
			break;
		}

		groupid = zbx_db_get_maxid("hstgrp");
		zbx_db_execute("insert into hstgrp (groupid, name, uuid, type, fgroupid, fgroupids) values(%d, '%s', '%s', %d, %d, '%s')",
			groupid, name, uuid, type, fgroupid, fgroupids);
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


void dc_get_dchecks(zbx_db_drule *drule,  int unique, zbx_vector_ptr_t *dchecks, zbx_vector_uint64_t *dcheckids)
{
	DB_RESULT	result;
	DB_ROW		row;
	char		sql[MAX_STRING_LEN];
	size_t		offset = 0;
	
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);
	// ORDER BY dc.type DESC 是确保nutanix扫描先触发Ntanix协议扫描，再触发snmp扫描
	offset += zbx_snprintf(sql + offset, sizeof(sql) - offset,
			"SELECT dc.dcheckid, dc.type, dc.key_, cdt.PORT, cdt.USER, cdt.PASSWORD, cdt.snmpv3_securitylevel,cdt.snmpv3_authpassphrase," \
			"cdt.snmpv3_privpassphrase, cdt.snmpv3_authprotocol, cdt.snmpv3_privprotocol, dr.houseid, dr.managerid, dc.druleid, dc.credentialid " \
			"FROM dchecks dc LEFT JOIN drules dr ON dc.druleid = dr.druleid LEFT JOIN credentials cdt ON dc.credentialid = cdt.id " \
			" WHERE dc.druleid=" ZBX_FS_UI64, drule->druleid); 
	if (0 != drule->unique_dcheckid)
	{
		offset += zbx_snprintf(sql + offset, sizeof(sql) - offset, " and dcheckid%s" ZBX_FS_UI64,
				unique ? "=" : "<>", drule->unique_dcheckid);
	}

	zbx_snprintf(sql + offset, sizeof(sql) - offset, " order by dcheckid");

	result = zbx_db_select("%s", sql);
	int main_type = -1;
	while (NULL != (row = zbx_db_fetch(result)))
	{ 
		DB_DCHECK *dcheck = (DB_DCHECK *)zbx_malloc(NULL, sizeof(DB_DCHECK));
		memset(dcheck, 0, sizeof(DB_DCHECK)); //必须对dcheck初始化，否则会crash
		ZBX_STR2UINT64(dcheck->dcheckid, row[0]);
		dcheck->type = zbx_atoi(row[1]);
		dcheck->key_ = zbx_strdup(NULL, row[2]);
		dcheck->ports = zbx_strdup(NULL, row[3]);
		dcheck->user = zbx_strdup(NULL, row[4]);
		dcheck->password = zbx_strdup(NULL, row[5]);
		dcheck->snmpv3_securityname = zbx_strdup(NULL, row[4]);
		dcheck->snmpv3_contextname = zbx_strdup(NULL, row[5]);
		dcheck->snmp_community = zbx_strdup(NULL, row[5]);
		dcheck->snmpv3_securitylevel = (unsigned char)zbx_atoi(row[6]);
		dcheck->snmpv3_authpassphrase = zbx_strdup(NULL, row[7]);
		dcheck->snmpv3_privpassphrase = zbx_strdup(NULL, row[8]);
		dcheck->snmpv3_authprotocol = (unsigned char)zbx_atoi(row[9]);
		dcheck->snmpv3_privprotocol = (unsigned char)zbx_atoi(row[10]);
		dcheck->houseid = zbx_atoi(row[11]);
		dcheck->managerid = zbx_atoi(row[12]);
		ZBX_STR2UINT64(dcheck->druleid, row[13]);
		dcheck->credentialid = zbx_atoi(row[14]);
		
		// 第一个为主扫描类型
		if(main_type < 0) main_type = dcheck->type;
		dcheck->main_type = main_type;

		if(NULL != dchecks)
			zbx_vector_ptr_append(dchecks, dcheck);
		if(NULL != dcheckids)
			zbx_vector_uint64_append(dcheckids, dcheck->dcheckid);
	}
	zbx_db_free_result(result);
	zabbix_log(LOG_LEVEL_DEBUG, "%s() End. ", __func__);
}


/**
 * 拷贝原始的json到zbx_json对象中
*/
void copy_original_json(struct zbx_json_parse *jp, struct zbx_json *json_dest, int depth, zbx_map_t *map)
{
	int i = 0;
	struct zbx_json_parse	jp_sub;
	const char		*p_value = NULL;
	char			*p = NULL, name[MAX_STRING_LEN], value[MAX_STRING_LEN];
	zbx_json_type_t		type;
	zabbix_log(LOG_LEVEL_DEBUG, "%s begin. depth=%d", __func__, depth);
	do
	{
		i ++;
		p = zbx_json_pair_next(jp, p, name, sizeof(name));
		zabbix_log(LOG_LEVEL_DEBUG, "%s name=%s,p=%s", __func__, name, p);
		if (NULL != (p))
		{
			memset(value, 0, sizeof(value));
			p_value = zbx_json_decodevalue(p, value, sizeof(value), NULL);
			type = zbx_json_valuetype(p);
			zabbix_log(LOG_LEVEL_DEBUG, "%s type=%d,name=%s,value=%s", __func__, type,name,value);
			if (NULL == p_value)
			{
				zabbix_log(LOG_LEVEL_DEBUG, "%s type=%d,p=%s", __func__, type,p);
				if (type == ZBX_JSON_TYPE_ARRAY)
				{
					zbx_json_addarray(json_dest, name);
					zbx_json_brackets_by_name(jp, name, &jp_sub);
					p=NULL;
					p = zbx_json_next(&jp_sub, p);
					p_value = zbx_json_decodevalue(p, value, sizeof(value), NULL);
					type = zbx_json_valuetype(p);
					// zabbix_log(LOG_LEVEL_DEBUG, "%s 111type=%d,p=%s", __func__, type,p);

					// p = zbx_json_next(&jp_sub, p);
					// p_value = zbx_json_decodevalue(p, value, sizeof(value), NULL);
					// type = zbx_json_valuetype(p);
					// zabbix_log(LOG_LEVEL_DEBUG, "%s 222type=%d,p=%s", __func__, type,p);

					// p = zbx_json_next(&jp_sub, p);
					// p_value = zbx_json_decodevalue(p, value, sizeof(value), NULL);
					// type = zbx_json_valuetype(p);
					// zabbix_log(LOG_LEVEL_DEBUG, "%s 333type=%d,p=%s", __func__, type,p);
					copy_original_json(&jp_sub, json_dest, depth+1, map);
					continue;
					// if (SUCCEED == zbx_json_brackets_open(p, &jp_sub))
					// {
					// 	// zbx_json_addarray(json_dest, name);
					// 	zbx_json_addobject(json_dest, NULL);
					// 	copy_original_json(&jp_sub, json_dest, depth+1, map);
					// 	continue;
					// }
				}
				else if (type == ZBX_JSON_TYPE_OBJECT)
				{
					if (SUCCEED == zbx_json_brackets_open(p, &jp_sub))
					{
						zbx_json_addobject(json_dest, name);
						copy_original_json(&jp_sub, json_dest, depth+1, map);
						continue;
					}
				}
			}
			else
			{
				if (type == ZBX_JSON_TYPE_STRING)
				{
					if(NULL != map && 0 ==zbx_strcmp_null(map->name, name)){
						zbx_json_addstring(json_dest, name, map->value, ZBX_JSON_TYPE_STRING);
					}else{
						zbx_json_addstring(json_dest, name, value, ZBX_JSON_TYPE_STRING);
					}
				}
				else if (type == ZBX_JSON_TYPE_INT)
				{
					zbx_json_addint64(json_dest, name, zbx_atoi(value));
				}
			}
		}
		else
		{
			if(depth > 1)  zbx_json_close(json_dest);
		}
	} while (NULL != p && i < 20); 
	zabbix_log(LOG_LEVEL_DEBUG, "%s end. depth=%d", __func__, depth);
}

/**
 * 拷贝原始的json到zbx_json对象中
*/
int copy_original_json2(zbx_json_type_t type, struct zbx_json_parse *jp, struct zbx_json *json_dest, int depth, zbx_map_t *map)
{
	int i = 0;
	struct zbx_json_parse	jp_sub;
	const char		*p_value = NULL;
	char			*p = NULL, name[MAX_STRING_LEN], value[MAX_STRING_LEN];
	
	// zabbix_log(LOG_LEVEL_DEBUG, "%s begin. depth=%d", __func__, depth);
	do
	{
		i ++;
        if(type == ZBX_JSON_TYPE_ARRAY){
            p = zbx_json_next(jp, p);
        }else{
		    p = zbx_json_pair_next(jp, p, name, sizeof(name));
        }

		//zabbix_log(LOG_LEVEL_DEBUG, "%s depth=%d,name=%s,p=%s", __func__, depth, name, p);
		if (NULL != (p))
		{
			memset(value, 0, sizeof(value));
			p_value = zbx_json_decodevalue(p, value, sizeof(value), NULL);
			type = zbx_json_valuetype(p);
			//zabbix_log(LOG_LEVEL_DEBUG, "%s depth=%d,type=%d,name=%s,value=%s,p_value=%s", __func__, depth,type,name,value,p_value);
			if (NULL == p_value)
			{
				if (type == ZBX_JSON_TYPE_ARRAY)
				{
                    if (SUCCEED == zbx_json_brackets_open(p, &jp_sub)){
                        if(NULL != name && strlen(name) > 0){
                            zbx_json_addarray(json_dest, name);
                        }else{
                            zbx_json_addarray(json_dest, NULL);
                        }
                        copy_original_json2(type, &jp_sub, json_dest, depth+1, map);
                        zbx_json_close(json_dest);
                    }else{
                        return FAIL;
                    }
					continue;
				}
				else if (type == ZBX_JSON_TYPE_OBJECT)
				{
					if (SUCCEED == zbx_json_brackets_open(p, &jp_sub))
					{
						if(NULL != name && strlen(name) > 0){
                            zbx_json_addobject(json_dest, name);
                        }else{
                            zbx_json_addobject(json_dest, NULL);
                        }
						copy_original_json2(type, &jp_sub, json_dest, depth+1, map);
                        zbx_json_close(json_dest);
						continue;
					}else{
                        return FAIL;
                    }
				}
			}
			else
			{
				if (type == ZBX_JSON_TYPE_STRING)
				{
					if(NULL != map && 0 ==zbx_strcmp_null(map->name, name)){
						zbx_json_addstring(json_dest, name, map->value, ZBX_JSON_TYPE_STRING);
					}else{
						zbx_json_addstring(json_dest, name, value, ZBX_JSON_TYPE_STRING);
					}
				}
				else if (type == ZBX_JSON_TYPE_INT)
				{
					zbx_json_addint64(json_dest, name, zbx_atoi(value));
				}
			}
		}
	} while (NULL != p && i < 20); 

    zbx_json_close(json_dest);
	// zabbix_log(LOG_LEVEL_DEBUG, "%s end. depth=%d", __func__, depth);
    if(depth == 0){
        zabbix_log(LOG_LEVEL_DEBUG, "%s newjson=%s", __func__, json_dest->buffer);
    }
    return SUCCEED;
}



// proxy程序处理server的请求后返回应答
char *proxy_build_single_resp_json(char *request, zbx_vector_ptr_t *dchecks)
{
	int ret, depth = 0;
	struct zbx_json_parse jp, jp_sub;
	struct zbx_json json;
	DB_DCHECK *dcheck = NULL;
	
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);
	if (SUCCEED != (ret = zbx_json_open(request, &jp))){
		goto out;
	}
	copy_original_json(&jp, &json, depth, NULL);

	//在原始json中增加处理结果数据
	zbx_json_addarray(&json, PROXY_DISCOVERY_RULES_RESP);
	for(int i = 0; i < dchecks->values_num; i ++)
	{
		dcheck = dchecks->values[i];
		zbx_json_addobject(&json, NULL);
		zbx_json_addint64(&json, "credentialid", dcheck->credentialid);
		zbx_json_addint64(&json, "result", dcheck->result);
		if(NULL != dcheck->resp_value){
			zbx_json_addstring(&json, "value", dcheck->resp_value,ZBX_JSON_TYPE_STRING);
		}
		zbx_json_close(&json);
	}
	zbx_json_close(&json);

out:
	zbx_json_close(&json);
	char *sjson = strdup(json.buffer);
	zbx_json_free(&json);
	// zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s response=%s", __func__, sjson);
	
	return sjson;
}

char *print_content(char *json)
{
	if(NULL == json)  return json;
	int len = strlen(json);
	if(len < MAX_STRING_LEN)
		return json;
	else
		return zbx_itoa(len);
}