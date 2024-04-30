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

#include "zbxdiscovery.h"

#include "log.h"
#include "../../zabbix_server/events.h"
#include "../../zabbix_server/discoverer/user_discoverer.h"
#include "zbxtime.h"
#include "zbxnum.h"
#include "zbxserver.h"
#include "zbx_host_constants.h"
#include "zbxdbwrap.h"
#include "zbxsysinfo.h"
#include "../../zabbix_server/discoverer/discoverer_vmware.h"
#include "../../zabbix_server/discoverer/discoverer_nutanix.h"
#include "../../zabbix_server/ipmi/ipmi_discovery.h"

static DB_RESULT	discovery_get_dhost_by_value(zbx_uint64_t dcheckid, const char *value)
{
	DB_RESULT	result;
	char		*value_esc;

	value_esc = zbx_db_dyn_escape_field("dservices", "value", value);

	result = zbx_db_select(
			"select dh.dhostid,dh.status,dh.lastup,dh.lastdown"
			" from dhosts dh,dservices ds"
			" where ds.dhostid=dh.dhostid"
				" and ds.dcheckid=" ZBX_FS_UI64
				" and ds.value" ZBX_SQL_STRCMP
			" order by dh.dhostid",
			dcheckid, ZBX_SQL_STRVAL_EQ(value_esc));

	zbx_free(value_esc);

	return result;
}

static DB_RESULT	discovery_get_dhost_by_ip_port(zbx_uint64_t druleid, const char *ip, int port)
{
	DB_RESULT	result;
	char		*ip_esc;

	ip_esc = zbx_db_dyn_escape_field("dservices", "ip", ip);

	result = zbx_db_select(
			"select dh.dhostid,dh.status,dh.lastup,dh.lastdown"
			" from dhosts dh,dservices ds"
			" where ds.dhostid=dh.dhostid"
				" and dh.druleid=" ZBX_FS_UI64
				" and ds.ip" ZBX_SQL_STRCMP
				" and ds.port=%d"
			" order by dh.dhostid",
			druleid, ZBX_SQL_STRVAL_EQ(ip_esc), port);

	zbx_free(ip_esc);

	return result;
}

/******************************************************************************
 *                                                                            *
 * Purpose: separate multiple-IP hosts                                        *
 *                                                                            *
 * Parameters: host ip address                                                *
 *                                                                            *
 ******************************************************************************/
static void	discovery_separate_host(const zbx_db_drule *drule, zbx_db_dhost *dhost, const char *ip)
{
	DB_RESULT	result;
	char		*ip_esc, *sql = NULL;
	zbx_uint64_t	dhostid;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s'", __func__, ip);

	ip_esc = zbx_db_dyn_escape_field("dservices", "ip", ip);

	sql = zbx_dsprintf(sql,
			"select dserviceid"
			" from dservices"
			" where dhostid=" ZBX_FS_UI64
				" and ip" ZBX_SQL_STRCMP,
			dhost->dhostid, ZBX_SQL_STRVAL_NE(ip_esc));

	result = zbx_db_select_n(sql, 1);

	if (NULL != zbx_db_fetch(result))
	{
		dhostid = zbx_db_get_maxid("dhosts");

		zbx_db_execute("insert into dhosts (dhostid,druleid)"
				" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ")",
				dhostid, drule->druleid);

		zbx_db_execute("update dservices"
				" set dhostid=" ZBX_FS_UI64
				" where dhostid=" ZBX_FS_UI64
					" and ip" ZBX_SQL_STRCMP,
				dhostid, dhost->dhostid, ZBX_SQL_STRVAL_EQ(ip_esc));

		dhost->dhostid = dhostid;
		dhost->status = DOBJECT_STATUS_DOWN;
		dhost->lastup = 0;
		dhost->lastdown = 0;
	}
	zbx_db_free_result(result);

	zbx_free(sql);
	zbx_free(ip_esc);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: register host if one does not exist                               *
 *                                                                            *
 * Parameters: host ip address                                                *
 *                                                                            *
 ******************************************************************************/
static void	discovery_register_dhost(const zbx_db_drule *drule, zbx_uint64_t dcheckid, zbx_db_dhost *dhost,
		const char *ip, int port, int status, const char *value)
{
	DB_RESULT	result;
	DB_ROW		row;
	int		match_value = 0;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s' status:%d value:'%s'", __func__, ip, status, value);

	if (drule->unique_dcheckid == dcheckid)
	{
		result = discovery_get_dhost_by_value(dcheckid, value);

		if (NULL == (row = zbx_db_fetch(result)))
		{
			zbx_db_free_result(result);

			result = discovery_get_dhost_by_ip_port(drule->druleid, ip, port);
			row = zbx_db_fetch(result);
		}
		else
			match_value = 1;

	}
	else
	{
		result = discovery_get_dhost_by_ip_port(drule->druleid, ip, port);
		row = zbx_db_fetch(result);
	}

	if (NULL == row)
	{
		if (DOBJECT_STATUS_UP == status)	/* add host only if service is up */
		{
			zabbix_log(LOG_LEVEL_DEBUG, "new host discovered at %s", ip);

			dhost->dhostid = zbx_db_get_maxid("dhosts");
			dhost->status = DOBJECT_STATUS_DOWN;
			dhost->lastup = 0;
			dhost->lastdown = 0;

			zbx_db_execute("insert into dhosts (dhostid,druleid)"
					" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ")",
					dhost->dhostid, drule->druleid);
		}
	}
	else
	{
		zabbix_log(LOG_LEVEL_DEBUG, "host at %s is already in database", ip);

		ZBX_STR2UINT64(dhost->dhostid, row[0]);
		dhost->status = atoi(row[1]);
		dhost->lastup = atoi(row[2]);
		dhost->lastdown = atoi(row[3]);

		if (0 == match_value)
			discovery_separate_host(drule, dhost, ip);
	}
	zbx_db_free_result(result);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}
 
//传入一个json数据 解析出对应字段
void discovery_parsing_value(const char *data, const char *field, char **out)
{
	struct zbx_json_parse	jp, jp_item;
	char			buf[MAX_STRING_LEN]={0},buf_tmp[1024]={0};
	const char		*p=NULL;
	


	if (FAIL == zbx_json_open(data, &jp))
		goto out;

	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp, p)))
	{
		if (SUCCEED != zbx_json_brackets_open(p, &jp_item))
			continue;

		if (SUCCEED == zbx_json_value_by_name(&jp_item, field, buf_tmp, sizeof(buf_tmp), NULL))
		{
			if (zbx_strcmp_natural(field, ZBX_DSERVICE_KEY_IFPHYSADDRESS) == 0) //选择数据 --如果有多个mac地址取最大的
			{
				char *fmacaddr = format_mac_address(buf_tmp);
				if(zbx_strcmp_natural(buf, fmacaddr) < 0)
				{
					zbx_strscpy(buf, fmacaddr);
				}
				zbx_free(fmacaddr);
			}else  if (zbx_strlen_utf8(buf_tmp) > zbx_strlen_utf8(buf)) //选择数据 --snmp父节点oid会有很多返回 取最长的
			{
				zbx_strscpy(buf, buf_tmp); 
			}	
		}
	}

out:
	*out = zbx_dsprintf(NULL, "%s", buf);
}

//传入一个json数据 解析出所有mac地址
void discovery_parsing_macs(const char *data,  const char *field_name, zbx_vector_str_t *out)
{
	struct zbx_json_parse	jp, jp_item;
	char			buf_tmp[1024]={0};
	const char		*p = NULL;
	char *fmacaddr = NULL;

	if (FAIL == zbx_json_open(data, &jp))
		return;
	
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp, p)))
	{
		if (SUCCEED != zbx_json_brackets_open(p, &jp_item))
			continue;
		
		if (SUCCEED == zbx_json_value_by_name(&jp_item, field_name, buf_tmp, sizeof(buf_tmp), NULL))
		{
			//数据预处理 --mac地址补全
			if (zbx_strcmp_natural(buf_tmp, "") == 0)
				continue;
			//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s mac:%s", __func__, buf_tmp);
			// agent 返回的mac地址一条可能有多个，中间用","分开
			if(NULL != index(buf_tmp,','))
			{
				int num = 20;
				char *macaddrs[20] = {0};
				zbx_split(buf_tmp, ",", macaddrs, &num);
				for(int k = 0; k < num; k ++)
				{
					fmacaddr = format_mac_address(macaddrs[k]);
					//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s,k=%d, fmac:%s",__func__, k, fmacaddr);
					
					if (strncmp(fmacaddr, ZBX_DSERVICE_ILLEGAL_MACADDRS, ZBX_DSERVICE_ILLEGAL_MACADDRS_LEN) != 0)
					{
						char *tmp = zbx_dsprintf(NULL, "%s", fmacaddr);
						zbx_vector_str_append(out, tmp);

					}else{
						zbx_free(fmacaddr);
					}
					
				}
			}
			else
			{
				fmacaddr = format_mac_address(buf_tmp);
				//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, fmac:%s",__func__,  fmacaddr);
					
				if (strncmp(fmacaddr, ZBX_DSERVICE_ILLEGAL_MACADDRS, ZBX_DSERVICE_ILLEGAL_MACADDRS_LEN) != 0)
				{
					char *tmp = zbx_dsprintf(NULL, "%s", fmacaddr);
					zbx_vector_str_append(out, tmp);
				}else{
					zbx_free(fmacaddr);
				}
				
			}
		}
			
	}

	zbx_vector_str_sort(out, ZBX_DEFAULT_STR_COMPARE_FUNC);
	zbx_vector_str_uniq(out, ZBX_DEFAULT_STR_COMPARE_FUNC);
}

/*
* 存储设备根据品牌和型号确定模板和组
* 后续增加的类型添加在这里
*/
void storage_template(const char *manufacturer_name, const char *model, int *hst_groupid, int *templateid)
{
	if(manufacturer_name == NULL || strlen(manufacturer_name) == 0)
		return;
	if(model == NULL || strlen(model) == 0)
		return;

	if (0 == strcmp(manufacturer_name, "dell"))
	{
		if (0 == strcmp(model, "UnityVSA"))
		{
			*hst_groupid = HSTGRP_GROUPID_STORAGE;
			*templateid = TEMPLATEID_STORAGE_DELL_UNITY;
		}
	}
}

//设备类型id 厂商id 模板id  (硬件型号->厂商id  硬件型号->设备类型id、品牌id->模板id(默认值))
void discovery_parsing_value_model(const char *entphysicalmodel, const char *sysdesc, int devicetype, int *hst_groupid, char **manufacturer, int *templateid)
{
	DB_RESULT	result;
	DB_ROW		row;

	if(NULL != entphysicalmodel && strlen(entphysicalmodel) > 0){
		// 首先根据设备型号找出模板名称，群组，厂商名称
		result = zbx_db_select("select templateid,groupid,manufacturer from device_model where physical_model='%s'", entphysicalmodel);
		if (NULL != (row = zbx_db_fetch(result)))
		{
			*templateid = zbx_atoi(row[0]);
			if(0 == *hst_groupid){
				*hst_groupid = zbx_atoi(row[1]);
			}
			*manufacturer = zbx_strdup(NULL, row[2]);
		}
		zbx_db_free_result(result);
	}

	//如果没有找到厂商名称，根据snmp协议返回的系统描述找出相关的厂家名称
	if(NULL == *manufacturer && NULL != sysdesc && 0 < strlen(sysdesc))  
	{	
		zbx_vector_str_t	v_manufacturer;
		zbx_vector_str_create(&v_manufacturer);
 
		str_to_vector(&v_manufacturer, sysdesc, " ");
		if(v_manufacturer.values_num > 0)
		{
			char	*sql = NULL;
			size_t	sql_alloc = 0, sql_offset = 0;
			zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, "select name from manufacturer where");
			zbx_db_add_str_condition_alloc(&sql, &sql_alloc, &sql_offset, "name", (const char **)v_manufacturer.values, v_manufacturer.values_num);
			result = zbx_db_select("%s", sql);
			if (NULL != (row = zbx_db_fetch(result)))
			{
				*manufacturer=zbx_strdup(NULL, row[0]); 
			}else{
				*manufacturer=zbx_strdup(NULL, "");
			}
			 
			zbx_free(sql);
			zbx_db_free_result(result);
		}

		zbx_vector_str_clear_ext(&v_manufacturer, zbx_str_free);
		zbx_vector_str_destroy(&v_manufacturer);

	}
}

// 根据系统描述分析出操作系统名称，再根据操作系统名称或数据库中的device_type分析出模板ID和群组ID
void discovery_parsing_os_value(const char *sysdesc, int check_type, int device_type, char *model, char **os, int *templateid, int *hst_groupid)
{
	if(NULL == sysdesc && 0 == device_type) return;

	int net_lShow = 0, net_hShow = 0, is_windows = 0, is_linux = 0, hstgpid = 0;
	zbx_vector_str_t	v_sdesc;
	zbx_vector_str_create(&v_sdesc);
	
	if(NULL != sysdesc && strlen(sysdesc) > 0)
	{
		str_to_vector(&v_sdesc, sysdesc, " ");
		for(int i = 0; i < v_sdesc.values_num; i ++)
		{
			char *ds = v_sdesc.values[i];
			if (zbx_strcasecmp(ds, "linux") == 0){
				*os = zbx_strdup(NULL, "Linux");
				is_linux = 1;
			}
			else if (zbx_strcasecmp(ds, "windows") == 0){
				*os = zbx_strdup(NULL, "Windows");
				is_windows = 1;
			}
			else if (zbx_strncasecmp(ds, "network", 7) == 0){
				net_lShow ++;
			}else if (zbx_strncasecmp(ds, "router", 6) == 0 || zbx_strncasecmp(ds, "firewall",8) == 0
					|| zbx_strncasecmp(ds, "switch",6) == 0 || zbx_strncasecmp(ds, "security",8) == 0){
				net_hShow ++;
			}
		}
	}

	switch (device_type)
	{
	case DEVICE_TYPE_HV:
		hstgpid = HSTGRP_GROUPID_SERVER;
		break;
	case DEVICE_TYPE_VM:
		hstgpid = HSTGRP_GROUPID_VM;
		break;
	case DEVICE_TYPE_NETWORK:
		hstgpid = HSTGRP_GROUPID_NETWORK;
		break;
	case DEVICE_TYPE_STORAGE:
	{
		// 分离品牌和型号
		int value_num = 2;
		char *manufacturer_value[2] = {0};
		zbx_split(model, "-", manufacturer_value, &value_num);
		storage_template(manufacturer_value[0], manufacturer_value[1], hst_groupid, templateid);
		break;
	}

	default:
		break;
	}

	switch (check_type)
	{
	case SVC_AGENT:
		if(device_type == DEVICE_TYPE_HV || device_type == DEVICE_TYPE_VM){
			if(is_windows) 
				*templateid = TEMPLATEID_SERVER_WINDOWS_BY_AGENT;
			else
				*templateid = TEMPLATEID_SERVER_LINUX_BY_AGENT;
		}
		break;
	case SVC_SNMPv1:
	case SVC_SNMPv2c:
	case SVC_SNMPv3:
		if(device_type == DEVICE_TYPE_HV || device_type == DEVICE_TYPE_VM)
		{
			if(is_windows)
				*templateid = TEMPLATEID_SERVER_WINDOWS_BY_SNMP;
			else
				*templateid = TEMPLATEID_SERVER_LINUX_BY_SNMP;
		}
		else if(device_type == DEVICE_TYPE_NETWORK)
		{
			*templateid = TEMPLATEID_NETWORK_DEVICE_SNMP;
		}
		else if(!is_windows && !is_linux)
		{
			if(net_hShow > 0){
				*templateid = TEMPLATEID_NETWORK_DEVICE_SNMP;
				hstgpid = HSTGRP_GROUPID_NETWORK;
			}
			// 这个判断规则需要改善
			else if(net_lShow > 0 && NULL != model && strlen(model) > 0){
				*templateid = TEMPLATEID_NETWORK_DEVICE_SNMP;
				hstgpid = HSTGRP_GROUPID_NETWORK;
			}
		}
		break;
	case SVC_IPMI:
		hstgpid = HSTGRP_GROUPID_SERVER;
		*templateid = TEMPLATEID_SERVER_IPMI;
		break;
	default:
		break;
	}
 
	if(0 == *hst_groupid){
		*hst_groupid = hstgpid;
	}

	//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s osShow=%d, net_lShow=%d, net_hShow:%d, type=%d, templateid=%d, model=%s, sysdesc:%s",
	//	 __func__, osShow, net_lShow, net_hShow, check_type, *templateid, model, sysdesc);
	
	zbx_vector_str_clear_ext(&v_sdesc, zbx_str_free);
	zbx_vector_str_destroy(&v_sdesc);
}


int discovery_register_soft(DB_HOST *host,DB_HOST_INVENTORY *inventory, const void *in_value, const char *ip, const char *dns, int port, int status, DB_DCHECK *dcheck)
{
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);
	
	if(NULL == dcheck || NULL == ip || strlen(ip) < 5) {
		zabbix_log(LOG_LEVEL_DEBUG, "%s fail!", __func__); 
		return FAIL; 
	} 

	int         ret = SUCCEED, is_new = 0;
	time_t		create_time=0,update_time=0;
	int hst_groupid=0, templateid=0;
	char host_s[256],ipproxy_s[128],name_s[256], *soft_des = NULL;
	
	if(SVC_ICMPPING == dcheck->type){  //扫描类型，没有传参，只能根据dcheck type来转化devicetype
		dcheck->devicetype = DEVICE_TYPE_PING;
	}
	host->device_type = dcheck->devicetype;
	host->status = HOST_STATUS_UNREACHABLE;

	if(FAIL == (ret = get_values_by_device_type(host->device_type, &soft_des, &hst_groupid, &templateid))){
		zabbix_log(LOG_LEVEL_DEBUG, "%s() get values by device_type fail, devicetype=%d", __func__, host->device_type);
		return FAIL;
	} 
	if(dcheck->devicetype >= DEVICE_TYPE_DOCKER && dcheck->devicetype <= DEVICE_TYPE_KUBERNETES_SCHEDULER){
		zbx_snprintf(name_s, sizeof(name_s),"%s[%s]", soft_des, dcheck->name);
		host->name = zbx_strdup(NULL, name_s);
	}else if(NULL == host->name){
		host->name = zbx_strdup(NULL, dcheck->name);
	}
	
	if(0 == host->hstgrpid){ //host有hstgrpid数据，则不用inventory_typeid
		host->hstgrpid = hst_groupid;
	}
	host->templateid = templateid;
	
	memset(host_s, 0, 256);
	memset(ipproxy_s, 0, 128);
	if(host->proxy_hostid > 0){
		zbx_snprintf(ipproxy_s, sizeof(ipproxy_s),"%s-%d", ip,host->proxy_hostid);
	}else{
		zbx_snprintf(ipproxy_s, sizeof(ipproxy_s),"%s", ip);
	}
	
	if(DEVICE_TYPE_PROCESS == dcheck->devicetype){ 
		zbx_snprintf(host_s, sizeof(host_s),"%s-%s-%s", ipproxy_s, soft_des, dcheck->process_name);
	}else if(SVC_AGENT == dcheck->type || SVC_ICMPPING == dcheck->type ){ 
		// 如果是代理监控和ping监控，端口都一样，所以不要用端口区分
		zbx_snprintf(host_s, sizeof(host_s),"%s-%s", ipproxy_s, soft_des);
	}else{ //一台服务器可能安装多个同类软件，所以要用ip、端口、代理和软件描述一起区分
		zbx_snprintf(host_s, sizeof(host_s),"%s-%d-%s", ipproxy_s, port,  soft_des);
	}
	
	host->host = zbx_strdup(NULL, host_s);

	dc_soft_find_update_hosts(host, ip);
	
	create_time = update_time = (int)time(NULL);
	int db_ret = 0;
	if (!host->hostid)
	{
		if (DOBJECT_STATUS_UP == status)	/* add host only if service is up */
		{
			host->hostid = zbx_db_get_maxid("hosts");
			db_ret = zbx_db_execute("insert into hosts (hostid,proxy_hostid,name,host,status,flags,description," \
					"create_time,uuid, templateid,groupid,hstgrpid,device_type)" \
					" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ",'%s','%s', %d, %d,'%s', %d,'%s',%d,%d,%d,%d)",
					host->hostid, host->proxy_hostid, host->name, host->host, HOST_STATUS_UNREACHABLE, 0, soft_des,
					create_time, host->uuid, templateid,host->groupid,host->hstgrpid,host->device_type);
			is_new = 1;
		}
	}
	else  
	{
		db_ret = zbx_db_execute("update hosts set proxy_hostid=%llu,name='%s',host='%s',update_time=%d,templateid=%d," \
				"groupid=%d,hstgrpid=%d,device_type=%d where hostid=" ZBX_FS_UI64,
				host->proxy_hostid,host->name,host->host,update_time,templateid,host->groupid,host->hstgrpid,host->device_type,host->hostid);
	}
	ret = db_ret >= 1 ? SUCCEED : FAIL;
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, is_new=%d,dbret=%d, status=%d, host->status=%d, hostid=%d, name=%s, proxy_hostid=%d",
		 __func__, is_new, db_ret, status, host->status, host->hostid, host->name, host->proxy_hostid);
	
	update_discovery_hosts(host);

	if(NULL != inventory)
	{
		inventory->dunique_type = DUNIQUE_TYPE_SOFT;
		inventory->dunique = zbx_strdup(NULL, host->host);
		inventory->hostid = host->hostid;
		inventory->inventory_typeid = hst_groupid;
		inventory->name = zbx_strdup(NULL, host->name);
		inventory->houseid = dcheck->houseid;
		inventory->managerid = dcheck->managerid;
		inventory->ip = zbx_strdup(NULL, ip);
		inventory->description = zbx_strdup(NULL, soft_des);
	}

out:

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
	return ret;
}

discovery_parsing_templateid(const DB_DCHECK *dcheck, const void *in_value, int *templateid, int *hst_groupid)
{
	vmware_server *p_vmware = NULL;
	nutanix_server *p_nutanix = NULL;
	int device_type = 0, hstgpid = 0;
	if(dcheck->type == SVC_VMWARE)
	{
		// 确定VMWare 物理机和虚拟机对应的模板ID
		p_vmware = (vmware_server *)in_value; 
		if(DEVICE_TYPE_HV == p_vmware->type){
			*templateid = TEMPLATEID_VMWARE_HV_SERVER;
			hstgpid = HSTGRP_GROUPID_SERVER;
		}else if(DEVICE_TYPE_VM == p_vmware->type){
			*templateid = TEMPLATEID_VMWARE_VM_SERVER;
			hstgpid = HSTGRP_GROUPID_VM;
		}
		device_type = p_vmware->type;
	}
	if(dcheck->type == SVC_NUTANIX)
	{
		p_nutanix = (nutanix_server *)in_value;
		// 确定VMWare 物理机和虚拟机对应的模板ID 
		if(DEVICE_TYPE_CLUSTER == p_nutanix->type){
			//templateid = TEMPLATEID_NUTANIX_CLUSTER;
			hstgpid = HSTGRP_GROUPID_SERVER;
		}
		else if(DEVICE_TYPE_HV == p_nutanix->type){
			*templateid = TEMPLATEID_NUTANIX_HV;
			hstgpid = HSTGRP_GROUPID_SERVER;
		}else if(DEVICE_TYPE_VM == p_nutanix->type){
			*templateid = TEMPLATEID_NUTANIX_VM;
			hstgpid = HSTGRP_GROUPID_VM;
		}
		device_type = p_nutanix->type;
	} 
	 
	// 确定nutanix 集群对应的模板ID
	if(SVC_NUTANIX == dcheck->main_type && SVC_SNMPv3 == dcheck->type){
		*templateid = TEMPLATEID_NUTANIX_CLUSTER;
		device_type = dcheck->devicetype;
		hstgpid = HSTGRP_GROUPID_SERVER;
	}

	if(0 == *hst_groupid){
		*hst_groupid = hstgpid;
	}

	zabbix_log(LOG_LEVEL_INFORMATION, "#TOGNIX#%s, dcheck_type=%d, devicetype=%d, templateid=%d, hstgpid=%d", 
		__func__, dcheck->type, device_type, *templateid, hstgpid);
	

}
/******************************************************************************
 *                                                                            *
 * Purpose: register service if one does not exist                            *
 *                                                                            *
 * 只注册不更新，web端会手动更新，如果自动更新会覆盖手动更新                       *
 *                                                                            *
 ******************************************************************************/
int discovery_register_host(DB_HOST *host,DB_HOST_INVENTORY *inventory, const void *in_value, const char *ip, const char *dns, int port, int status, const DB_DCHECK *dcheck)
{
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	int         ret = SUCCEED;
	time_t		create_time=0,update_time=0;
	
	int hst_groupid = 0, templateid=0;

	char *value,  *manufacturer = NULL;
	char *sysdesc=NULL,*entphysicalmodel=NULL,*entphysicalserial=NULL,*description_esc=NULL;
	char *os=NULL, *chassis = NULL,*chassis_serial = NULL,*board = NULL,*board_serial = NULL;

	// IPMI的相关变量		
	char *temp = NULL, *ipmi_username = NULL, *ipmi_password = NULL, *ipmi_username_esc = NULL, *ipmi_password_esc = NULL;
	int ipmi_authtype = 0, ipmi_privilege = 0;
	ipmitool_option_t *ioption = NULL;
	
	host->macs =  (zbx_vector_str_t *)zbx_malloc(host->macs, sizeof(zbx_vector_str_t));
	zbx_vector_str_create(host->macs);
	 
	vmware_server *p_vmware = NULL;
	nutanix_server *p_nutanix = NULL;
	switch (dcheck->type)
	{
	case SVC_VMWARE:
		// 一定要用 zbx_strdup 复制，否则会crash
		p_vmware = (vmware_server *)in_value; 
		
		host->device_type = p_vmware->type;
		host->hstgrpid = p_vmware->hstgrpid;
		
		host->name = zbx_strdup(host->name, p_vmware->name);
		host->uuid = zbx_strdup(NULL, p_vmware->uuid);
		host->ifphysaddresses = zbx_strdup(host->ifphysaddresses, p_vmware->macs);
		str_to_vector(host->macs, p_vmware->macs, "/");

		inventory->cpu =  zbx_strdup(NULL, p_vmware->cpu);
		inventory->memory =  zbx_strdup(NULL, p_vmware->memory);
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s SVC_VMWARE name=%s, devicetype=%d, uuid=%s", 
		__func__, p_vmware->name, p_vmware->type, p_vmware->uuid);
		break;
	case SVC_NUTANIX:
		p_nutanix = (nutanix_server *)in_value;
		host->name = zbx_strdup(NULL, p_nutanix->name);
		host->device_type = p_nutanix->type;
		host->hstgrpid = p_nutanix->hstgrpid; 

		host->uuid = zbx_strdup(NULL, p_nutanix->uuid);
		host->ifphysaddresses = zbx_strdup(host->ifphysaddresses, p_nutanix->macs);
		str_to_vector(host->macs, p_nutanix->macs, "/");

		inventory->disk = zbx_strdup(NULL, p_nutanix->disk);
		inventory->cpu = zbx_strdup(NULL, p_nutanix->cpu);
		inventory->bios = zbx_strdup(NULL, p_nutanix->bios);
		inventory->memory = zbx_strdup(NULL, p_nutanix->memory);
		break;
	case SVC_IPMI:
		// ipmi 模板
		discovery_parsing_value(in_value, "ipmi_username",&ipmi_username);
		discovery_parsing_value(in_value,"ipmi_password",&ipmi_password);
		discovery_parsing_value(in_value,"ipmi_privilege",&temp);
		ipmi_privilege = zbx_atoi(temp);
		zbx_free(temp);  temp = NULL;
		discovery_parsing_value(in_value,"ipmi_authtype",&temp);
		ipmi_authtype = zbx_atoi(temp);
		zbx_free(temp);  temp = NULL;
		
		ipmi_username_esc = zbx_db_dyn_escape_field("hosts", "ipmi_username", ipmi_username);
		ipmi_password_esc = zbx_db_dyn_escape_field("hosts", "ipmi_password", ipmi_password);

		// update_ipmi_hostmacro(host->hostid, ipmi_username, ipmi_password);

		// 资产信息提取
		init_ipmitool_option(&ioption);
		get_ipmi_inventory_value(ioption,ip, port, ipmi_username, ipmi_password);// 获取资产
		discovery_parsing_value(ioption->json, "chassis", &chassis);
		discovery_parsing_value(ioption->json, "chassis_serial", &chassis_serial);
		discovery_parsing_value(ioption->json, "board", &board);
		discovery_parsing_value(ioption->json, "board_serial", &board_serial);

		/*ipmi*/
		inventory->chassis = zbx_strdup(NULL, chassis);
		inventory->chassis_serial = zbx_strdup(NULL, chassis_serial);
		inventory->board = zbx_strdup(NULL, board);
		inventory->board_serial = zbx_strdup(NULL, board_serial);
		inventory->cpu = extract_json_field(ioption->json, "cpu");
		inventory->disk = extract_json_field(ioption->json, "disk");
		inventory->network = extract_json_field(ioption->json, "network");
		inventory->bios = extract_json_field(ioption->json, "bios");
		inventory->psu = extract_json_field(ioption->json, "psu");

		free_ipmitool_option(ioption);
		break;
	case SVC_HTTPS:
	{
		value = (char *)in_value;
		if(dcheck->devicetype == DEVICE_TYPE_STORAGE)
		{
			host->device_type = dcheck->devicetype;
			char *jsonpath = "$.entries[*].content";
			char *newvalue = NULL;
			zbx_jsonobj_t	obj;

			if (FAIL == zbx_jsonobj_open(value, &obj))
				zabbix_log(LOG_LEVEL_ERR,"#TOGNIX#%s open storage json faid",__func__);
			zbx_jsonobj_query(&obj, jsonpath, &newvalue);
			discovery_parsing_macs(newvalue, "macAddress",host->macs);

			vector_to_str_max(host->macs, &host->ifphysaddresses, "/", MAX_MACADDRESS_NUM);
			entphysicalmodel = zbx_strdup(NULL, dcheck->path);
			host->name = zbx_strdup(NULL, dcheck->name);
		}
	}break;
	default:
		value = (char *)in_value;
		discovery_parsing_macs(value, ZBX_DSERVICE_KEY_IFPHYSADDRESS,host->macs);
		vector_to_str_max(host->macs, &host->ifphysaddresses, "/", MAX_MACADDRESS_NUM);
		host->device_type = dcheck->devicetype;

		discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSNAME,&host->name);
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSDESC,&sysdesc);
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM,&entphysicalserial);
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME,&entphysicalmodel);
		break;
	}
	 
	
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, dcheck_type=%d, name=%s, devicetype=%d, uuid=%s, hstgrpid=%d,macsnum=%d,macs=%s", 
		__func__, dcheck->type, host->name, host->device_type, host->uuid, host->hstgrpid, host->macs->values_num, host->ifphysaddresses);

	//如果mac地址为空并且ip地址也是空，则不监控  
	if (0 == host->macs->values_num && ( NULL == ip || 0 == strlen(ip) || 0 == zbx_strcmp_null(ip, ZERO_IP_ADDRESS)))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s can't monitor. dcheckid:%d ip:%s port:%d dns:%s", __func__, dcheck->dcheckid, ip, port, dns);
		ret = FAIL;
		goto out;
	}

	host->status = HOST_STATUS_UNREACHABLE;
	if(NOTSUPPORTED ==  dc_find_update_hosts(host, ip, dcheck->type)){
		ret = FAIL;
		goto out; 
	}

	// 根据系统描述和entphysicalmodel查找厂商名称，群组，模板id
	discovery_parsing_value_model(entphysicalmodel, sysdesc, dcheck->type, &hst_groupid, &manufacturer, &templateid);

	// 根据系统描述分析出操作系统名称，再根据操作系统名称或数据库中的device_type分析出模板ID和群组ID
	discovery_parsing_os_value(sysdesc, dcheck->type, host->device_type, entphysicalmodel, &os, &templateid, &hst_groupid);

	// 确定VMWare 物理机和虚拟机对应的模板ID
	discovery_parsing_templateid(dcheck, in_value, &templateid, &hst_groupid);

	// 如果找出新模板，则用新模板。否则用数据库中以前的模板
	if(0 < templateid && templateid != host->templateid){
		host->templateid = templateid;
	}

	// 如果找出群组，则用群组。否则用数据库中以前的群组. >1000 表示该hst_groupid是有层级关系。
	if(0 < hst_groupid && HSTGRP_ID_PRESET_MAX > host->hstgrpid){
		host->hstgrpid = hst_groupid;
	}

	description_esc = zbx_db_dyn_escape_field("hosts", "description", sysdesc);
	if(NULL == ipmi_username_esc) ipmi_username_esc = zbx_strdup(NULL,"");
	if(NULL == ipmi_password_esc) ipmi_password_esc = zbx_strdup(NULL,"");
	create_time = update_time = (int)time(NULL);
	int db_ret = 0;
	if (!host->hostid)
	{
		if (DOBJECT_STATUS_UP == status)	/* add host only if service is up */
		{
			host->hostid = zbx_db_get_maxid("hosts");
			db_ret = zbx_db_execute("insert into hosts (hostid,proxy_hostid,name,host,ifphysaddresses,status,flags,description," \
					"create_time,templateid,groupid,hstgrpid,device_type,uuid,ipmi_username,ipmi_password,ipmi_privilege,ipmi_authtype)" \
					" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ",'%s','%s','%s',%d,%d,'%s',%d,%d,%d,%d,%d,'%s','%s','%s',%d,%d)", 
					host->hostid, host->proxy_hostid, host->name, host->host, host->ifphysaddresses, HOST_STATUS_UNREACHABLE, 0, description_esc, 
					create_time,host->templateid,host->groupid,host->hstgrpid,host->device_type,host->uuid,ipmi_username_esc,ipmi_password_esc,ipmi_privilege,ipmi_authtype);
		}
	}
	else  
	{
		db_ret = zbx_db_execute("update hosts set proxy_hostid=%llu,name='%s',host='%s',ifphysaddresses='%s'," \
				"update_time=%d,templateid=%d,groupid=%d,hstgrpid=%d,device_type=%d,uuid='%s'," \
				"ipmi_username='%s', ipmi_password='%s', ipmi_privilege=%d, ipmi_authtype=%d " \
				" where hostid=" ZBX_FS_UI64,
				host->proxy_hostid,host->name,host->host,host->ifphysaddresses,
				update_time,host->templateid,host->groupid,host->hstgrpid,host->device_type,host->uuid,
				ipmi_username_esc,ipmi_password_esc,ipmi_privilege,ipmi_authtype,
				host->hostid);
	}
	ret = db_ret >= 1 ? SUCCEED : FAIL;
	 
	zabbix_log(LOG_LEVEL_INFORMATION, "#TOGNIX#%s, dbret=%d, status=%d, hoststatus=%d, hostid=%d, templateid=%d", 
		__func__, db_ret, status, host->status, host->hostid, host->templateid);
	
	update_discovery_hosts(host);

	// 绑定模板和资产列表，用hst_groupid
	if(0 < hst_groupid && hst_groupid < HSTGRP_ID_PRESET_MAX){
		host->hstgrpid = hst_groupid;
	}

	int dunique_type = DUNIQUE_TYPE_UNKNOW;
	char *dunique = NULL;
	if(host->ifphysaddresses != NULL && strlen(host->ifphysaddresses) > 5)
	{
		dunique_type = DUNIQUE_TYPE_MACS;
		dunique = host->ifphysaddresses;
	}
	else if(entphysicalserial != NULL && strlen(entphysicalserial) > 5)
	{
		dunique_type = DUNIQUE_TYPE_DEFAULT;
		dunique = entphysicalserial;
	}
	else if(ip != NULL && strlen(ip) > 5)
	{
		dunique_type = DUNIQUE_TYPE_IP;
		dunique = ip;
	}
	inventory->dunique_type = dunique_type;
	inventory->dunique = zbx_strdup(NULL, dunique);
	inventory->hostid = host->hostid;
	inventory->inventory_typeid = hst_groupid;
	inventory->name = zbx_strdup(NULL, host->name);
	inventory->description =  zbx_strdup(NULL,sysdesc);
	inventory->physical_model =  zbx_strdup(NULL,entphysicalmodel);
	inventory->physical_serial =  zbx_strdup(NULL,entphysicalserial);
	inventory->houseid = dcheck->houseid;
	inventory->managerid = dcheck->managerid;
	inventory->os_short = zbx_strdup(NULL,os);
	inventory->manufacturer = zbx_strdup(NULL,manufacturer);
	inventory->ip = zbx_strdup(NULL, ip);

out:
	zbx_free(sysdesc);
	zbx_free(entphysicalmodel);
	zbx_free(entphysicalserial);
	zbx_free(description_esc);
	zbx_free(os); 
	zbx_free(chassis);
	zbx_free(chassis_serial);
	zbx_free(board);
	zbx_free(board_serial);

	zbx_free(ipmi_username);
	zbx_free(ipmi_password);
	zbx_free(ipmi_password_esc);
	zbx_free(ipmi_username_esc);
  
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
	return ret;
}


static void	discovery_register_interface_snmp(int interfaceid, const DB_DCHECK *dcheck)
{
	DB_RESULT	result;
	DB_ROW		row;
	int version;

	if (SVC_SNMPv1==dcheck->type)
		version=1;
	else if (SVC_SNMPv2c==dcheck->type)
		version=2;
	else if (SVC_SNMPv3==dcheck->type)
		version=3;
	else
		version=0;

	result = zbx_db_select("select interfaceid from interface_snmp"
			" where interfaceid=" ZBX_FS_UI64,
			interfaceid);

	if (NULL == (row = zbx_db_fetch(result)))
	{
		zbx_db_execute("insert into interface_snmp (interfaceid,version,community,securityname,securitylevel, authpassphrase,privpassphrase,authprotocol,privprotocol,contextname)"
				" values (" ZBX_FS_UI64 ",%d,'%s','%s',%d,'%s','%s',%d,%d,'%s')",
				interfaceid, version, dcheck->snmp_community,dcheck->snmpv3_securityname,dcheck->snmpv3_securitylevel,
				dcheck->snmpv3_authpassphrase,dcheck->snmpv3_privpassphrase,dcheck->snmpv3_authprotocol,dcheck->snmpv3_privprotocol,dcheck->snmpv3_contextname);
	}
	else
	{
		zbx_db_execute("update interface_snmp set version=%d,community='%s',securityname='%s',securitylevel=%d,authpassphrase='%s',privpassphrase='%s',authprotocol=%d,privprotocol=%d,contextname='%s'"
			" where interfaceid=" ZBX_FS_UI64,
			version,dcheck->snmp_community,dcheck->snmpv3_securityname,dcheck->snmpv3_securitylevel,
			dcheck->snmpv3_authpassphrase,dcheck->snmpv3_privpassphrase,dcheck->snmpv3_authprotocol,dcheck->snmpv3_privprotocol,dcheck->snmpv3_contextname,interfaceid);
	}

	zbx_db_free_result(result);
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}


/******************************************************************************
 *                                                                            *
 * Purpose: register service if one does not exist                            *
 *                                                                            *
 * 只注册不更新，web端会手动更新，如果自动更新会覆盖手动更新                       *
 *                                                                            *
 ******************************************************************************/
void discovery_register_interface(const DB_HOST *host, DB_INTERFACE *interface,
	const char *ip, const char *dns, int port, const DB_DCHECK *dcheck)
{
	DB_RESULT	result;
	DB_ROW		row;
	int main = 1, interfaceid = -1; //此默认值不能修改，否则会导致程序逻辑出错
	char		*ip_esc = NULL, *dns_esc = NULL, *extend = NULL;
	int templateid = -1, host_templateid = host->templateid;

	if(NULL == host || host->hostid == 0){
		zabbix_log(LOG_LEVEL_DEBUG, "%s hostid is illegal", __func__);
		return;
	}

	ip_esc = zbx_db_dyn_escape_field("interface", "ip", ip);
	dns_esc = zbx_db_dyn_escape_field("interface", "dns", dns);

	//用ip和端口来确定接口的唯一性 在监控的时候需要判断通过ip和端口返回的mac地址是否和数据库一致如果不一致 说明ip或者端口变了 这个接口需要废弃(如果接口数为0了 重新扫描？)
	result = zbx_db_select("select interfaceid,main,type,ip,port,available from interface"
			" where hostid=" ZBX_FS_UI64,
			host->hostid);
	
	int type = (NULL==dcheck ? INTERFACE_TYPE_UNKNOWN : get_interface_type_by_dservice_type(dcheck->type));

	while (NULL != (row = zbx_db_fetch(result)))
	{
		int db_interfaceid = atoi(row[0]);
		int db_main = atoi(row[1]);
		int db_type = atoi(row[2]);
		char *db_ip = row[3];
		int db_port = zbx_atoi(row[4]);
		int db_available = zbx_atoi(row[5]);

		// 如果hostid, type, ip, port 都一样，或者VMWares扫描并且ip为"0.0.0.0", 说明要更新
		if(db_type == type && port == db_port &&  ( 0 == zbx_strcmp_null(ip_esc, db_ip) 
			|| (INTERFACE_TYPE_VMWARE == type && 0 == zbx_strcmp_null(ZERO_IP_ADDRESS, db_ip))))
		{
			interfaceid = db_interfaceid;
		}
		// main 是定义接口是否是默认接口的字段，
		//1:默认接口，默认接口意思是hostid和type都是第一次加入的接口，一台主机中同个type类型只有一个； 0：非默认接口,hostid和type 在表中存在过
		else if(db_type == type && 1 == db_main) //如果同个主机中有相同类型，而且主机main也是1，说明已经有默认接口了，此次增加的接口就为非默认接口
		{
			main = 0;
		}

		if(INTERFACE_TYPE_IPMI == db_type && 1 == db_available)  
		{
			switch (type)
			{
			case INTERFACE_TYPE_AGENT:
				templateid = TEMPLATEID_SERVER_LINUX_BY_AGENT;
				break;
			case INTERFACE_TYPE_SNMP:
				templateid = TEMPLATEID_SERVER_LINUX_BY_SNMP;
			default:
				break;
			} 
		}
	}
	
	zabbix_log(LOG_LEVEL_DEBUG, "In %s() hostid:%d ip:%s port:%d,type:%d,interfaceid:%d,main:%d,templateid:%d", 
		__func__, host->hostid, ip_esc, port, type, interfaceid, main, templateid);
	
	if(templateid > 0)
	{
		zbx_db_execute("update hosts set templateid=%d where hostid=" ZBX_FS_UI64, templateid,host->hostid);
		host_templateid = templateid;
	}
	
	int credentialid = dcheck->credentialid;
	
	if( (NULL != dcheck->path) && (0 != strlen(dcheck->path)) )
		extend = zbx_get_db_escape_string(dcheck->path);
	else if((NULL != dcheck->database) && (0 != strlen(dcheck->database)) )
		extend = zbx_get_db_escape_string(dcheck->database);
	else
		extend = zbx_strdup(NULL, "");
		
	if (interfaceid == -1)
	{
		interface->interfaceid = zbx_db_get_maxid("interface");
		interface->status = HOST_STATUS_UNREACHABLE;
		zbx_db_execute("insert into interface (interfaceid,hostid,ip,dns,port,available,type,main,credentialid,templateid,extend)"
				" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ",'%s','%s','%d', %d, %d, %d, %d, %d ,'%s')",
				interface->interfaceid, host->hostid, ip_esc, dns_esc, port, interface->available, type, main, credentialid, host_templateid, extend);
	}
	else
	{
		interface->interfaceid = interfaceid;
		interface->status = HOST_STATUS_MONITORED;
		zbx_db_execute("update interface set hostid="ZBX_FS_UI64",ip='%s',dns='%s',port='%d', type=%d,main=%d,credentialid=%d, templateid=%d, extend='%s'"
		" where interfaceid="ZBX_FS_UI64,
		host->hostid,ip_esc,dns_esc,port,type,main,credentialid, host_templateid, extend, interfaceid);
	}

	// 当第一次扫码为Nutanix 或VMWare 等方式时，如果没有开机当前的IP可能为'0.0.0.0'，后续再用SNMP，Agent方式添加时，修正以前扫描的IP
	if(0 != zbx_strcmp_null(ip_esc, ZERO_IP_ADDRESS)){
		zbx_db_execute("update interface set ip='%s',dns='%s' where hostid=" ZBX_FS_UI64 " and ip='%s'",
			ip_esc, dns_esc, host->hostid, ZERO_IP_ADDRESS);
	}

	zbx_db_free_result(result);

	if (INTERFACE_TYPE_SNMP==type)
		discovery_register_interface_snmp(interface->interfaceid, dcheck);

	
	zbx_free(ip_esc);
	zbx_free(dns_esc);
	zbx_free(extend);
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}



/******************************************************************************
 *                                                                            *
 * Purpose: register service if one does not exist                            *
 *                                                                            *
 * Parameters: host ip address                                                *
 *                                                                            *
 ******************************************************************************/
static void	discovery_register_dservice(zbx_uint64_t dcheckid, zbx_db_dhost *dhost, DB_DSERVICE *dservice,
		const char *ip, const char *dns, int port, int status)
{
	DB_RESULT	result;
	DB_ROW		row;
	char		*ip_esc, *dns_esc;

	zbx_uint64_t	dhostid;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s' port:%d", __func__, ip, port);

	ip_esc = zbx_db_dyn_escape_field("dservices", "ip", ip);

	result = zbx_db_select(
			"select dserviceid,dhostid,status,lastup,lastdown,value,dns"
			" from dservices"
			" where dcheckid=" ZBX_FS_UI64
				" and ip" ZBX_SQL_STRCMP
				" and port=%d",
			dcheckid, ZBX_SQL_STRVAL_EQ(ip_esc), port);

	if (NULL == (row = zbx_db_fetch(result)))
	{
		if (DOBJECT_STATUS_UP == status)	/* add host only if service is up */
		{
			zabbix_log(LOG_LEVEL_DEBUG, "new service discovered on port %d", port);

			dservice->dserviceid = zbx_db_get_maxid("dservices");
			dservice->status = DOBJECT_STATUS_DOWN;
			dservice->value = zbx_strdup(dservice->value, "");

			dns_esc = zbx_db_dyn_escape_field("dservices", "dns", dns);

			zbx_db_execute("insert into dservices (dserviceid,dhostid,value,dcheckid,ip,dns,port,status)"
					" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ",''," ZBX_FS_UI64 ",'%s','%s',%d,%d)",
					dservice->dserviceid, dhost->dhostid, dcheckid, ip_esc, dns_esc, port,
					dservice->status);

			zbx_free(dns_esc);
		}
	}
	else
	{
		zabbix_log(LOG_LEVEL_DEBUG, "service is already in database");

		ZBX_STR2UINT64(dservice->dserviceid, row[0]);
		ZBX_STR2UINT64(dhostid, row[1]);
		dservice->status = atoi(row[2]);
		dservice->lastup = atoi(row[3]);
		dservice->lastdown = atoi(row[4]);
		dservice->value = zbx_strdup(dservice->value, row[5]);

		if (dhostid != dhost->dhostid)
		{
			zbx_db_execute("update dservices"
					" set dhostid=" ZBX_FS_UI64
					" where dhostid=" ZBX_FS_UI64,
					dhost->dhostid, dhostid);

			zbx_db_execute("delete from dhosts"
					" where dhostid=" ZBX_FS_UI64,
					dhostid);
		}

		if (0 != strcmp(row[6], dns))
		{
			dns_esc = zbx_db_dyn_escape_field("dservices", "dns", dns);

			zbx_db_execute("update dservices"
					" set dns='%s'"
					" where dserviceid=" ZBX_FS_UI64,
					dns_esc, dservice->dserviceid);

			zbx_free(dns_esc);
		}
	}
	zbx_db_free_result(result);

	zbx_free(ip_esc);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: update discovered service details                                 *
 *                                                                            *
 ******************************************************************************/
static void	discovery_update_dservice(zbx_uint64_t dserviceid, int status, int lastup, int lastdown,
		const char *value)
{
	char	*value_esc;

	value_esc = zbx_db_dyn_escape_field("dservices", "value", value);

	zbx_db_execute("update dservices set status=%d,lastup=%d,lastdown=%d,value='%s' where dserviceid=" ZBX_FS_UI64,
			status, lastup, lastdown, value_esc, dserviceid);

	zbx_free(value_esc);
}

/******************************************************************************
 *                                                                            *
 * Purpose: update discovered service details                                 *
 *                                                                            *
 ******************************************************************************/
static void	discovery_update_dservice_value(zbx_uint64_t dserviceid, const char *value)
{
	char	*value_esc;

	value_esc = zbx_db_dyn_escape_field("dservices", "value", value);

	zbx_db_execute("update dservices set value='%s' where dserviceid=" ZBX_FS_UI64, value_esc, dserviceid);

	zbx_free(value_esc);
}

/******************************************************************************
 *                                                                            *
 * Purpose: update discovered host details                                    *
 *                                                                            *
 ******************************************************************************/
static void	discovery_update_dhost(const zbx_db_dhost *dhost)
{
	zbx_db_execute("update dhosts set status=%d,lastup=%d,lastdown=%d where dhostid=" ZBX_FS_UI64,
			dhost->status, dhost->lastup, dhost->lastdown, dhost->dhostid);
}

/******************************************************************************
 *                                                                            *
 * Purpose: process and update the new service status                         *
 *                                                                            *
 ******************************************************************************/
static void	discovery_update_dservice_status(zbx_db_dhost *dhost, const DB_DSERVICE *dservice, int service_status,
		const char *value, int now)
{
	zbx_timespec_t	ts;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	ts.sec = now;
	ts.ns = 0;
	zabbix_log(LOG_LEVEL_DEBUG,"discovery_update_dservice_status value=%s",value);
	if (DOBJECT_STATUS_UP == service_status)
	{
		if (DOBJECT_STATUS_DOWN == dservice->status || 0 == dservice->lastup)
		{
			discovery_update_dservice(dservice->dserviceid, service_status, now, 0, value);
			zbx_add_event(EVENT_SOURCE_DISCOVERY, EVENT_OBJECT_DSERVICE, dservice->dserviceid, &ts,
					DOBJECT_STATUS_DISCOVER, NULL, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, NULL,
					NULL);

			if (DOBJECT_STATUS_DOWN == dhost->status)
			{
				/* Service went UP, but host status is DOWN. Update host status. */

				dhost->status = DOBJECT_STATUS_UP;
				dhost->lastup = now;
				dhost->lastdown = 0;

				discovery_update_dhost(dhost);
				zbx_add_event(EVENT_SOURCE_DISCOVERY, EVENT_OBJECT_DHOST, dhost->dhostid, &ts,
						DOBJECT_STATUS_DISCOVER, NULL, NULL, NULL, 0, 0, NULL,
						0, NULL, 0, NULL, NULL, NULL);
			}
		}
		else if (0 != strcmp(dservice->value, value))
		{
			discovery_update_dservice_value(dservice->dserviceid, value);
		}
	}
	else	/* DOBJECT_STATUS_DOWN */
	{
		if (DOBJECT_STATUS_UP == dservice->status || 0 == dservice->lastdown)
		{
			discovery_update_dservice(dservice->dserviceid, service_status, 0, now, dservice->value);
			zbx_add_event(EVENT_SOURCE_DISCOVERY, EVENT_OBJECT_DSERVICE, dservice->dserviceid, &ts,
					DOBJECT_STATUS_LOST, NULL, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, NULL,
					NULL);

			/* service went DOWN, no need to update host status here as other services may be UP */
		}
	}
	zbx_add_event(EVENT_SOURCE_DISCOVERY, EVENT_OBJECT_DSERVICE, dservice->dserviceid, &ts, service_status,
			NULL, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, NULL, NULL);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: update new host status                                            *
 *                                                                            *
 ******************************************************************************/
static void	discovery_update_host_status(zbx_db_dhost *dhost, int status, int now)
{
	zbx_timespec_t	ts;

	ts.sec = now;
	ts.ns = 0;

	/* update host status */
	if (DOBJECT_STATUS_UP == status)
	{
		if (DOBJECT_STATUS_DOWN == dhost->status || 0 == dhost->lastup)
		{
			dhost->status = status;
			dhost->lastdown = 0;
			dhost->lastup = now;

			discovery_update_dhost(dhost);
			zbx_add_event(EVENT_SOURCE_DISCOVERY, EVENT_OBJECT_DHOST, dhost->dhostid, &ts,
					DOBJECT_STATUS_DISCOVER, NULL, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, NULL,
					NULL);
		}
	}
	else	/* DOBJECT_STATUS_DOWN */
	{
		if (DOBJECT_STATUS_UP == dhost->status || 0 == dhost->lastdown)
		{
			dhost->status = status;
			dhost->lastdown = now;
			dhost->lastup = 0;

			discovery_update_dhost(dhost);
			zbx_add_event(EVENT_SOURCE_DISCOVERY, EVENT_OBJECT_DHOST, dhost->dhostid, &ts,
					DOBJECT_STATUS_LOST, NULL, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, NULL,
					NULL);
		}
	}
	zbx_add_event(EVENT_SOURCE_DISCOVERY, EVENT_OBJECT_DHOST, dhost->dhostid, &ts, status, NULL, NULL, NULL, 0, 0,
			NULL, 0, NULL, 0, NULL, NULL, NULL);
}

/******************************************************************************
 *                                                                            *
 * Purpose: process new host status                                           *
 *                                                                            *
 * Parameters: host - host info                                               *
 *                                                                            *
 ******************************************************************************/
void	zbx_discovery_update_host(zbx_db_dhost *dhost, int status, int now)
{
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	if (NULL != dhost && 0 != dhost->dhostid)
		discovery_update_host_status(dhost, status, now);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

/******************************************************************************
 *                                                                            *
 * Purpose: process new service status                                        *
 *                                                                            *
 * Parameters: service - service info                                         *
 *                                                                            *
 ******************************************************************************/
void	zbx_discovery_update_service(zbx_db_drule *drule, zbx_uint64_t dcheckid, zbx_db_dhost *dhost,
		const char *ip, const char *dns, int port, int status, const char *value, int now, DB_DCHECK *dcheck)
{
	DB_DSERVICE	dservice;
	DB_HOST host;
	DB_INTERFACE interface;
	DB_HOST_INVENTORY inventory;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s' dns:'%s' port:%d proxy:%d status:%d value:'%s'",
			__func__, ip, dns, port, drule->proxy_hostid, status, value);

	memset(&dservice, 0, sizeof(DB_DSERVICE));
	memset(&host, 0, sizeof(DB_HOST));
	memset(&interface, 0, sizeof(DB_INTERFACE));
	memset(&inventory, 0, sizeof(DB_HOST_INVENTORY));
 
	//入库dhost /* register host if is not registered yet */
	if (0 == dhost->dhostid)
		discovery_register_dhost(drule, dcheckid, dhost, ip, port, status, value);

	//入库dservice /* register service if is not registered yet */
	if (0 != dhost->dhostid)
		discovery_register_dservice(dcheckid, dhost, &dservice, ip, dns, port, status);

	//更新dservice信息 /* service was not registered because we do not add down service */
	if (0 != dservice.dserviceid)
		discovery_update_dservice_status(dhost, &dservice, status, value, now);
 
	//暂时主机只做snmp/agent/ipmi proxy调用过来的也按原逻辑处理
	if (NULL == dcheck || INTERFACE_TYPE_UNKNOWN == get_interface_type_by_dservice_type(dcheck->type)){
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s fail, dcheck is illegal. type=%d", __func__, dcheck->type);
		goto out;
	}

	int ret = FAIL;
	host.proxy_hostid = drule->proxy_hostid;
	//入库host 
	if(SVC_ICMPPING == dcheck->type){
		ret = discovery_register_soft(&host, &inventory, value, ip, dns, port, status, dcheck);
	}else if (DEVICE_TYPE_HW_MAX > dcheck->devicetype && 0 != dservice.dserviceid){
		host.hostid = drule->main_hostid;
		ret = discovery_register_host(&host, &inventory, value, ip, dns, port, status, dcheck);
	} 
		
	if(SUCCEED == ret)
	{
		discovery_register_interface(&host, &interface, ip, dns, port, dcheck);

		//if(SVC_ICMPPING != dcheck->type){
			discovery_register_host_inventory(&inventory);
		//}

		// 对dhost赋值，是为了返回上层绑定模板和add_hostid
		dhost->hostid = host.hostid;
		dhost->templateid = host.templateid;
		dhost->hstgrpid = host.hstgrpid;
		dhost->hstatus = host.status;
		dhost->istatus = interface.status;
		dhost->druleid = dcheck->druleid;
		dhost->proxy_hostid = drule->proxy_hostid;
	}

out:
	db_hosts_free(&host);
	zbx_free(dservice.value);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

// 绑定模板和 返回hostid给前端展示
int discovery_update_other(zbx_db_dhost *dhost)
{
	DB_HOST host;

	if(NULL == dhost || 0 == dhost->hostid){
		zabbix_log(LOG_LEVEL_WARNING,"#TOGNIX#%s fail! hostid=%llu", __func__,(dhost==NULL?-1:dhost->hostid));
		return -1;
	}
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s proxy_hostid=%d, druleid=%d, hostid=%llu,templateid=%d,hstatus=%d,istatus=%d",
			__func__,dhost->proxy_hostid, dhost->druleid, dhost->hostid, dhost->templateid,dhost->hstatus,dhost->istatus);
	
	// status 0已监控，1已关闭，2未纳管, 未纳管的设备返回给前端实时显示
	if(dhost->hstatus == HOST_STATUS_UNREACHABLE || dhost->istatus == HOST_STATUS_UNREACHABLE)
	{
		host.hostid = dhost->hostid;
		host.templateid = dhost->templateid;
		host.hstgrpid = dhost->hstgrpid;
		
		// 绑定模板
		discoverer_bind_templateid(&host);

		if(dhost->proxy_hostid > 0){
			server_user_discover_add_proxy_hostid(dhost->druleid, host.hostid);
		}else{
			user_discover_add_hostid(dhost->druleid, host.hostid);
		}
	}
	return 0;
}