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
#include "../../zabbix_server/ipmi/ipmi_discovery.h"

void inventory_free(DB_HOST_INVENTORY *inventory)
{
	zbx_free(inventory->dunique);
	zbx_free(inventory->manufacturer);
	zbx_free(inventory->physical_model);
	zbx_free(inventory->physical_serial);
	zbx_free(inventory->chassis);
	zbx_free(inventory->chassis_serial);
	zbx_free(inventory->board);
	zbx_free(inventory->board_serial);
	zbx_free(inventory->os_short);
	zbx_free(inventory->ip);
	zbx_free(inventory->name);
	zbx_free(inventory->description);
	zbx_free(inventory->cpu);
	zbx_free(inventory->memory);
	zbx_free(inventory->disk);
	zbx_free(inventory->network);
	zbx_free(inventory->bios);
	zbx_free(inventory->psu);	
}

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

//把mac地址标准化输出
char * format_mac_address(char *mac_address)
{
	//zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s mac:%s\n",__func__, mac_address);
	char *formatted_mac = NULL;
	size_t	alloc = 0, offset = 0;
    int i=0, j=0, k=0, count=0;
	for (i = 0; i < zbx_strlen_utf8(mac_address); i++)
	{
        if (mac_address[i] == ':')
            count++;
    }
	int need_len = 3*count+3;
	formatted_mac = zbx_realloc(formatted_mac, need_len);
	//mac地址都是最多2位加一个:的
	formatted_mac[3*count+2] = '\0';
	//从后面往前面照抄过来 遇到:不够2位就补零
    for (i = zbx_strlen_utf8(mac_address)-1, j=3*count+1; i >= 0; i--)
	{
		if (mac_address[i]!=':')
		{
			k++;
			formatted_mac[j--] = mac_address[i];
		}
		else
		{
			if (k<2)
			{
				formatted_mac[j--]='0';
			}
			k=0;
			formatted_mac[j--]='-';
		}
    }
	//最后把前面的0补齐
	for (;j>=0;)
		formatted_mac[j--]='0';
 
	//zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s formatted_mac:%s",__func__, formatted_mac);
	
	return formatted_mac;
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
void discovery_parsing_macs(const char *data, zbx_vector_str_t *out)
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
		
		if (SUCCEED == zbx_json_value_by_name(&jp_item, ZBX_DSERVICE_KEY_IFPHYSADDRESS, buf_tmp, sizeof(buf_tmp), NULL))
		{
			//数据预处理 --mac地址补全
			if (zbx_strcmp_natural(buf_tmp, "") == 0)
				continue;
			//zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#discovery_parsing_macs mac:%s", buf_tmp);
			// agent 返回的mac地址一条可能有多个，中间用","分开
			if(NULL != index(buf_tmp,','))
			{
				int num = 20;
				char *macaddrs[20] = {0};
				zbx_split(buf_tmp, ",", macaddrs, &num);
				for(int k = 0; k < num; k ++)
				{
					zbx_lrtrim(macaddrs[k], ZBX_WHITESPACE);
					fmacaddr = format_mac_address(macaddrs[k]);
					//zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#discovery_parsing_macs,k=%d, mac:%s",k, fmacaddr);
					
					if (strncmp(fmacaddr, ZBX_DSERVICE_ILLEGAL_MACADDRS, ZBX_DSERVICE_ILLEGAL_MACADDRS_LEN) != 0)
					{
						char *tmp = zbx_dsprintf(NULL, "%s", fmacaddr);
						zbx_vector_str_append(out, tmp);

					}
					zbx_free(fmacaddr);
				}
			}
			else
			{
				fmacaddr = format_mac_address(buf_tmp);
				if (strncmp(fmacaddr, ZBX_DSERVICE_ILLEGAL_MACADDRS, ZBX_DSERVICE_ILLEGAL_MACADDRS_LEN) != 0)
				{
					char *tmp = zbx_dsprintf(NULL, "%s", fmacaddr);
					zbx_vector_str_append(out, tmp);
				}
				zbx_free(fmacaddr);
				
			}
		}
			
	}

	zbx_vector_str_sort(out, ZBX_DEFAULT_STR_COMPARE_FUNC);
	zbx_vector_str_uniq(out, ZBX_DEFAULT_STR_COMPARE_FUNC);
}

void str_to_vector(zbx_vector_str_t *out, const char *str, const char *split)
{
	char	*one, *saveptr;
	char	str_copy[MAX_STRING_LEN] = {0};
	zbx_strscpy(str_copy, str);
	 
	for (one = strtok_r(str_copy, split, &saveptr); NULL != one; one = strtok_r(NULL, split, &saveptr))
	{
		char *tmp = zbx_dsprintf(NULL, "%s", one);
		//zabbix_log(LOG_LEVEL_DEBUG, "str_to_vector str=%s",tmp);
		zbx_vector_str_append(out, tmp);
	}
	 
}

void vector_to_str(zbx_vector_str_t *v, char **out, const char *split)
{
	vector_to_str_max(v, out, split, 65535);
}

void vector_to_str_max(zbx_vector_str_t *v, char **out, const char *split, int max)
{
	size_t	alloc = 0, offset = 0;
	zbx_strcpy_alloc(out, &alloc, &offset, "");

	for (int i = 0; i < v->values_num && i < max; i++)
	{
		zbx_strcpy_alloc(out, &alloc, &offset, v->values[i]);
		zbx_strcpy_alloc(out, &alloc, &offset, "/");
	}
}

//设备类型id 厂商id 模板id  (硬件型号->厂商id  硬件型号->设备类型id、品牌id->模板id(默认值))
void discovery_parsing_value_model(const char *entphysicalmodel, const char *sysdesc, int dcheck_type, int *groupid, char **manufacturer, int *templateid)
{
	*manufacturer = NULL;

	*groupid = 0;
	*templateid = 0;
	DB_RESULT	result;
	DB_ROW		row;

	if(NULL != entphysicalmodel && strlen(entphysicalmodel) > 0){
		// 首先根据设备型号找出模板名称，群组，厂商名称
		result = zbx_db_select("select templateid,groupid,manufacturer from model_type where physical_model='%s'", entphysicalmodel);
		if (NULL != (row = zbx_db_fetch(result)))
		{
			*templateid = atoi(row[0]);
			*groupid = atoi(row[1]);
			*manufacturer = zbx_strdup(NULL, row[2]);
		}
		zbx_db_free_result(result);
	}

	//如果没有找到厂商名称，根据snmp协议返回的系统描述找出相关的厂家id
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

void discovery_parsing_value_os(const char *sysdesc, char **out)
{
	if (strstr(sysdesc, "Linux") || strstr(sysdesc, "linux"))
		*out = zbx_strdup(NULL, "Linux");
	else if (strstr(sysdesc, "Windows") || strstr(sysdesc, "windows"))
		*out = zbx_strdup(NULL, "Windows");
	else
		*out = zbx_strdup(NULL, "");
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
	int         ret = SUCCEED;
	DB_RESULT	result;
	DB_ROW		row;
	char		*name_esc=NULL,*host_esc=NULL,*ifphysaddresses_esc=NULL,*description_esc=NULL;
	char        *name_upper_esc=NULL;
	time_t		create_time,update_time;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	int hstgrpid = -1,device_type = -1, inventory_typeid = 0;
	char *uuid=NULL;
	char *sysname=NULL;					//资产名称
	char *sysdesc=NULL;					//主机描述(windows/linux 品牌)
	char *ifphysaddress=NULL;			//mac地址
	char *ifphysaddresses=NULL;			//mac地址 可能有多个以/分割
	char *entphysicalserial=NULL;		//序列号
	char *entphysicalmodel=NULL;		//硬件型号
	char *os=NULL;						//os
	char *name=NULL;					//服务器名称

	char *chassis = NULL;					// 机箱类型
	char *chassis_serial = NULL;			// 机箱序列号
	char *board = NULL;						// 主板名称
	char *board_serial = NULL;				// 主板序列号

	zbx_vector_str_t	macs_dis;
	zbx_vector_str_t	macs_his;
	zbx_vector_str_create(&macs_dis);
	zbx_vector_str_create(&macs_his);
	vmware_server *p_server = NULL;
	if(dcheck->type == SVC_VMWARE)
	{
		// 一定要用 zbx_strdup 复制，否则会crash
		p_server = (vmware_server *)in_value;
		
		hstgrpid = p_server->hstgrpid;
		device_type = p_server->type;
		sysname = zbx_strdup(NULL, p_server->id);
		uuid = zbx_strdup(NULL, p_server->uuid);
		//sysdesc = p_server->name;
		str_to_vector(&macs_dis, p_server->macs, "/");
		
		inventory->cpu =  zbx_strdup(NULL, p_server->cpu);
		inventory->memory =  zbx_strdup(NULL, p_server->memory);
		zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#%s, sysname=%s, uuid=%s, hstgrpid=%d,macs=%s", 
			 __func__, sysname, uuid, hstgrpid, p_server->macs);
	}
	else
	{
		char *value = (char *)in_value;
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSNAME,&sysname);
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSDESC,&sysdesc);
		discovery_parsing_macs(value,&macs_dis);
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM,&entphysicalserial);
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME,&entphysicalmodel);
		uuid = zbx_strdup(NULL,"");
	}


	//如果mac地址为空 记录日志  
	if (macs_dis.values_num == 0)
	{
		ret = FAIL;
		user_discover_add_alarm(dcheck->druleid,ip, port);
		zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s mac is null. dcheckid:%d ip:%s port:%d dns:%s", __func__, dcheck->dcheckid, ip, port, dns);
		goto out;
	}

	char *manufacturer = NULL, *repeat_name = NULL;
	int groupid=0,manufacturerid=0,templateid=0;
	char *db_name = NULL;

	discovery_parsing_value_model(entphysicalmodel, sysdesc, dcheck->type, &groupid, &manufacturer, &templateid);
	// 确定VMWare 物理机和虚拟机对应的模板ID
	if(dcheck->type == SVC_VMWARE && NULL != p_server){
		if(VMWARE_SERVER_TYPE_HV == p_server->type){
			templateid = VMWARE_SERVER_HV_TEMPLATEID;
			inventory_typeid = INVENTORY_SERVER_TYPEID;
		}else if(VMWARE_SERVER_TYPE_VM == p_server->type){
			templateid = VMWARE_SERVER_VM_TEMPLATEID;
			inventory_typeid = INVENTORY_VM_TYPEID;
		}
	}
	host->status = HOST_STATUS_UNREACHABLE;
	//新发现的mac地址和主机表里面的任何一个mac地址匹配上了 把匹配上的作为host字段 且说明在表里面
	result = zbx_db_select("select hostid,ifphysaddresses,name,status,device_type from hosts where ifphysaddresses != '' order by name asc");
	while (NULL != (row = zbx_db_fetch(result)))
	{
		int is_find = 0;
		zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
		zbx_vector_str_clear(&macs_his);
		str_to_vector(&macs_his, row[1], "/");
		char *host_name = row[2];
		
		for (int i = 0; i < macs_dis.values_num; i++)
		{
			int index;
			if (NULL == db_name && FAIL != (index = zbx_vector_str_bsearch(&macs_his, macs_dis.values[i], ZBX_DEFAULT_STR_COMPARE_FUNC)))
			{
				ZBX_STR2UINT64(host->hostid, row[0]);
				int db_devicetype = zbx_atoi(row[4]);
				// 如果虚拟机 的mac地址和 物理机的mac地址一样，把扫描出来的虚拟机丢弃，不监控
				if(db_devicetype == VMWARE_SERVER_TYPE_HV && device_type == VMWARE_SERVER_TYPE_VM)
				{
					ret = FAIL;
					zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s The MAC address of hv and vm is duplicated. hostid=%d", __func__, host->hostid);
					goto out;
				}
				
				db_name = host_name;
				host->status = atoi(row[3]);
				ifphysaddress = zbx_dsprintf(NULL, "%s", macs_his.values[index]);
				is_find = 1;
			}
		}

		// 如果发现其他主机名称和新扫描的主机名称一样，则记录其他主机的名称
		if(!is_find && NULL != host_name && NULL != sysname)
		{
			if(zbx_strncasecmp(sysname, host_name, strlen(sysname)) == 0)
			{
				repeat_name = host_name;
			}
		}
	}
	zbx_db_free_result(result);

	// 其他主机名称和新扫描的主机名称一样，则把新扫描主机从新命名，防止grafana根据主机名称显示状态出错
	if(NULL != repeat_name)
	{
		int number = 0;
		char new_name[256];
		zbx_vector_str_t	v_rname;
		zbx_vector_str_create(&v_rname);
		str_to_vector(&v_rname, repeat_name, "-");
		
		// 重命名的主机格式为 xxx-1,xxx-2. 如：ruijie-1，ruijie-2
		if(v_rname.values_num > 1){
			int number = zbx_atoi(v_rname.values[v_rname.values_num-1]);
			number ++;
			zbx_snprintf(new_name,sizeof(new_name),"%s-%d", sysname, number);
		}else{
			number = 1;
			zbx_snprintf(new_name,sizeof(new_name),"%s-%d", sysname, number);
		}
		sysname = zbx_strdup(sysname, new_name);
		zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s rename success. new_name=%s,", __func__, sysname);
		
		zbx_vector_str_clear_ext(&v_rname, zbx_str_free);
		zbx_vector_str_destroy(&v_rname);
	}

	if (NULL==ifphysaddress)
		ifphysaddress = zbx_dsprintf(NULL, "%s", macs_dis.values[0]);

	vector_to_str_max(&macs_dis, &ifphysaddresses, "/", MAX_MACADDRESS_NUM);
	 
	if(NULL != db_name && strlen(db_name) > 0){ //如果数据库已经存在系统名称，则用数据库的名称
		name = zbx_strdup(NULL,db_name);
	}else{
		name = zbx_strdup(NULL,sysname);;
	}
	name_esc = zbx_db_dyn_escape_field("hosts", "name", name);
	// 大写的名称, 前端查找机器名称使用
	zbx_strupper(name);
	name_upper_esc = zbx_db_dyn_escape_field("hosts", "name_upper", name);
	
	host_esc = zbx_db_dyn_escape_field("hosts", "host", ifphysaddress);
	ifphysaddresses_esc = zbx_db_dyn_escape_field("hosts", "ifphysaddresses", ifphysaddresses);
	description_esc = zbx_db_dyn_escape_field("hosts", "description", "");
	create_time = update_time = (int)time(NULL);

	if(NULL != sysdesc)
	{
		//系统名称
		discovery_parsing_value_os(sysdesc, &os);
	}

	if (!host->hostid)
	{
		host->hostid = zbx_db_get_maxid("hosts");
		zbx_db_execute("insert into hosts (hostid,name,host,ifphysaddresses,status,flags,description,"
				"create_time,name_upper,templateid,groupid,hstgrpid,device_type,uuid)"
				" values (" ZBX_FS_UI64 ",'%s','%s','%s',%d,%d,'%s',%d,'%s',%d,%d,%d,%d,'%s')",
				host->hostid, name_esc, host_esc, ifphysaddresses_esc, HOST_STATUS_UNREACHABLE, 0, description_esc, 
				create_time,name_upper_esc,templateid,groupid,hstgrpid,device_type,uuid);
	}
	else
	{
		zbx_db_execute("update hosts set name='%s',host='%s',ifphysaddresses='%s',"
				"update_time=%d,name_upper='%s',templateid=%d,groupid=%d,hstgrpid=%d,device_type=%d,uuid='%s' where hostid=" ZBX_FS_UI64,
				name_esc,host_esc,ifphysaddresses_esc,update_time,name_upper_esc,templateid,groupid,hstgrpid,device_type,uuid,host->hostid);
	}
	 
	zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s, status=%d, hoststatus:%d, hostid:%d", __func__, status, host->status, host->hostid);
	 
	int dunique_type = DUNIQUE_TYPE_UNKNOW;
	char *dunique = NULL;
	if(ifphysaddresses != NULL && strlen(ifphysaddresses) > 5)
	{
		dunique_type = DUNIQUE_TYPE_MACS;
		dunique = ifphysaddresses;
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
	
	if(dcheck->type == SVC_IPMI)
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s() value=[%s]",
							__func__, in_value);
		// ipmi 模板
		// templateid = IPMI_TEMPLATEID;
		templateid = 16;
		// 更新 host表的ipmi信息
		char *ipmi_username = NULL;
		char *ipmi_password = NULL;
		char *temp;
		signed char ipmi_authtype;
		unsigned char ipmi_privilege;

		discovery_parsing_value(in_value, "ipmi_username",&ipmi_username);
		discovery_parsing_value(in_value,"ipmi_password",&ipmi_password);
		discovery_parsing_value(in_value,"ipmi_privilege",&temp);
		ipmi_authtype = (signed char)zbx_atoi(temp);
		discovery_parsing_value(in_value,"ipmi_authtype",&temp);
		ipmi_privilege = (unsigned char)zbx_atoi(temp);
		
		char *escaped_ipmi_username = zbx_db_dyn_escape_field("hosts", "ipmi_username", ipmi_username);
		char *escaped_ipmi_password = zbx_db_dyn_escape_field("hosts", "ipmi_password", ipmi_password);

		char sql_query[MAX_STRING_LEN]; 
		zbx_snprintf(sql_query, sizeof(sql_query), 
					"UPDATE hosts SET ipmi_username='%s', ipmi_password='%s', ipmi_privilege=%d, ipmi_authtype=%d,templateid=%d WHERE hostid=" ZBX_FS_UI64,
					escaped_ipmi_username, escaped_ipmi_password, ipmi_privilege, ipmi_authtype,templateid, host->hostid);
		zbx_db_execute(sql_query);

		//绑定模板和设备类型
		//bind_template_to_host(host->hostid);
		update_ipmi_hostmacro(host->hostid, ipmi_username, ipmi_password);

		// 资产信息提取
		discovery_parsing_value(in_value, "chassis", &chassis);
		discovery_parsing_value(in_value, "chassis_serial", &chassis_serial);
		discovery_parsing_value(in_value, "board", &board);
		discovery_parsing_value(in_value, "board_serial", &board_serial);
		/*ipmi*/
		inventory->chassis = zbx_strdup(NULL, chassis);
		inventory->chassis_serial = zbx_strdup(NULL, chassis_serial);
		inventory->board = zbx_strdup(NULL, board);
		inventory->board_serial = zbx_strdup(NULL, board_serial);
		inventory_typeid = INVENTORY_SERVER_TYPEID;
		extract_json_field(in_value, 6, 
                   "cpu", &inventory->cpu, 
                   "memory", &inventory->memory, 
                   "disk", &inventory->disk, 
                   "network", &inventory->network, 
                   "bios", &inventory->bios, 
                   "psu", &inventory->psu);

		zbx_free(ipmi_username);
		zbx_free(ipmi_password);
		zbx_free(escaped_ipmi_password);
		zbx_free(escaped_ipmi_username);
		zbx_free(temp);
	}

	inventory->dunique_type = dunique_type;
	inventory->dunique = zbx_strdup(NULL, dunique);
	inventory->hostid = host->hostid;
	inventory->inventory_typeid = inventory_typeid;
	inventory->name = zbx_strdup(NULL, name);
	inventory->description =  zbx_strdup(NULL,sysdesc);
	inventory->physical_model =  zbx_strdup(NULL,entphysicalmodel);
	inventory->physical_serial =  zbx_strdup(NULL,entphysicalserial);
	inventory->houseid = dcheck->houseid;
	inventory->managerid = dcheck->managerid;
	inventory->os_short = zbx_strdup(NULL,os);
	inventory->manufacturer = zbx_strdup(NULL,manufacturer);
	inventory->ip = zbx_strdup(NULL, ip);

out:
	zbx_free(sysname);
	zbx_free(sysdesc);
	zbx_free(ifphysaddress);
	zbx_free(entphysicalserial);
	zbx_free(entphysicalmodel);
	zbx_free(name_esc);
	zbx_free(host_esc);
	zbx_free(ifphysaddresses_esc);
	zbx_free(description_esc);
	zbx_free(os);
	zbx_free(name);
	zbx_free(name_upper_esc);
	zbx_free(chassis);
	zbx_free(chassis_serial);
	zbx_free(board);
	zbx_free(board_serial);
	
	zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
	zbx_vector_str_destroy(&macs_his);

	zbx_vector_str_clear_ext(&macs_dis, zbx_str_free);
	zbx_vector_str_destroy(&macs_dis);
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
	return ret;
}


/******************************************************************************
 *                                                                            *
 * Return value: Interface type                                               *
 *                                                                            *
 * Comments: !!! Don't forget to sync the code with PHP !!!                   *
 *                                                                            *
 ******************************************************************************/
unsigned char	get_interface_type_by_dservice_type(unsigned char type)
{
	switch (type)
	{
		case SVC_AGENT:
			return INTERFACE_TYPE_AGENT;
		case SVC_SNMPv1:
		case SVC_SNMPv2c:
		case SVC_SNMPv3:
			return INTERFACE_TYPE_SNMP;
		case SVC_IPMI:
			return INTERFACE_TYPE_IPMI;
		case SVC_VMWARE:
			return INTERFACE_TYPE_VMWARE;
		default:
			return INTERFACE_TYPE_UNKNOWN;
	}
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
//todo:1111 proxy传过来的dcheck暂时用null,后续是需要更改适配的
void discovery_register_interface(const DB_HOST *host, DB_INTERFACE *interface, const char *value, 
	const char *ip, const char *dns, int port, zbx_uint64_t dcheckid, const DB_DCHECK *dcheck)
{
	DB_RESULT	result;
	DB_ROW		row;
	int main = 1, interfaceid = -1; //此默认值不能修改，否则会导致程序逻辑出错
	char		*ip_esc, *dns_esc;

	ip_esc = zbx_db_dyn_escape_field("interface", "ip", ip);
	dns_esc = zbx_db_dyn_escape_field("interface", "dns", dns);

	//todo:1111 就用ip和端口来确定接口的唯一性 在监控的时候需要判断通过ip和端口返回的mac地址是否和数据库一致如果不一致 说明ip或者端口变了 这个接口需要废弃(如果接口数为0了 重新扫描？)
	result = zbx_db_select("select interfaceid,main,type,ip,port from interface"
			" where hostid=" ZBX_FS_UI64,
			host->hostid);
	
	int type = (NULL==dcheck ? INTERFACE_TYPE_UNKNOWN : get_interface_type_by_dservice_type(dcheck->type));

	while (NULL != (row = zbx_db_fetch(result)))
	{
		int db_interfaceid = atoi(row[0]);
		int db_main = atoi(row[1]);
		int db_type = atoi(row[2]);
		int	*db_ip = row[3];
		int db_port = -1;
		if(row[4] != NULL)
		{
			db_port = atoi(row[4]);
		}

		// main 是定义接口是否是默认接口的字段，
		//1:默认接口，默认接口意思是hostid和type都是第一次加入的接口，一台主机中同个type类型只有一个； 0：非默认接口,hostid和type 在表中存在过
		if(db_type == type && 1 == db_main) //如果同个主机中有相同类型，而且主机main也是1，说明已经有默认接口了，此次增加的接口就为非默认接口
		{
			main = 0;
		}

		// 如果hostid, type, ip, port 都一样，说明要更新
		if(db_type == type && 0 == zbx_strcmp_null(ip_esc, db_ip) && port == db_port)
		{
			interfaceid = db_interfaceid;
		}
	}

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() hostid:%d ip:%s port:%d,type:%d,interfaceid:%d,main:%d", 
		__func__, host->hostid, ip_esc, port, type, interfaceid, main);
	
	int credentialid = dcheck->credentialid;
	if (interfaceid == -1)
	{
		interface->interfaceid = zbx_db_get_maxid("interface");
		zbx_db_execute("insert into interface (interfaceid,hostid,ip,dns,port,available,type,main,credentialid)"
				" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ",'%s','%s','%d', %d, %d, %d, %d)",
				interface->interfaceid, host->hostid, ip_esc, dns_esc, port, interface->available, type, main, credentialid);
	}
	else
	{
		interface->interfaceid = interfaceid;
		zbx_db_execute("update interface set hostid="ZBX_FS_UI64",ip='%s',dns='%s',port='%d', type=%d,main=%d,credentialid=%d"
		" where interfaceid="ZBX_FS_UI64,
		host->hostid,ip_esc,dns_esc,port,type,main,credentialid, interfaceid);
	}
	zbx_db_free_result(result);

	if (INTERFACE_TYPE_SNMP==type)
		discovery_register_interface_snmp(interface->interfaceid, dcheck);

	
	zbx_free(ip_esc);
	zbx_free(dns_esc);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}


static char * get_str_inventory_field(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 0)
		return old;
	else
		return zbx_get_db_escape_string(new);
}

static int get_int_inventory_field(int old, int new)
{
	if(new <= 0)
		return old;
	else
		return new;
}

static char* update_inventory_cpu(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return new;
	
	char cpu_num_old[16],mf_old[256],name_old[256];
	memset(mf_old, 0, sizeof(mf_old));
	memset(name_old, 0, sizeof(name_old));
	struct zbx_json_parse jp_old;
	if (SUCCEED == zbx_json_open(old, &jp_old))
	{
		zbx_json_value_by_name(&jp_old, "cpu_num", cpu_num_old, sizeof(cpu_num_old), NULL);
		zbx_json_value_by_name(&jp_old, "mf", mf_old, sizeof(mf_old), NULL);
		zbx_json_value_by_name(&jp_old, "name", name_old, sizeof(name_old), NULL);
	}

	struct zbx_json_parse jp_new;
	char cpu_num_new[16],mf_new[256],name_new[256];
	memset(mf_new, 0, sizeof(mf_new));
	memset(name_new, 0, sizeof(name_new));
	if (SUCCEED == zbx_json_open(new, &jp_new))
	{
		zbx_json_value_by_name(&jp_new, "cpu_num", cpu_num_new, sizeof(cpu_num_new), NULL);
		zbx_json_value_by_name(&jp_new, "mf", mf_new, sizeof(mf_new), NULL);
		zbx_json_value_by_name(&jp_new, "name", name_new, sizeof(name_new), NULL);
	}

	struct zbx_json j;
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);

	int cpu_num = zbx_atoi(get_str_inventory_field(cpu_num_old, cpu_num_new));
	if(cpu_num > 0) zbx_json_addint64(&j, "cpu_num", cpu_num);

	char *mf = get_str_inventory_field(mf_old, mf_new);
	if(NULL != mf && strlen(mf) > 0) zbx_json_addstring(&j, "mf", mf, ZBX_JSON_TYPE_STRING);
	
	char *name = get_str_inventory_field(name_old, name_new);
	if(NULL != name && strlen(name) > 0) zbx_json_addstring(&j, "name", name, ZBX_JSON_TYPE_STRING);

	zbx_json_close(&j);
    //char *json = strdup(j.buffer);
	char *json = zbx_db_dyn_escape_string_basic(j.buffer, ZBX_SIZE_T_MAX, ZBX_SIZE_T_MAX, ESCAPE_SEQUENCE_ON);
	zbx_json_free(&j);
	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	
	return json;
}


static char* update_inventory_bios(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return new;

	char mf_old[256],model_old[256],version_old[256];
	memset(mf_old, 0, sizeof(mf_old));
	memset(model_old, 0, sizeof(model_old));
	memset(version_old, 0, sizeof(version_old));
	struct zbx_json_parse jp_old;
	if (SUCCEED == zbx_json_open(old, &jp_old))
	{
		zbx_json_value_by_name(&jp_old, "mf", mf_old, sizeof(mf_old), NULL);
		zbx_json_value_by_name(&jp_old, "model", model_old, sizeof(model_old), NULL);
		zbx_json_value_by_name(&jp_old, "version", version_old, sizeof(version_old), NULL);
	}
	//zbx_json_close(&jp_old);

	struct zbx_json_parse jp_new;
	char mf_new[256],model_new[256],version_new[256];
	memset(mf_new, 0, sizeof(mf_new));
	memset(model_new, 0, sizeof(model_new));
	memset(version_new, 0, sizeof(version_new));
	if (SUCCEED == zbx_json_open(new, &jp_new))
	{
		zbx_json_value_by_name(&jp_new, "mf", mf_new, sizeof(mf_new), NULL);
		zbx_json_value_by_name(&jp_new, "model", model_new, sizeof(model_new), NULL);
		zbx_json_value_by_name(&jp_new, "version", version_new, sizeof(version_new), NULL);
	}
	//zbx_json_close(&jp_new);

	struct zbx_json j;
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);

	char *mf = get_str_inventory_field(mf_old, mf_new);
	if(NULL != mf && strlen(mf) > 0) zbx_json_addint64(&j, "mf", mf);

	char *model = get_str_inventory_field(model_old, model_new);
	if(NULL != model && strlen(model) > 0) zbx_json_addstring(&j, "model", model, ZBX_JSON_TYPE_STRING);

	char *version = get_str_inventory_field(version_old, version_new);
	if(NULL != version && strlen(version) > 0) zbx_json_addstring(&j, "version", version, ZBX_JSON_TYPE_STRING);
	
	zbx_json_close(&j);
    //char *json = strdup(j.buffer);
	char *json = zbx_db_dyn_escape_string_basic(j.buffer, ZBX_SIZE_T_MAX, ZBX_SIZE_T_MAX, ESCAPE_SEQUENCE_ON);
	
    zbx_json_free(&j);

	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	return json;
}

/**
 * 内存，json数据格式
 * {
	"capacity": "32G", //内存总容量
	"memory":[{
		"mf":"Micron",  //内存厂商
		"model":"镁光16G",  //内存型号
		"serial":"0000000",  //内存序列号
		"capacity": "16 G" //内存容量
		}
	  ]
	}
*/
static char* update_inventory_memory(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return new;

	struct zbx_json j;
	struct zbx_json_parse jp_old,jp_new;
	struct zbx_json_parse jp_memory_old,jp_memory_new;
	int result_old = zbx_json_open(old, &jp_old);
	int result_new = zbx_json_open(new, &jp_new);
	
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	char t_capacity_old[256],t_capacity_new[256];
	char mf_new[256],model_new[256],serial_new[256],capacity_new[256];


	if (SUCCEED == result_old && SUCCEED == result_new)
	{
		memset(t_capacity_old, 0, sizeof(t_capacity_old));
		memset(t_capacity_new, 0, sizeof(t_capacity_new));
		zbx_json_value_by_name(&jp_old, "capacity", t_capacity_old, sizeof(t_capacity_old), NULL);
		zbx_json_value_by_name(&jp_new, "capacity", t_capacity_new, sizeof(t_capacity_new), NULL);

		char *capacity = get_str_inventory_field(t_capacity_old, t_capacity_new);
		if(NULL != capacity && strlen(capacity) > 0) zbx_json_addstring(&j, "capacity", capacity, ZBX_JSON_TYPE_STRING);

		int is_used_new = 0;
		const char *p = NULL;
		// 如果有新的对象有值，则用新的对象值
		if (SUCCEED == zbx_json_brackets_by_name(&jp_new, "memory", &jp_memory_new)
			&& zbx_json_count(&jp_memory_new) > 0)
		{
			is_used_new = 1;
			p = zbx_json_next(&jp_memory_new, p);
		}
		// 否则则用数据库对象值
		else if (SUCCEED == zbx_json_brackets_by_name(&jp_old, "memory", &jp_memory_old)
			&& zbx_json_count(&jp_memory_old) > 0)
		{
			p = zbx_json_next(&jp_memory_old, p);
		}

		zbx_json_addarray(&j, "memory");
		while (NULL != p)
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				zbx_json_addobject(&j, NULL);
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "mf", mf_new, sizeof(mf_new), NULL))
				{
					zbx_json_addstring(&j, "mf", mf_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "model", model_new, sizeof(model_new), NULL))
				{
					zbx_json_addstring(&j, "model", model_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "serial", serial_new, sizeof(serial_new), NULL))
				{
					zbx_json_addstring(&j, "serial", serial_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "capacity", capacity_new, sizeof(capacity_new), NULL))
				{
					zbx_json_addstring(&j, "capacity", capacity_new, ZBX_JSON_TYPE_STRING);
				}
			}
			if(is_used_new)
				p = zbx_json_next(&jp_memory_new, p);
			else
				p = zbx_json_next(&jp_memory_old, p);
		}

	} 
	zbx_json_close(&j);
    //char *json = strdup(j.buffer);
	char *json = zbx_db_dyn_escape_string_basic(j.buffer, ZBX_SIZE_T_MAX, ZBX_SIZE_T_MAX, ESCAPE_SEQUENCE_ON);
	
    zbx_json_free(&j);

	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	return json;
}

/**
 * 磁盘，json数据格式
 * {
	"capacity": "32G", //磁盘总容量
	"disk":[{
		"name":"镁光MTFDKBA512TFH",  //磁盘名称
		"model":"Micron MTFDKABA512TFH",  //磁盘型号
		"serial":"5WBXT0C4DAU2EM",  //磁盘序列号
		"capacity": "512 G"  //磁盘容量
		}
	]
	}
*/
static char* update_inventory_disk(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return new;
	struct zbx_json j;
	struct zbx_json_parse jp_old,jp_new;
	struct zbx_json_parse jp_disk_old,jp_disk_new;
	int result_old = zbx_json_open(old, &jp_old);
	int result_new = zbx_json_open(new, &jp_new);

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	char t_capacity_old[256],t_capacity_new[256];
	char name_new[256],model_new[256],serial_new[256],capacity_new[256];
	if (SUCCEED == result_old && SUCCEED == result_new)
	{
		memset(t_capacity_old, 0, sizeof(t_capacity_old));
		memset(t_capacity_new, 0, sizeof(t_capacity_new));
		zbx_json_value_by_name(&jp_old, "capacity", t_capacity_old, sizeof(t_capacity_old), NULL);
		zbx_json_value_by_name(&jp_new, "capacity", t_capacity_new, sizeof(t_capacity_new), NULL);

		char *capacity = get_str_inventory_field(t_capacity_old, t_capacity_new);
		if(NULL != capacity && strlen(capacity) > 0) zbx_json_addstring(&j, "capacity", capacity, ZBX_JSON_TYPE_STRING);

		int is_used_new = 0;
		const char *p = NULL;
		// 如果有新的对象有值，则用新的对象值
		if (SUCCEED == zbx_json_brackets_by_name(&jp_new, "disk", &jp_disk_new)
			&& zbx_json_count(&jp_disk_new) > 0)
		{
			is_used_new = 1;
			p = zbx_json_next(&jp_disk_new, p);
		}
		// 否则则用数据库对象值
		else if (SUCCEED == zbx_json_brackets_by_name(&jp_old, "disk", &jp_disk_old)
			&& zbx_json_count(&jp_disk_old) > 0)
		{
			p = zbx_json_next(&jp_disk_old, p);
		}
		zbx_json_addarray(&j, "disk");
		while (NULL != p)
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				zbx_json_addobject(&j, NULL);

				if (SUCCEED == zbx_json_value_by_name(&obj_j, "name", name_new, sizeof(name_new), NULL))
				{
					zbx_json_addstring(&j, "name", name_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "model", model_new, sizeof(model_new), NULL))
				{
					zbx_json_addstring(&j, "model", model_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "serial", serial_new, sizeof(serial_new), NULL))
				{
					zbx_json_addstring(&j, "serial", serial_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "capacity", capacity_new, sizeof(capacity_new), NULL))
				{
					zbx_json_addstring(&j, "capacity", capacity_new, ZBX_JSON_TYPE_STRING);
				}
			}
			if(is_used_new)
				p = zbx_json_next(&jp_disk_new, p);
			else
				p = zbx_json_next(&jp_disk_old, p);
		}

	} 
	zbx_json_close(&j);
    //char *json = strdup(j.buffer);
	char *json = zbx_db_dyn_escape_string_basic(j.buffer, ZBX_SIZE_T_MAX, ZBX_SIZE_T_MAX, ESCAPE_SEQUENCE_ON);
	
    zbx_json_free(&j);

	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	return json;
}


/**
 * 网络，json数据格式
 * {
	"port_num": 48,   //端口数量
	"ethernet_num": 2,  //网卡数量
	"ethernet": [{
	"name": "HPE Ethernet 1Gb 4-port 331i Adapter - NIC",  //网卡名称(不是端口名称)
	"netspeed":"1G"     //传输速率
	},
	{
	"name": "HPE Ethernet 2Gb 8-port 689 Adapter - NIC"
	}
	]
	}
*/
static char* update_inventory_network(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return new;

	struct zbx_json j;
	struct zbx_json_parse jp_old,jp_new;
	struct zbx_json_parse jp_network_old,jp_network_new;
	int result_old = zbx_json_open(old, &jp_old);
	int result_new = zbx_json_open(new, &jp_new);

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	char port_num_old[32],port_num_new[32];
	char ethernet_num_old[32],ethernet_num_new[32];
	char name_new[256],netspeed_new[256];
	if (SUCCEED == result_old && SUCCEED == result_new)
	{
		memset(port_num_old, 0, sizeof(port_num_old));
		memset(port_num_new, 0, sizeof(port_num_new));
		zbx_json_value_by_name(&jp_old, "port_num", port_num_old, sizeof(port_num_old), NULL);
		zbx_json_value_by_name(&jp_new, "port_num", port_num_new, sizeof(port_num_new), NULL);
		int port_num = zbx_atoi(get_str_inventory_field(port_num_old, port_num_new));
		if(port_num > 0) zbx_json_addint64(&j, "port_num", port_num);
		
		memset(ethernet_num_old, 0, sizeof(ethernet_num_old));
		memset(ethernet_num_new, 0, sizeof(ethernet_num_new));
		zbx_json_value_by_name(&jp_old, "ethernet_num", ethernet_num_old, sizeof(ethernet_num_old), NULL);
		zbx_json_value_by_name(&jp_new, "ethernet_num", ethernet_num_new, sizeof(ethernet_num_new), NULL);
		int ethernet_num = zbx_atoi(get_str_inventory_field(ethernet_num_old, ethernet_num_new));
		if(ethernet_num > 0) zbx_json_addint64(&j, "ethernet_num", ethernet_num);
		
		int is_used_new = 0;
		const char *p = NULL;

		// 如果有新的对象有值，则用新的对象值
		if (SUCCEED == zbx_json_brackets_by_name(&jp_new, "ethernet", &jp_network_new)
			&& zbx_json_count(&jp_network_new) > 0)
		{
			is_used_new = 1;
			p = zbx_json_next(&jp_network_new, p);
		}
		// 否则则用数据库对象值
		else if (SUCCEED == zbx_json_brackets_by_name(&jp_old, "ethernet", &jp_network_old)
			&& zbx_json_count(&jp_network_old) > 0)
		{
			p = zbx_json_next(&jp_network_old, p);
		}

		zbx_json_addarray(&j, "ethernet");
		while (NULL != p)
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				zbx_json_addobject(&j, NULL);

				if (SUCCEED == zbx_json_value_by_name(&obj_j, "name", name_new, sizeof(name_new), NULL))
				{
					zbx_json_addstring(&j, "name", name_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "netspeed", netspeed_new, sizeof(netspeed_new), NULL))
				{
					zbx_json_addstring(&j, "netspeed", netspeed_new, ZBX_JSON_TYPE_STRING);
				}
			}
			if(is_used_new)
				p = zbx_json_next(&jp_network_new, p);
			else
				p = zbx_json_next(&jp_network_old, p);
		}
		
	} 
	zbx_json_close(&j);
    //char *json = strdup(j.buffer);
	char *json = zbx_db_dyn_escape_string_basic(j.buffer, ZBX_SIZE_T_MAX, ZBX_SIZE_T_MAX, ESCAPE_SEQUENCE_ON);
	
    zbx_json_free(&j);

	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	return json;
}

/**
 * 电源信息，json格式定义:
 * {
	"psu_num": 2, //电源数量
	"mf":"DELTA",  //电源厂家
	"model":"865414-B21",  //电源型号
	"version":"1.00",  //电源版本
	"serial":"5WBXT0C4DAU2EM",  //电源序列号
	"max_power": 800,  //电源最大功率
	}
*/
static char* update_inventory_psu(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return new;

	char psu_num_old[16],mf_old[256],name_old[256],version_old[256],serial_old[256],max_power_old[256];
	memset(psu_num_old, 0, sizeof(psu_num_old));
	memset(mf_old, 0, sizeof(mf_old));
	memset(name_old, 0, sizeof(name_old));
	memset(version_old, 0, sizeof(version_old));
	memset(serial_old, 0, sizeof(serial_old));
	memset(max_power_old, 0, sizeof(max_power_old));

	struct zbx_json_parse jp_old;
	if (SUCCEED == zbx_json_open(old, &jp_old))
	{
		zbx_json_value_by_name(&jp_old, "psu_num", psu_num_old, sizeof(psu_num_old), NULL);
		zbx_json_value_by_name(&jp_old, "mf", mf_old, sizeof(mf_old), NULL);
		zbx_json_value_by_name(&jp_old, "name", name_old, sizeof(name_old), NULL);
		zbx_json_value_by_name(&jp_old, "version", version_old, sizeof(version_old), NULL);
		zbx_json_value_by_name(&jp_old, "serial", serial_old, sizeof(serial_old), NULL);
		zbx_json_value_by_name(&jp_old, "max_power", max_power_old, sizeof(max_power_old), NULL);
	}

	struct zbx_json_parse jp_new;
	char psu_num_new[16],mf_new[256],name_new[256],version_new[256],serial_new[256],max_power_new[256];
	memset(psu_num_new, 0, sizeof(psu_num_new));
	memset(mf_new, 0, sizeof(mf_new));
	memset(name_new, 0, sizeof(name_new));
	memset(version_new, 0, sizeof(version_new));
	memset(serial_new, 0, sizeof(serial_new));
	memset(max_power_new, 0, sizeof(max_power_new));
	if (SUCCEED == zbx_json_open(new, &jp_new))
	{
		zbx_json_value_by_name(&jp_new, "psu_num", psu_num_new, sizeof(psu_num_new), NULL);
		zbx_json_value_by_name(&jp_new, "mf", mf_new, sizeof(mf_new), NULL);
		zbx_json_value_by_name(&jp_new, "name", name_new, sizeof(name_new), NULL);
		zbx_json_value_by_name(&jp_new, "version", version_new, sizeof(version_new), NULL);
		zbx_json_value_by_name(&jp_new, "serial", serial_new, sizeof(serial_new), NULL);
		zbx_json_value_by_name(&jp_new, "max_power", max_power_new, sizeof(max_power_new), NULL);
	}

	struct zbx_json j;
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	int psu_num = zbx_atoi(get_str_inventory_field(psu_num_old, psu_num_new));
	if(psu_num > 0) zbx_json_addint64(&j, "psu_num", psu_num);
	char *mf = get_str_inventory_field(mf_old, mf_new);
	if(NULL != mf && strlen(mf) > 0) zbx_json_addstring(&j, "mf", mf, ZBX_JSON_TYPE_STRING);

	char *name = get_str_inventory_field(name_old, name_new);
	if(NULL != name && strlen(name) > 0) zbx_json_addstring(&j, "name", name, ZBX_JSON_TYPE_STRING);

	char *version = get_str_inventory_field(version_old, version_new);
	if(NULL != version && strlen(version) > 0) zbx_json_addstring(&j, "version", version, ZBX_JSON_TYPE_STRING);
	
	char *serial = get_str_inventory_field(serial_old, serial_new);
	if(NULL != serial && strlen(serial) > 0) zbx_json_addstring(&j, "serial", serial, ZBX_JSON_TYPE_STRING);
	
	char *max_power = get_str_inventory_field(max_power_old, max_power_new);
	if(NULL != max_power && strlen(max_power) > 0) zbx_json_addstring(&j, "max_power", max_power, ZBX_JSON_TYPE_STRING);

	zbx_json_close(&j);
    //char *json = strdup(j.buffer);
	char *json = zbx_db_dyn_escape_string_basic(j.buffer, ZBX_SIZE_T_MAX, ZBX_SIZE_T_MAX, ESCAPE_SEQUENCE_ON);
	
    zbx_json_free(&j);

	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	return json;
}



/**
 * 资产信息插入或更新
*/
void discovery_register_host_inventory(DB_HOST_INVENTORY *inventory)
{
	DB_RESULT result;
	DB_ROW row;
	
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	int is_find_inventory = 0, is_insert = 0;
	char *unique,*manufacturer;
	char *physical_model,*physical_serial,*chassis,*chassis_serial,*board,*board_serial;
	char *os_short,*description,*ip,*name,*cpu,*memory,*disk,*network,*bios,*psu;
	int inventory_mode,hostid,houseid,inventory_typeid,managerid,hostgroupid,groupid;
	int create_time, update_time;
  
	int inventory_id = -1;
	int dunique_type = inventory->dunique_type;
	char *dunique = inventory->dunique;
	inventory_mode = -1;  // -1 - (默认) 关闭;0 - 手动;1 - 自动.
	// 根据mac地址找到对应的资产
	if (DUNIQUE_TYPE_MACS == inventory->dunique_type && strlen(inventory->dunique) > 0)
	{
		zbx_vector_str_t	macs_his; 
		zbx_vector_str_create(&macs_his); 
		zbx_vector_str_t	macs_dis; 
		zbx_vector_str_create(&macs_dis); 

		str_to_vector(&macs_dis, inventory->dunique, "/");
 
		//新发现的mac地址和主机表里面的任何一个mac地址匹配上了，说明在表里面
		result = zbx_db_select("select id, dunique from host_inventory where dunique_type = 1 ");
		while (NULL != (row = zbx_db_fetch(result)))
		{
			zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
			zbx_vector_str_clear(&macs_his);
			str_to_vector(&macs_his, row[1], "/");
			for (int i = 0; i < macs_dis.values_num; i++)
			{
				if (FAIL != zbx_vector_str_bsearch(&macs_his, macs_dis.values[i], ZBX_DEFAULT_STR_COMPARE_FUNC))
				{
					inventory_id = zbx_atoi(row[0]);
					break;
				}
			}
		}

		zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
		zbx_vector_str_destroy(&macs_his);

		zbx_vector_str_clear_ext(&macs_dis, zbx_str_free);
		zbx_vector_str_destroy(&macs_dis);

		zbx_db_free_result(result);
	} 
	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s dunique_type=%d, inventory_id=%d, dunique=%s",
		 __func__, dunique_type, inventory_id, dunique);

	if((dunique_type == DUNIQUE_TYPE_MACS && inventory_id >= 0) || 
		(dunique_type != DUNIQUE_TYPE_MACS && inventory->dunique != NULL && strlen(inventory->dunique) > 0))
	{
		char		*sql = NULL;
		size_t		sql_alloc = 512, sql_offset = 0;
		zbx_strcpy_alloc(&sql, &sql_alloc, &sql_offset,
					"select id,hostid,houseid,inventory_typeid,managerid,hostgroupid,groupid,manufacturer," \
						"physical_model,physical_serial,chassis,chassis_serial,board,board_serial," \
						"os_short,description,ip,name,cpu,memory,disk,network,bios,psu from host_inventory " );
		if(inventory_id >= 0)
			zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, 
				" where id=%d", inventory_id);
		else
			zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, 
				"  where dunique='%s'", inventory->dunique);
		
		zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s sql:'%s'", __func__, sql);
		
		result = zbx_db_select(sql); 
		while (NULL != (row = zbx_db_fetch(result)))
		{
			int i=0;
			int id  = zbx_atoi(row[i++]);
			hostid =  get_int_inventory_field(zbx_atoi(row[i++]), inventory->hostid);
			houseid =  get_int_inventory_field(zbx_atoi(row[i++]), inventory->houseid);
			inventory_typeid = get_int_inventory_field(zbx_atoi(row[i++]), inventory->inventory_typeid);
			managerid = get_int_inventory_field(zbx_atoi(row[i++]), inventory->managerid);
			hostgroupid = get_int_inventory_field(zbx_atoi(row[i++]), inventory->hostgroupid);
			groupid = get_int_inventory_field(zbx_atoi(row[i++]), inventory->groupid);
			manufacturer = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->manufacturer);
			physical_model = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->physical_model);
			physical_serial = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->physical_serial);
			chassis = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->chassis);
			chassis_serial = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->chassis_serial);
			board = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->board);
			board_serial = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->board_serial);
			os_short = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->os_short);
			description = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->description);
			ip = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->ip);
			name = get_str_inventory_field(zbx_strdup(NULL, row[i++]), inventory->name);
			
			cpu = zbx_strdup(NULL, row[i++]);
			memory = zbx_strdup(NULL, row[i++]);
			disk = zbx_strdup(NULL, row[i++]);
			network = zbx_strdup(NULL, row[i++]);
			bios = zbx_strdup(NULL, row[i++]);
			psu = zbx_strdup(NULL, row[i++]);

			cpu = update_inventory_cpu(cpu, inventory->cpu);
			memory = update_inventory_memory(memory, inventory->memory);
			disk = update_inventory_disk(disk, inventory->disk);
			network = update_inventory_network(network, inventory->network);
			bios = update_inventory_bios(bios, inventory->bios);
			psu = update_inventory_psu(psu, inventory->psu);
			update_time = (int)time(NULL);
  
			zbx_db_execute("update host_inventory set dunique_type=%d, dunique='%s', hostid=%d,houseid=%d, managerid=%d, hostgroupid=%d, inventory_typeid=%d, groupid=%d," \ 
				"manufacturer='%s',physical_model='%s', physical_serial='%s', chassis='%s', chassis_serial='%s', board='%s', board_serial='%s', " \
				"os_short='%s', description='%s', ip='%s',name='%s',cpu='%s', memory='%s', disk='%s', network='%s', bios='%s', psu='%s', update_time=%d " \
				" where id=%d ",
				dunique_type,dunique,hostid,houseid, inventory_typeid, managerid, hostgroupid, groupid,  
				manufacturer, physical_model, physical_serial, chassis, chassis_serial, board, board_serial, 
				os_short, description, ip, name, cpu, memory, disk, network, bios, psu, update_time, id);
			is_find_inventory = 1;
			break;
		}
		zbx_free(sql);
		zbx_db_free_result(result);
	}

	if(is_find_inventory == 0)
	{
		hostid =  inventory->hostid;
		houseid =  inventory->houseid;
		managerid = inventory->managerid;
		hostgroupid = inventory->hostgroupid;
		inventory_typeid = inventory->inventory_typeid;
		groupid = inventory->groupid;
		manufacturer = zbx_get_db_escape_string(inventory->manufacturer);
		physical_model = zbx_get_db_escape_string(inventory->physical_model);
		physical_serial = zbx_get_db_escape_string(inventory->physical_serial);
		chassis = zbx_get_db_escape_string(inventory->chassis);
		chassis_serial = zbx_get_db_escape_string(inventory->chassis_serial);
		board = zbx_get_db_escape_string(inventory->board);
		board_serial = zbx_get_db_escape_string(inventory->board_serial);
		os_short = zbx_get_db_escape_string(inventory->os_short);
		description = zbx_get_db_escape_string(inventory->description);
		ip = zbx_get_db_escape_string(inventory->ip);
		name = zbx_get_db_escape_string(inventory->name);
			
		cpu = zbx_get_db_escape_string(inventory->cpu);
		memory = zbx_get_db_escape_string(inventory->memory);
		disk = zbx_get_db_escape_string(inventory->disk);
		network = zbx_get_db_escape_string(inventory->network);
		bios = zbx_get_db_escape_string(inventory->bios);
		psu = zbx_get_db_escape_string(inventory->psu);


		create_time = update_time = (int)time(NULL);
		zbx_db_execute("insert into host_inventory (dunique_type,dunique,inventory_mode,hostid,houseid,inventory_typeid,managerid,hostgroupid,groupid," \
					"manufacturer,physical_model,physical_serial,chassis,chassis_serial,board,board_serial," \
 					"os_short,description,ip,name,cpu,memory,disk,network,bios,psu,update_time,create_time)" \
					   " values (%d,'%s',%d,%d,%d,%d,%d,%d,%d,"\
					             "'%s','%s','%s','%s','%s','%s','%s'," \
								 "'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%d, %d)",
					dunique_type,dunique,inventory_mode,hostid, houseid, inventory_typeid, managerid, hostgroupid, groupid,
					manufacturer, physical_model, physical_serial, chassis, chassis_serial, board, board_serial, 
					os_short, description, ip, name, cpu, memory, disk, network, bios, psu, update_time, create_time);
	}

	zbx_free(manufacturer);
	zbx_free(physical_model);
	zbx_free(physical_serial);
	zbx_free(chassis);
	zbx_free(chassis_serial);
	zbx_free(board);
	zbx_free(board_serial);
	zbx_free(os_short);
	zbx_free(description);
	zbx_free(ip);
	zbx_free(name);
	zbx_free(cpu);
	zbx_free(memory);
	zbx_free(disk);
	zbx_free(network);
	zbx_free(bios);
	zbx_free(psu);

	inventory_free(inventory);

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

			zbx_db_execute("insert into dservices (dserviceid,dhostid,dcheckid,ip,dns,port,status)"
					" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 "," ZBX_FS_UI64 ",'%s','%s',%d,%d)",
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

	if (0 != dhost->dhostid)
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
void	zbx_discovery_update_service(const zbx_db_drule *drule, zbx_uint64_t dcheckid, zbx_db_dhost *dhost,
		const char *ip, const char *dns, int port, int status, const char *value, int now, const DB_DCHECK *dcheck)
{
	DB_DSERVICE	dservice;
	DB_HOST host;
	DB_INTERFACE interface;
	DB_HOST_INVENTORY inventory;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s' dns:'%s' port:%d status:%d value:'%s'",
			__func__, ip, dns, port, status, value);

	memset(&dservice, 0, sizeof(dservice));
	memset(&host, 0, sizeof(host));
	memset(&interface, 0, sizeof(interface));
	memset(&inventory, 0, sizeof(inventory));
 
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
	if (NULL==dcheck || INTERFACE_TYPE_UNKNOWN==get_interface_type_by_dservice_type(dcheck->type))
		goto out;

	int ret = FAIL;
	//入库host
	if (0 != dservice.dserviceid)
		ret = discovery_register_host(&host, &inventory, value, ip, dns, port, status, dcheck);
	if(SUCCEED == ret)
	{
		discovery_register_interface(&host, &interface, value, ip, dns, port, dcheckid, dcheck);
		discovery_register_host_inventory(&inventory);
		
		// status 0已监控，1已关闭，2未纳管, 未纳管的设备返回给前端实时显示
		if(host.status == HOST_STATUS_UNREACHABLE)
		{
			user_discover_add_hostid(dcheck->druleid, host.hostid);
		}
	}
	

out:
	zbx_free(dservice.value);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}
