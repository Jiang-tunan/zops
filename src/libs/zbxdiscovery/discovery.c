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

typedef struct
{
	zbx_uint64_t	dserviceid;
	int		status;
	int		lastup;
	int		lastdown;
	char		*value;
}
DB_DSERVICE;

typedef struct
{
	zbx_uint64_t	hostid;
	//char		    *host;
	//int		    status;
	//int		    flags;
}
DB_HOST;

typedef struct
{
	zbx_uint64_t	interfaceid;
	zbx_uint64_t	hostid;
	//char		    *ip;
	//char		    *port;
	//unsigned char	type;
	//unsigned char	main;
	//unsigned char	useip;
}
DB_INTERFACE;

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
static char * format_mac_address(char *mac_address)
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
		zbx_vector_str_append(out, tmp);
	}
}

void vector_to_str(zbx_vector_str_t *v, char **out, const char *split)
{
	size_t	alloc = 0, offset = 0;
	zbx_strcpy_alloc(out, &alloc, &offset, "");

	for (int i = 0; i < v->values_num; i++)
	{
		zbx_strcpy_alloc(out, &alloc, &offset, v->values[i]);
		zbx_strcpy_alloc(out, &alloc, &offset, "/");
	}
}

//设备类型id 厂商id 模板id  (硬件型号->厂商id  硬件型号->设备类型id、品牌id->模板id(默认值))
void discovery_parsing_value_model(const char *entphysicalmodelname, const char *sysdesc, int dcheck_type, int *groupid, int *manufacturerid, int *templateid)
{
	char *manufacturer = NULL;

	*groupid = 0;
	*manufacturerid = 0;
	*templateid = 0;
	
	DB_RESULT	result;
	DB_ROW		row;
	result = zbx_db_select("select templateid,groupid,manufacturer from model_type where physical_model='%s'", entphysicalmodelname);
	if (NULL != (row = zbx_db_fetch(result)))
	{
		*templateid = atoi(row[0]);
		*groupid = atoi(row[1]);
		manufacturer = row[2];
	}
	zbx_db_free_result(result);
 

	if (NULL != manufacturer)  // 如果在设备型号表能找到相关厂家信息，则用设备型号表的信息
	{
		result = zbx_db_select("select manufacturerid from manufacturer where name='%s'", manufacturer);
		if (NULL != (row = zbx_db_fetch(result)))
		{
			*manufacturerid = atoi(row[0]);
		}
		zbx_db_free_result(result);
	}
	else if(NULL != sysdesc)  //否则根据snmp协议返回的系统描述找出相关的厂家id
	{	
		zbx_vector_str_t	manufacturer_names;
		zbx_vector_str_create(&manufacturer_names);

		char *saveptr, *token;
		char *sysdesc_b = zbx_strdup(NULL, sysdesc);
		for (token = strtok_r(sysdesc_b, " ", &saveptr); NULL != token; token = strtok_r(NULL, " ", &saveptr))
			zbx_vector_str_append(&manufacturer_names, zbx_strdup(NULL,token));

		char	*sql = NULL;
		size_t	sql_alloc = 0, sql_offset = 0;
		zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, "select manufacturerid, name from manufacturer where");
		zbx_db_add_str_condition_alloc(&sql, &sql_alloc, &sql_offset, "name", (const char **)manufacturer_names.values, manufacturer_names.values_num);
		result = zbx_db_select("%s", sql);
		if (NULL != (row = zbx_db_fetch(result)))
		{
			*manufacturerid=atoi(row[0]);
		}

		zbx_vector_str_clear_ext(&manufacturer_names, zbx_str_free);
		zbx_vector_str_destroy(&manufacturer_names);
		zbx_free(sysdesc_b);
		zbx_free(sql);
		zbx_db_free_result(result);
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
static void	discovery_register_host(DB_HOST *host, const char *value, const char *ip, const char *dns, int port, int status, const DB_DCHECK *dcheck)
{
	DB_RESULT	result;
	DB_ROW		row;
	char		*name_esc=NULL,*host_esc=NULL,*ifphysaddresses_esc=NULL,*description_esc=NULL,*serial_esc=NULL,*model_esc=NULL,*os_esc=NULL;
	char        *name_upper_esc=NULL;
	time_t		create_time,update_time;

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() value:%s", __func__, value);

	char *sysname=NULL;                   //资产名称
	char *sysdesc=NULL;                   //主机描述(windows/linux 品牌)
	char *ifphysaddress=NULL;             //mac地址
	char *ifphysaddresses=NULL;           //mac地址 可能有多个以/分割
	char *entphysicalserialnum=NULL;      //序列号
	char *entphysicalmodelname=NULL;      //硬件型号
	char *os=NULL;                        //os
	char *name=NULL;					  //服务器名称

	zbx_vector_str_t	macs_dis;
	zbx_vector_str_t	macs_his;
	zbx_vector_str_create(&macs_dis);
	zbx_vector_str_create(&macs_his);

	discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSNAME,&sysname);
	discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSDESC,&sysdesc);
	discovery_parsing_macs(value,&macs_dis);
	discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM,&entphysicalserialnum);
	discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME,&entphysicalmodelname);

	//如果mac地址为空 记录日志  
	if (macs_dis.values_num == 0)
	{
		user_discover_add_alarm(dcheck->druleid,ip, port);
		zabbix_log(LOG_LEVEL_ERR, "mac is null. dcheckid:%d ip:%s port:%d dns:%s", dcheck->dcheckid, ip, port, dns);
		goto out;
	}

	int groupid=0,manufacturerid=0,templateid=0;
	discovery_parsing_value_model(entphysicalmodelname, sysdesc, dcheck->type, &groupid, &manufacturerid, &templateid);

	char *db_name = NULL;
	//新发现的mac地址和主机表里面的任何一个mac地址匹配上了 把匹配上的作为host字段 且说明在表里面
	result = zbx_db_select("select hostid, ifphysaddresses, name from hosts where ifphysaddresses != '' ");
	while (NULL != (row = zbx_db_fetch(result)))
	{
		zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
		zbx_vector_str_clear(&macs_his);
		str_to_vector(&macs_his, row[1], "/");
		for (int i = 0; i < macs_dis.values_num; i++)
		{
			int index;
			if (FAIL != (index = zbx_vector_str_bsearch(&macs_his, macs_dis.values[i], ZBX_DEFAULT_STR_COMPARE_FUNC)))
			{
				db_name = row[2];
				ZBX_STR2UINT64(host->hostid, row[0]);
				ifphysaddress = zbx_dsprintf(NULL, "%s", macs_his.values[index]);
				break;
			}
		}
	}
	zbx_db_free_result(result);

	if (NULL==ifphysaddress)
		ifphysaddress = zbx_dsprintf(NULL, "%s", macs_dis.values[0]);

	vector_to_str(&macs_dis, &ifphysaddresses, "/");

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
	serial_esc = zbx_db_dyn_escape_field("hosts", "physical_serial", entphysicalserialnum);
	model_esc = zbx_db_dyn_escape_field("hosts", "physical_model", entphysicalmodelname);
	description_esc = zbx_db_dyn_escape_field("hosts", "description", "");
	create_time = update_time = (int)time(NULL);

	//系统名称
	discovery_parsing_value_os(sysdesc, &os);
	os_esc = zbx_db_dyn_escape_field("hosts", "os", os);
	
	//因为templateid字段有hostid外键关联，如果templateid没有对应hostid值，导致插入不进去的问题. 所以有值才插入templateid字段
	if(templateid > 0) 
	{ 
		if (!host->hostid)
		{
			host->hostid = zbx_db_get_maxid("hosts");
			zbx_db_execute("insert into hosts (hostid,name,host,ifphysaddresses,status,flags,description,"
					"create_time,physical_serial,physical_model,houseid,manufacturerid,os,name_upper,templateid,groupid)"
					" values (" ZBX_FS_UI64 ",'%s','%s','%s',%d,%d,'%s',%d,'%s','%s',%d,%d,'%s','%s',%d,%d)",
					host->hostid, name_esc, host_esc, ifphysaddresses_esc, HOST_STATUS_UNREACHABLE, 0, description_esc, 
					create_time,serial_esc,model_esc,dcheck->houseid,manufacturerid,os_esc,name_upper_esc,templateid,groupid);
		}
		else
		{
			zbx_db_execute("update hosts set name='%s',host='%s',ifphysaddresses='%s',physical_serial='%s',physical_model='%s',houseid=%d,"
					"update_time=%d,os='%s',name_upper='%s',templateid=%d,groupid=%d  where hostid=" ZBX_FS_UI64,
					name_esc,host_esc,ifphysaddresses_esc,serial_esc,model_esc,dcheck->houseid,
					update_time,os_esc,name_upper_esc,templateid,groupid,host->hostid);
		}
	}else{
		if (!host->hostid)
		{
			host->hostid = zbx_db_get_maxid("hosts");
			zbx_db_execute("insert into hosts (hostid,name,host,ifphysaddresses,status,flags,description,"
					"create_time,physical_serial,physical_model,houseid,manufacturerid,os,name_upper,groupid)"
					" values (" ZBX_FS_UI64 ",'%s','%s','%s',%d,%d,'%s',%d,'%s','%s',%d,%d,'%s','%s',%d)",
					host->hostid, name_esc, host_esc, ifphysaddresses_esc, HOST_STATUS_UNREACHABLE, 0, description_esc, 
					create_time,serial_esc,model_esc,dcheck->houseid,manufacturerid,os_esc,name_upper_esc,groupid);
		}
		else
		{
			zbx_db_execute("update hosts set name='%s',host='%s',ifphysaddresses='%s',physical_serial='%s',physical_model='%s',houseid=%d,"
					"update_time=%d,os='%s',name_upper='%s',groupid=%d  where hostid=" ZBX_FS_UI64,
					name_esc,host_esc,ifphysaddresses_esc,serial_esc,model_esc,dcheck->houseid,
					update_time,os_esc,name_upper_esc,groupid,host->hostid);
		}
	}
	//zbx_db_free_result(result);

	// if (templateid)
	// {
	// 	zbx_uint64_t hosttemplateid;
	// 	result = zbx_db_select("select hosttemplateid from hosts_templates where hostid="ZBX_FS_UI64" and templateid="ZBX_FS_UI64, host->hostid, templateid);
	// 	if (NULL == (row = zbx_db_fetch(result)))
	// 	{
	// 		hosttemplateid = zbx_db_get_maxid("hosts_templates");
	// 		zbx_db_execute("insert into hosts_templates (hosttemplateid,hostid,templateid,link_type)"
	// 			" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 "," ZBX_FS_UI64 ", %d)",
	// 			hosttemplateid, host->hostid, templateid, ZBX_TEMPLATE_LINK_LLD);
	// 	}
	// 	else
	// 	{
	// 		ZBX_STR2UINT64(hosttemplateid, row[0]);
	// 		zbx_db_execute("update hosts_templates set link_type=%d"
	// 		" where hosttemplateid=" ZBX_FS_UI64,
	// 		ZBX_TEMPLATE_LINK_LLD, hosttemplateid);
	// 	}
	// 	zbx_db_free_result(result);
	// }

out:
	zbx_free(sysname);
	zbx_free(sysdesc);
	zbx_free(ifphysaddress);
	zbx_free(entphysicalserialnum);
	zbx_free(entphysicalmodelname);
	zbx_free(name_esc);
	zbx_free(host_esc);
	zbx_free(ifphysaddresses_esc);
	zbx_free(serial_esc);
	zbx_free(model_esc);
	zbx_free(description_esc);
	zbx_free(os);
	zbx_free(os_esc);
	zbx_free(name);
	zbx_free(name_upper_esc);
	zbx_vector_str_clear_ext(&macs_dis, zbx_str_free);
	zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
	zbx_vector_str_destroy(&macs_dis);
	zbx_vector_str_destroy(&macs_his);
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
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
		//case SVC_IPMI:
		//	return INTERFACE_TYPE_IPMI;
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
static void	discovery_register_interface(const DB_HOST *host, DB_INTERFACE *interface, const char *value, const char *ip, const char *dns, int port, zbx_uint64_t dcheckid, const DB_DCHECK *dcheck)
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
	

	if (interfaceid == -1)
	{
		interface->interfaceid = zbx_db_get_maxid("interface");
		zbx_db_execute("insert into interface (interfaceid,hostid,ip,dns,port,type,main)"
				" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ",'%s','%s','%d', %d, %d)",
				interface->interfaceid, host->hostid, ip_esc, dns_esc, port,type,main);
	}
	else
	{
		zbx_db_execute("update interface set hostid="ZBX_FS_UI64",ip='%s',dns='%s',port='%d',type=%d,main=%d"
		" where interfaceid="ZBX_FS_UI64,
		host->hostid,ip_esc,dns_esc,port,type,main, interfaceid);
	}

	if (INTERFACE_TYPE_SNMP==type)
		discovery_register_interface_snmp(interface->interfaceid, dcheck);

	zbx_db_free_result(result);
	zbx_free(ip_esc);
	zbx_free(dns_esc);

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

	zabbix_log(LOG_LEVEL_DEBUG, "In %s() ip:'%s' dns:'%s' port:%d status:%d value:'%s'",
			__func__, ip, dns, port, status, value);

	memset(&dservice, 0, sizeof(dservice));
	memset(&host, 0, sizeof(host));
	memset(&interface, 0, sizeof(interface));

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

	//入库host
	if (0 != dservice.dserviceid)
		discovery_register_host(&host, value, ip, dns, port, status, dcheck);

	//入库host对应的接口
	if (0 != host.hostid)
		discovery_register_interface(&host, &interface, value, ip, dns, port, dcheckid, dcheck);

out:
	zbx_free(dservice.value);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}
