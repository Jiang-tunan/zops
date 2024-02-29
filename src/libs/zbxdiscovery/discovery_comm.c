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
#include "zbxserver.h"
#include "log.h"
#include "zbxmutexs.h"

zbx_mutex_t		g_dc_hosts_lock = ZBX_MUTEX_NULL;
#define LOCK_DC_HOSTS	zbx_mutex_lock(g_dc_hosts_lock)
#define UNLOCK_DC_HOSTS	zbx_mutex_unlock(g_dc_hosts_lock)


static char * __get_2str_field_free(char *old, char *new, int isfreeold, int isfeenew)
{
	char *str = NULL;
	if(new == NULL || strlen(new) <= 0){
		if(isfeenew)  // 释放new,说明old 和输出参数不同源,要重新生成
			str = zbx_strdup(NULL, old);
		else
			str = old;
	}else{
		str = zbx_get_db_escape_string(new);
	}
	if(isfreeold && str != old) zbx_free(old);
	if(isfeenew) zbx_free(new);
	return str;
}

char * get_2str_field_lfree(char *old, char *new)
{
	return __get_2str_field_free(old, new, 1, 0);
}
char * get_2str_field_lrfree(char *old, char *new)
{
	return __get_2str_field_free(old, new, 1, 1);
}
char * get_2str_field_rfree(char *old, char *new)
{
	return __get_2str_field_free(old, new, 0, 1);
}
char * get_2str_field(char *old, char *new)
{
	return __get_2str_field_free(old, new, 0, 0);
}

int get_2int_field(int old, int new)
{
	if(new <= 0)
		return old;
	else
		return new;
}


void vector_to_str(zbx_vector_str_t *v, char **out, const char *split)
{
	vector_to_str_max(v, out, split, 65535);
}

void vector_to_str_max(zbx_vector_str_t *v, char **out, const char *split, int max)
{
	if(NULL == v || v->values_num == 0){
		*out = zbx_strdup(*out, "");
		return;
	} 
	zbx_free(*out);
	size_t	alloc = 0, offset = 0;
	zbx_strcpy_alloc(out, &alloc, &offset, ""); 
	for (int i = 0; i < v->values_num && i < max; i++)
	{
		zbx_strcpy_alloc(out, &alloc, &offset, v->values[i]);
		if(i < (v->values_num-1) && i < (max-1)){
			zbx_strcpy_alloc(out, &alloc, &offset, split);
		}
	}
}


void str_to_vector(zbx_vector_str_t *out, const char *str, const char *split)
{
	if(NULL == str || 0 == strlen(str) || NULL == split) 
		return;

	char	*one=NULL, *saveptr=NULL;
	char	str_copy[MAX_STRING_LEN] = {0};
	zbx_strscpy(str_copy, str);
	 
	for (one = strtok_r(str_copy, split, &saveptr); NULL != one; one = strtok_r(NULL, split, &saveptr))
	{
		//char *tmp = zbx_dsprintf(NULL, "%s", one);
		char *tmp = zbx_strdup(NULL, one);
		//zabbix_log(LOG_LEVEL_DEBUG, "%s str=%s", __func__, tmp);
		zbx_vector_str_append(out, tmp);
	}
	 
}

/*
把mac地址标准化输出
可能的字符串:"[ens192] 00:50:56:8f:0d:e6" "50 6B 8D 8D A3 11 "
*/
char * format_mac_address(char *mac_address)
{
	//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s mac:%s\n",__func__, mac_address);
	char *formatted_mac = NULL;
	size_t	alloc = 0, offset = 0;
    int i=0, j=0, k=0, count=0;
	
	zbx_lrtrim(mac_address, ZBX_WHITESPACE);

	// 有些mac地址为大写，转为小写
	zbx_strlower(mac_address);

	char split = ':';
	if(NULL == strchr(mac_address, ':')) split = ' ';

	for (i = 0; i < zbx_strlen_utf8(mac_address); i++)
	{
        if (mac_address[i] == split)
            count++;
    }
	int need_len = 3*count+3;
	formatted_mac = zbx_realloc(formatted_mac, need_len);
	//mac地址都是最多2位加一个:的
	formatted_mac[3*count+2] = '\0';
	//从后面往前面照抄过来 遇到:不够2位就补零
    for (i = zbx_strlen_utf8(mac_address)-1, j=3*count+1; i >= 0; i--)
	{
		if (mac_address[i] != split)
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
 
	//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s formatted_mac:%s",__func__, formatted_mac);
	
	return formatted_mac;
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
		case SVC_HTTP:
		case SVC_HTTPS:
			return INTERFACE_TYPE_HTTP;
		case SVC_JMX:
			return INTERFACE_TYPE_JMX;
		case SVC_ICMPPING:
			return INTERFACE_TYPE_ICMP;
		case SVC_NUTANIX:
			return INTERFACE_TYPE_NUTANIX;
		case SVC_ODBC:
			return INTERFACE_TYPE_ODBC;
		default:
			return INTERFACE_TYPE_UNKNOWN;
	}
}

int get_values_by_device_type(int devicetype, char **softdes, int *inventory_typeid, int *templateid)
{
	switch (devicetype)
	{
	case DEVICE_TYPE_MYSQL:
		*softdes ="mysql";
		*templateid = TEMPLATEID_SOFT_MYSQL;
		*inventory_typeid = INVENTORY_TYPEID_DATABASE;
		break;
	case DEVICE_TYPE_MSSQL:
		*softdes = "mssql";
		*templateid = TEMPLATEID_SOFT_MSSQL;
		*inventory_typeid = INVENTORY_TYPEID_DATABASE;
		break;
	case DEVICE_TYPE_ORACLE:
		*softdes = "oracle";
		*templateid = TEMPLATEID_SOFT_ORACLE;
		*inventory_typeid = INVENTORY_TYPEID_DATABASE;
		break;
	case DEVICE_TYPE_APACHE:
		*softdes = "apache";
		*templateid = TEMPLATEID_SOFT_APACHE;
		*inventory_typeid = INVENTORY_TYPEID_WEBSERVER;
		break;
	case DEVICE_TYPE_TOMCAT:
		*softdes = "tomcat";
		*templateid = TEMPLATEID_SOFT_TOMCAT;
		*inventory_typeid = INVENTORY_TYPEID_WEBSERVER;
		break;
	case DEVICE_TYPE_IIS:
		*softdes = "IIS";
		*templateid = TEMPLATEID_SOFT_IIS;
		*inventory_typeid = INVENTORY_TYPEID_WEBSERVER;
		break;
	case DEVICE_TYPE_RABBITMQ_CLUSTER:
		*softdes = "rabbitmq-cluster";
		*templateid = TEMPLATEID_SOFT_RABBITMQ_CLUSTER;
		*inventory_typeid = INVENTORY_TYPEID_MIDDLEWARE;
		break;
	case DEVICE_TYPE_RABBITMQ_NODE:
		*softdes = "rabbitmq-node";
		*templateid = TEMPLATEID_SOFT_RABBITMQ_NODE;
		*inventory_typeid = INVENTORY_TYPEID_MIDDLEWARE;
		break;
	case DEVICE_TYPE_KAFKA:
		*softdes = "kafka";
		*templateid = TEMPLATEID_SOFT_KAFKA;
		*inventory_typeid = INVENTORY_TYPEID_MIDDLEWARE;
		break;
	case DEVICE_TYPE_NGINX:
		*softdes = "nginx";
		*templateid = TEMPLATEID_SOFT_NGINX;
		*inventory_typeid = INVENTORY_TYPEID_MIDDLEWARE;
		break;
	case DEVICE_TYPE_PING:
		*softdes = "ping";
		*templateid = TEMPLATEID_NETWORK_PING;
		*inventory_typeid = INVENTORY_TYPEID_NETWORKTOOLS;
		break;
	case DEVICE_TYPE_PROCESS:
		*softdes = "process";
		*templateid = TEMPLATEID_SOFT_PROCESS;
		*inventory_typeid = INVENTORY_TYPEID_SOFTWARE;
		break;
	case DEVICE_TYPE_DOCKER:
		*softdes = "docker";
		*templateid = TEMPLATEID_SOFT_DOCKER;
		*inventory_typeid = INVENTORY_TYPEID_VIRTUALIZATION;
		break;
	case DEVICE_TYPE_REDIS:
		*softdes = "REDIS";
		*templateid = TEMPLATEID_SOFT_REDIS;
		*inventory_typeid = INVENTORY_TYPEID_DATABASE;
		break;
	case DEVICE_TYPE_MEMCACHED:
		*softdes = "MEMCACHED";
		*templateid = TEMPLATEID_SOFT_MEMCACHED;
		*inventory_typeid = INVENTORY_TYPEID_DATABASE;
		break;
	default:
		return FAIL;
	}
	return SUCCEED;
}


/* 
其他主机名称和新扫描的主机名称一样，则把新扫描主机从新命名，防止grafana根据主机名称显示状态出错
重命名的主机格式为 xxx-1,xxx-2. 如：ruijie-1，ruijie-2
*/	
void host_rename(zbx_vector_ptr_t *v_hosts, int self_index, int device_type, char **host_name)
{
	if(NULL == *host_name || NULL == v_hosts) 
		return;
	int find_same_index = -1, index = -1;
	DB_HOST *host = NULL;
	char *same_name = NULL;
	char *name, *lname=NULL, *rname=NULL;
	// zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s index=%d, now_name=%s", __func__, self_index, *host_name);

	for (int i = v_hosts->values_num - 1;  i >= 0; i --)
	{
		host = v_hosts->values[i];
		// 同个设备类型不能同名(如：数据库为一个类型，服务器为一个类型)
		if(i != self_index && NULL != host->name && 
		          ((DEVICE_TYPE_HW_MAX > device_type && DEVICE_TYPE_HW_MAX > host->device_type)
				|| (DEVICE_TYPE_HW_MAX < device_type && DEVICE_TYPE_HW_MAX < host->device_type)))
		{
			 
			index = zbx_strrchr(host->name, '-', &lname, &rname);
			// zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s index=%d,isdigitstr=%d, number=%d, hostname=%s,lname=%s,rname=%s",
			// 	 __func__, index, isdigitstr(rname), zbx_atoi(rname), host->name, lname, rname);

			if(0 >= index || 0 == isdigitstr(rname) || 0 == zbx_atoi(rname)){
				name = host->name;
			}else{
				name = lname;
			}
			// 发现是否有同名，如果发现其他主机名称和新扫描的主机名称一样，则记录其他主机的名称
			if(zbx_strcasecmp(name, *host_name) == 0 || zbx_strcasecmp(host->name, *host_name) == 0)
			{
				find_same_index = i;
				same_name = host->name;
				break;
			}
			zbx_free(lname);
			zbx_free(rname);
			 
		}
	}

	if(-1 == find_same_index || NULL == same_name || strlen(same_name) == 0) {
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s don't need rename. find_index=%d, self_index=%d, now_name=%s", 
			__func__,find_same_index, self_index, *host_name);
		return;
	}
  
	int number = 0;
	// lname=NULL;  rname=NULL;
	// index = zbx_strrchr(same_name, '-', &lname, &rname);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s othername=%s,lname=%s,rname=%s",
				 __func__, same_name, lname, rname);
	// 重命名的主机格式为 xxx-1,xxx-2. 如：ruijie-1，ruijie-2
	if(index >= 0 && isdigitstr(rname)){
		number = zbx_atoi(rname) + 1;
	}else{
		number = 1;
	}

	char new_name[256];
	zbx_snprintf(new_name,sizeof(new_name),"%s-%d", lname, number);
	*host_name = zbx_strdup(*host_name, new_name);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s rename success. find_index=%d, self_index=%d, nums=%d, same_name=%s, new_name=%s", 
		__func__, find_same_index, self_index, v_hosts->values_num, same_name, *host_name);
	
	zbx_free(lname);
	zbx_free(rname);
	  
}

int	dc_compare_hosts_hostid(const void *d1, const void *d2)
{
	const DB_HOST	*ptr1 = *((const DB_HOST * const *)d1);
	const DB_HOST	*ptr2 = *((const DB_HOST * const *)d2);
	if(ptr1->hostid == ptr2->hostid)
		return 0;
	return -1;
}

int	dc_compare_hosts_devicetype_host(const void *d1, const void *d2)
{
	const DB_HOST	*ptr1 = *((const DB_HOST * const *)d1);
	const DB_HOST	*ptr2 = *((const DB_HOST * const *)d2);
	if(NULL == ptr1->host || NULL == ptr2->host) 
		return -1;
	
	if(ptr1->device_type == ptr2->device_type)
		return strcmp(ptr1->host, ptr2->host);
	return -1;
}

int	dc_compare_hosts_uuid(const void *d1, const void *d2)
{
	const DB_HOST	*ptr1 = *((const DB_HOST * const *)d1);
	const DB_HOST	*ptr2 = *((const DB_HOST * const *)d2);
	// zabbix_log(LOG_LEVEL_DEBUG,"%s uuid1=%s, uuid2=%s",  __func__, ptr1->uuid, ptr2->uuid);
	
	if(NULL == ptr1->uuid || 0 == strlen(ptr1->uuid) || NULL == ptr2->uuid )
		return -1;
	if(ptr1->device_type == ptr2->device_type)
		return strcmp(ptr1->uuid, ptr2->uuid);
	return -1;
}

int	dc_compare_hosts_mac(const void *d1, const void *d2)
{
	const DB_HOST	*ptr1 = *((const DB_HOST * const *)d1);
	const DB_HOST	*ptr2 = *((const DB_HOST * const *)d2); 

	if(NULL == ptr1->macs || NULL == ptr2->macs) 
		return -1;
	for (int i = 0; i < ptr2->macs->values_num; i++)
	{ 
		if (FAIL != (zbx_vector_str_bsearch(ptr1->macs, ptr2->macs->values[i], ZBX_DEFAULT_STR_COMPARE_FUNC))){
			return 0;
		} 
	}
	return -1;
}

int	dc_find_hosts_by_devicetype_host(int device_type, char *host)
{ 
	if(-1 == device_type ||NULL == host || 0 == strlen(host))
		return -1;
	
	int index = -1;
	DB_HOST f_host;
	f_host.device_type = device_type;
	f_host.host = host;
	if (FAIL != (index = zbx_vector_ptr_search(&g_DC_HOSTS, &f_host, dc_compare_hosts_devicetype_host)))
	{
		return index;
	} 
	return -1;
}


int	dc_find_hosts_by_hostid(int hostid)
{ 
	if(0 >= hostid)
		return -1;
	 
	DB_HOST f_host;
	f_host.hostid = hostid;
	int  index = zbx_vector_ptr_search(&g_DC_HOSTS, &f_host, dc_compare_hosts_hostid);
	zabbix_log(LOG_LEVEL_DEBUG,"%s find_index=%d, hostid=%d",  __func__, index, hostid);
	return index;
}

int	dc_find_hosts_by_mac(int device_type, zbx_vector_str_t *macs)
{ 
	if(NULL == macs || 0 == macs->values_num)
		return -1;
	
	int  index = -1;
	DB_HOST f_host;
	f_host.macs = macs;
	
	if (FAIL != (index = zbx_vector_ptr_search(&g_DC_HOSTS, &f_host, dc_compare_hosts_mac)))
	{
		DB_HOST *host = g_DC_HOSTS.values[index];
		if(host->device_type == DEVICE_TYPE_HV && device_type == DEVICE_TYPE_VM)
		{ 
			zabbix_log(LOG_LEVEL_ERR, "%s The MAC address of hv and vm is duplicated. hostid=%d", __func__, host->hostid);	 
			return NOTSUPPORTED;
		}
	}
	zabbix_log(LOG_LEVEL_DEBUG,"%s find_index=%d, nums=%d, macs=%s"
		, __func__, index, g_DC_HOSTS.values_num, macs->values[0]);
	return index;
}

int	dc_find_hosts_by_uuid(int device_type, char *uuid)
{ 
	if(0 > device_type || NULL == uuid || 0 == strlen(uuid))
		return -1;
	 
	DB_HOST f_host;
	f_host.device_type = device_type;
	f_host.uuid = uuid;
	int  index = zbx_vector_ptr_search(&g_DC_HOSTS, &f_host, dc_compare_hosts_uuid);
	zabbix_log(LOG_LEVEL_DEBUG,"%s find_index=%d, nums=%d, device_type=%d, uuid=%s", 
		 __func__, index, g_DC_HOSTS.values_num, device_type, uuid);
	return index;
}

// 只针对 DEVICE_TYPE 小于100的主机类型
int	dc_find_hosts_by_ip(int dcheck_type, char *ip)
{ 
	if(0 > dcheck_type || dcheck_type > DEVICE_TYPE_HW_MAX 
		|| NULL == ip || 0 == strlen(ip) || 0 == zbx_strcmp_null(ip, ZERO_IP_ADDRESS))
		return -1;
	
	DB_RESULT	result;
	DB_ROW		row;
	DB_HOST f_host;
	int  index = -1;
	
	char itypes[128];
	memset(itypes, 0, 128);
	zbx_snprintf(itypes, 128, "%d,%d,%d", INTERFACE_TYPE_SNMP,INTERFACE_TYPE_AGENT,INTERFACE_TYPE_IPMI);

	// 设备类型 device_type < DEVICE_TYPE_HW_MAX 为服务器/虚拟机/网络设备，可以用ip地址判断是否存在统一设备
	result = zbx_db_select("select i.hostid from interface i where i.ip = '%s' and i.type in(%s)",
			ip, itypes);
	while (NULL != (row = zbx_db_fetch(result)))
	{
		f_host.hostid = zbx_atoi(row[0]);
		index = zbx_vector_ptr_search(&g_DC_HOSTS, &f_host, dc_compare_hosts_hostid);
		break; 
	}  
	zbx_db_free_result(result);  
 
	zabbix_log(LOG_LEVEL_DEBUG,"%s find_index=%d, ip=%s",  __func__, index, ip);
	return index;
}


void db_hosts_free(DB_HOST *host)
{
	if(NULL == host) return;
	
	zbx_free(host->host);
	zbx_free(host->ifphysaddresses); 
	zbx_free(host->name); 
	zbx_free(host->uuid);
	if(NULL != host->macs){
		zbx_vector_str_clear_ext(host->macs, zbx_str_free);
		zbx_vector_str_destroy(host->macs); 
	}
	
	// zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s() end", __func__);
}

void update_discovery_hosts(DB_HOST *mhost)
{
	if(NULL == mhost || 0 == mhost->hostid) 
		return;

	int index,find_index = -1;
	DB_HOST *host = NULL, f_host;

	LOCK_DC_HOSTS;
	//根据hostid地址查询主机
	f_host.hostid = mhost->hostid;
	if (FAIL != (index = zbx_vector_ptr_search(&g_DC_HOSTS, &f_host, dc_compare_hosts_hostid)))
	{
		find_index = index;
	}
 
	if(find_index >= 0){
		host = g_DC_HOSTS.values[find_index];
	}else{
		host = (DB_HOST *)zbx_malloc(NULL, sizeof(DB_HOST));
		memset(host, 0, sizeof(DB_HOST));
	}

	host->hostid = mhost->hostid;
	//host->status = mhost->status;
	host->host = zbx_strdup(NULL, mhost->host);
	host->ifphysaddresses = zbx_strdup(NULL, mhost->ifphysaddresses);
	host->name = zbx_strdup(NULL, mhost->name);
	host->uuid = zbx_strdup(NULL, mhost->uuid);
	host->templateid = mhost->templateid;
	host->groupid = mhost->groupid;
	host->hstgrpid = mhost->hstgrpid;
	host->device_type = mhost->device_type;

	if(find_index == -1)
		zbx_vector_ptr_append(&g_DC_HOSTS, host);
	UNLOCK_DC_HOSTS;
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s success. hostid=%d,find_index=%d,hostnum=%d", 
		__func__, host->hostid, find_index, g_DC_HOSTS.values_num);
}

void destroy_discovery_hosts()
{
	LOCK_DC_HOSTS;
	zbx_vector_ptr_clear_ext(&g_DC_HOSTS, db_hosts_free);
	zbx_vector_ptr_destroy(&g_DC_HOSTS);
	UNLOCK_DC_HOSTS;
}

int update_hosts_values(int index, DB_HOST *mhost, char *ip)
{
	int ret = FAIL;
	DB_HOST *host = NULL;
	if(index >= 0 && index < g_DC_HOSTS.values_num)
	{
		host = g_DC_HOSTS.values[index];
		mhost->hostid = host->hostid;
		mhost->status = host->status;
		mhost->host = get_2str_field_rfree(host->host, mhost->host);
		mhost->ifphysaddresses = get_2str_field_rfree(host->ifphysaddresses, mhost->ifphysaddresses);
		mhost->name = get_2str_field_rfree(host->name, mhost->name);
		mhost->uuid = get_2str_field_rfree(host->uuid, mhost->uuid);
		mhost->templateid = get_2int_field(host->templateid,mhost->templateid);
		mhost->groupid = get_2int_field(host->groupid,mhost->groupid);
		mhost->hstgrpid = get_2int_field(host->hstgrpid,mhost->hstgrpid);
		mhost->device_type = get_2int_field(host->device_type,mhost->device_type);
		ret = SUCCEED;
	}
	if(NULL == mhost->name || 0 == strlen(mhost->name)) 
		mhost->name = zbx_strdup(mhost->name, ip);
	if(NULL == mhost->host || 0 == strlen(mhost->host))
		mhost->host = zbx_strdup(mhost->host, ip);
	if(NULL == mhost->uuid) 
		mhost->uuid = zbx_strdup(NULL, "");
	if(NULL == mhost->ifphysaddresses ) 
		mhost->ifphysaddresses = zbx_strdup(NULL, "");
	return ret;
}

// 获得 hosts 的数据
void init_discovery_hosts()
{
	DB_RESULT	sql_result;
	DB_ROW		row;
	int i = 0;
	LOCK_DC_HOSTS;
	if( g_DC_HOSTS.values_num == 0){
		zbx_vector_ptr_create(&g_DC_HOSTS); 
	}else{
		zbx_vector_ptr_clear_ext(&g_DC_HOSTS, db_hosts_free);
	}

	sql_result = zbx_db_select("select hostid,status,host,ifphysaddresses,name,uuid,templateid,groupid,hstgrpid,device_type " \
		"from hosts where status != 3 order by name");

	while (NULL != (row = zbx_db_fetch(sql_result)))
	{
		i = 0;
		DB_HOST *host = (DB_HOST *)zbx_malloc(NULL, sizeof(DB_HOST));
		memset(host, 0, sizeof(DB_HOST));

		host->hostid = zbx_atoi(row[i++]);
		host->status = zbx_atoi(row[i++]);
 
		host->host = zbx_strdup(NULL, row[i++]);
		host->ifphysaddresses = zbx_strdup(NULL, row[i++]);
		host->name = zbx_strdup(NULL, row[i++]);
		host->uuid = zbx_strdup(NULL, row[i++]);

		host->templateid = zbx_atoi(row[i++]);
		host->groupid = zbx_atoi(row[i++]);
		host->hstgrpid = zbx_atoi(row[i++]);
		host->device_type = zbx_atoi(row[i++]);

		if(NULL != host->ifphysaddresses && strlen(host->ifphysaddresses) > 0 && NULL == host->macs){
			host->macs = (zbx_vector_str_t *)zbx_malloc(host->macs, sizeof(zbx_vector_str_t));
			zbx_vector_str_create(host->macs);
			str_to_vector(host->macs, host->ifphysaddresses, "/");
			// zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s mac=%s", __func__, ((DB_HOST *)(v_hosts->values[i]))->macs.values[0]);
		}
		 
		zbx_vector_ptr_append(&g_DC_HOSTS, host);
		// zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, type=%d, hostid=%d, uuid=%s, hstgrpid=%d", 
		// 	__func__, host->device_type, host->hostid , host->uuid, host->hstgrpid);
	}
	UNLOCK_DC_HOSTS;
	zbx_db_free_result(sql_result);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s success. hostnum=%d", __func__, g_DC_HOSTS.values_num);
} 

int dc_find_update_hosts(DB_HOST *mhost, char *ip, int dcheck_type)
{
	int ret=FAIL, find_index = -1;
	
	LOCK_DC_HOSTS;
	//根据hostid地址查询主机
	find_index = dc_find_hosts_by_hostid(mhost->hostid);
	
	//根据MAC地址查询主机
	if(-1 == find_index){
		find_index = dc_find_hosts_by_mac(mhost->device_type, mhost->macs);
		if(NOTSUPPORTED == find_index) ret = NOTSUPPORTED;
	}

	//根据UUID查询主机
	if(-1 == find_index){
		find_index = dc_find_hosts_by_uuid(mhost->device_type, mhost->uuid);
	}

	// 上述都没有找到，则根据ip地址查找(SVC_VMWARE 扫描有"0.0.0.0"IP，要排除)
	if(-1 == find_index){
		find_index = dc_find_hosts_by_ip(dcheck_type, ip);
	} 

	if(NULL != mhost->macs && mhost->macs->values_num > 0){
		mhost->host = zbx_strdup(mhost->host, mhost->macs->values[0]);
	}

	if(NULL == mhost->name || strlen(mhost->name) == 0){
		mhost->name = zbx_strdup(mhost->name, ip);
	}
	host_rename(&g_DC_HOSTS, find_index,  mhost->device_type, &mhost->name);

	update_hosts_values(find_index, mhost, ip);
	UNLOCK_DC_HOSTS;

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s ret=%d, find_index=%d, hostid=%d, dcheck_type=%d, ip=%s, uuid=%s, name=%s", 
		__func__, ret, find_index, mhost->hostid, dcheck_type, ip, mhost->uuid, mhost->name); 
	return ret;

}

int dc_soft_find_update_hosts(DB_HOST *mhost, char *ip)
{
	LOCK_DC_HOSTS;
	int find_index = dc_find_hosts_by_devicetype_host(mhost->device_type, mhost->host);
	update_hosts_values(find_index, mhost, ip);
	host_rename(&g_DC_HOSTS, find_index, mhost->device_type, &mhost->name);
	UNLOCK_DC_HOSTS;
}
