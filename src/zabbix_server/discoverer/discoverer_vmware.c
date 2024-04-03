#include "discoverer.h"
#include "discoverer_manager.h"
#include "user_discoverer.h"
#include "discoverer_single.h"
#include "discoverer_vmware.h"
#include "discoverer_comm.h"

#include "log.h"
#include "zbxicmpping.h"
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

void wmware_free_vmware_server_ptr(vmware_server *p_server)
{
	zbx_free(p_server->dataCenterName); 
	zbx_free(p_server->clusterName); 
    zbx_free(p_server->uuid); 
	zbx_free(p_server->id); 
	zbx_free(p_server->name); 
    zbx_free(p_server->ip); 
    zbx_free(p_server->parentName); 
	zbx_free(p_server->parentType); 
	zbx_free(p_server->hvNetName); 
    zbx_free(p_server->hvUuid); 
	zbx_free(p_server->macs); 
	zbx_free(p_server->cpu); 
	zbx_free(p_server->memory);
	zbx_free(p_server->cpuMode);
	zbx_free(p_server);
}

static void vmware_recv(char **out_value, char *key, char *user, char *passwd, char *ip, int port, int maxTry)
{
	AGENT_RESULT	result;
	zbx_vector_ptr_t add_results;
	DC_ITEM		item;

	zbx_vector_ptr_create(&add_results);
	zbx_init_agent_result(&result);
 
	
	//模拟请求获取数据
	zbx_free_agent_result(&result);
	memset(&item, 0, sizeof(DC_ITEM));

	zbx_strscpy(item.key_orig, key);
	item.key = item.key_orig;

	item.interface.useip = 1;
	item.interface.addr = ip;
	item.interface.port = (unsigned short)port;
	item.username = user;
	item.password = passwd;
	item.state = 1;
	item.value_type	= ITEM_VALUE_TYPE_STR;
	int ret = 0, count = 0;
	char **pvalue;
	do{
		ret = get_value_simple(&item, &result, &add_results);
		if(SUCCEED == ret && NULL != (pvalue = ZBX_GET_TEXT_RESULT(&result)))
		{
			*out_value = zbx_strdup(NULL, *pvalue);
			break;
		}else{
			count ++;
			zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s, get_value_simple fail. key=%s,count=%d,result=%d",
				__func__, key, count, ret);
			zbx_sleep(2);
		}
	}
	while (count < maxTry);
	
	
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, key=%s, user=%s, ip=%s, port=%d, recv value=%s", 
		__func__, key, user, ip, port, *out_value);
	 
	zbx_vector_ptr_clear_ext(&add_results, (zbx_mem_free_func_t)zbx_free_agent_result_ptr);
	zbx_vector_ptr_destroy(&add_results);
	zbx_free_agent_result(&result);

}

/**
 * 获取网卡地址
 * [
	{
		"{#IFNAME}": "vmnic0",
		"{#IFDRIVER}": "igbn",
		"{#IFSPEED}": 1000,
		"{#IFDUPLEX}": "full",
		"{#IFMAC}": "0c:c4:7a:64:ea:72"
	}
	]
*/
static void vmware_get_net_data(char *checkKey, char *user, char *passwd, char *ip, int port, char *uuid, vmware_server *p_server)
{
    char key[256];

	zbx_snprintf(key, sizeof(key), "%s[https://%s/sdk,%s]", checkKey, ip, uuid);  // 填入ip地址
	//vmware.hv.net.if.discovery
    //vmware.vm.net.if.discovery
    char *value = NULL;
    vmware_recv(&value, key, user, passwd, ip, port, 2);
	if(NULL == value || strlen(value) == 0)
	{
		return;
	}

	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED;
 
	const char		*p=NULL;
	char *fmacaddr = NULL;
	char  tstr[128], cHvMac[256];
	memset(cHvMac, 0, sizeof(cHvMac));
	if (SUCCEED != zbx_json_open(value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"zbx_json_open fail");
		return;
	}
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
		{
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#IFMAC}", tstr, sizeof(tstr), NULL))
			{ 
				fmacaddr = format_mac_address(tstr);
				if (strncmp(fmacaddr, ZBX_DSERVICE_ILLEGAL_MACADDRS, ZBX_DSERVICE_ILLEGAL_MACADDRS_LEN) != 0)
				{
					strcat(cHvMac,fmacaddr);
					strcat(cHvMac,"/");
				}
				zbx_free(fmacaddr);
			} 
		}
	}
    p_server->macs = zbx_strdup(NULL, cHvMac);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, macs=%s", __func__, p_server->macs);
}

static void vmware_get_common_data(char *checkKey, char *user, char *passwd, char *ip, int port, char *uuid, vmware_server *p_server)
{
    char key[256];

	zbx_snprintf(key, sizeof(key), "%s[https://%s/sdk,%s]", checkKey, ip, uuid);  // 填入ip地址
    char *value = NULL;
    vmware_recv(&value, key, user, passwd, ip, port, 2);
	if(NULL == value || strlen(value) == 0)
	{
		return;
	}
	if(zbx_strcmp_null(checkKey,"vmware.hv.hw.cpu.model") == 0){
		p_server->cpuMode = zbx_strdup(NULL, value);
	}else if(zbx_strcmp_null(checkKey,"vmware.hv.hw.cpu.num") == 0 || zbx_strcmp_null(checkKey,"vmware.vm.cpu.num") == 0){
		p_server->cpuNum = zbx_atoi(value);
	}else if(zbx_strcmp_null(checkKey,"vmware.hv.hw.memory") == 0 || zbx_strcmp_null(checkKey,"vmware.vm.memory.size") == 0){
		p_server->totalMemory = zbx_atol(value);
	}else if(zbx_strcmp_null(checkKey,"vmware.hv.hw.vendor") == 0){
		
	} 
	 
	zbx_free(value);
}

//获取vmware扩展数据
static void discover_get_hv_extend_data(char *user, char *passwd, char *ip, int port, vmware_server *p_server)
{
	//获取mac地址
	vmware_get_net_data("vmware.hv.net.if.discovery", user, passwd, ip, port, p_server->uuid, p_server);
	vmware_get_common_data("vmware.hv.hw.cpu.model", user, passwd, ip, port, p_server->uuid, p_server);
	vmware_get_common_data("vmware.hv.hw.cpu.num", user, passwd, ip, port, p_server->uuid, p_server);
	vmware_get_common_data("vmware.hv.hw.memory", user, passwd, ip, port, p_server->uuid, p_server);
	vmware_get_common_data("vmware.hv.hw.vendor", user, passwd, ip, port, p_server->uuid, p_server);
	vmware_get_common_data("vmware.hv.hw.model", user, passwd, ip, port, p_server->uuid, p_server);
	// vmware_get_common_data("", user, passwd, ip, port, p_server->uuid, p_server);
}
static void make_inventory_json_data(vmware_server *p_server)
{
	char buf[256];
    struct zbx_json j;
	if(p_server->cpuNum > 0 || p_server->cpuMode != NULL)
	{
		zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
		if(p_server->cpuNum > 0)
			zbx_json_addint64(&j, "cpu_num", p_server->cpuNum);

		if(p_server->cpuMode != NULL)
			zbx_json_addstring(&j, "name", p_server->cpuMode, ZBX_JSON_TYPE_STRING);
		zbx_json_close(&j);
    	p_server->cpu = strdup(j.buffer);
    	zbx_json_free(&j);
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, cpu=%s", __func__, p_server->cpu);
	}
	struct zbx_json j_memory;
	if(p_server->totalMemory > 0 )
	{
		zbx_json_init(&j_memory, ZBX_JSON_STAT_BUF_LEN);
		int capacity = 0;
		if(p_server->type == DEVICE_TYPE_HV)
			capacity = p_server->totalMemory/1024/1024/1024;
		else
			capacity = p_server->totalMemory/1024;
		
		zbx_snprintf(buf, sizeof(buf),"%dG", capacity);
		zbx_json_addstring(&j_memory, "capacity", buf, ZBX_JSON_TYPE_STRING);
		zbx_json_close(&j_memory);
    	p_server->memory = strdup(j_memory.buffer);
    	zbx_json_free(&j_memory);
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, memroy=%s", __func__, p_server->memory);
	}
}
static void __parse_vmware_hv_data(char *user, char *passwd, char *ip, int port, char *hv_value, zbx_vector_ptr_t *v_vmware_servers)
{
	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED;
 
	const char		*p=NULL;
	char  tstr[128];
	
	if (SUCCEED != zbx_json_open(hv_value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s zbx_json_open fail", __func__);
		return;
	}
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
		{
			vmware_server *p_server = (vmware_server *)zbx_malloc(NULL, sizeof(vmware_server));
			memset(p_server, 0, sizeof(vmware_server));
			p_server->type = DEVICE_TYPE_HV;

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#HV.UUID}", tstr, sizeof(tstr), NULL))
			{
				p_server->uuid = zbx_strdup(NULL, tstr);
			}
			
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#HV.ID}", tstr, sizeof(tstr), NULL))
			{
				p_server->id = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#HV.NAME}", tstr, sizeof(tstr), NULL))
			{
				p_server->name = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#HV.NETNAME}", tstr, sizeof(tstr), NULL))
			{
				//p_server->hvNetName = zbx_strdup(NULL, tstr);
				if(strlen(tstr) > 0 && NULL != p_server->name)
				{
					zbx_strscat(tstr, "[");
					zbx_strscat(tstr, p_server->name);
					zbx_strscat(tstr, "]");
					p_server->name = zbx_strdup(p_server->name, tstr);
				}
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#HV.IP}", tstr, sizeof(tstr), NULL))
			{
				if(strlen(tstr) > 0)
					p_server->ip = zbx_strdup(NULL, tstr);
				else // 如果没有IP地址，给个"0.0.0.0""的IP
					p_server->ip = zbx_strdup(NULL, ZERO_IP_ADDRESS);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#DATACENTER.NAME}", tstr, sizeof(tstr), NULL))
			{
				p_server->dataCenterName = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#CLUSTER.NAME}", tstr, sizeof(tstr), NULL))
			{
				p_server->clusterName = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#PARENT.NAME}", tstr, sizeof(tstr), NULL))
			{
				p_server->parentName = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#PARENT.TYPE}", tstr, sizeof(tstr), NULL))
			{
				p_server->parentType = zbx_strdup(NULL, tstr);
			}
			
			zbx_vector_ptr_append(v_vmware_servers, p_server);
		}
	}
}

//获取vmware扩展数据
static void discover_get_vm_extend_data(char *user, char *passwd, char *ip, int port, vmware_server *p_server)
{
	//获取mac地址
    vmware_get_net_data("vmware.vm.net.if.discovery", user, passwd, ip, port, p_server->uuid, p_server);
	vmware_get_common_data("vmware.vm.cpu.num", user, passwd, ip, port, p_server->uuid, p_server);
	vmware_get_common_data("vmware.vm.memory.size", user, passwd, ip, port, p_server->uuid, p_server);
		
}

static void __parse_vmware_vm_data(char *user, char *passwd, char *ip, int port, char *hv_value, zbx_vector_ptr_t *v_vmware_servers)
{
	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED;
 
	const char		*p=NULL;
	char  tstr[128];
	
	if (SUCCEED != zbx_json_open(hv_value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"zbx_json_open fail");
		return;
	}
	//遍历vmware.vm.discovery返回的json
	while (NULL != (p = zbx_json_next(&jp, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
		{
			vmware_server *p_server = (vmware_server *)zbx_malloc(NULL, sizeof(vmware_server));
			memset(p_server, 0, sizeof(vmware_server));
			p_server->type = DEVICE_TYPE_VM;

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#VM.UUID}", tstr, sizeof(tstr), NULL))
			{
				p_server->uuid = zbx_strdup(NULL, tstr);
			}
			
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#VM.ID}", tstr, sizeof(tstr), NULL))
			{
				p_server->id = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#VM.NAME}", tstr, sizeof(tstr), NULL))
			{
				p_server->name = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#HV.UUID}", tstr, sizeof(tstr), NULL))
			{
				p_server->hvUuid = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#VM.IP}", tstr, sizeof(tstr), NULL))
			{
				if(strlen(tstr) > 0)
					p_server->ip = zbx_strdup(NULL, tstr);
				else // 虚拟机可能没有IP地址，给个"0.0.0.0""的IP
					p_server->ip = zbx_strdup(NULL, ZERO_IP_ADDRESS);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#DATACENTER.NAME}", tstr, sizeof(tstr), NULL))
			{
				p_server->dataCenterName = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "{#CLUSTER.NAME}", tstr, sizeof(tstr), NULL))
			{
				p_server->clusterName = zbx_strdup(NULL, tstr);
			}

			zbx_vector_ptr_append(v_vmware_servers, p_server);
		}
	}
}

// 返回vc_groupid
static int discover_vmware_dc_or_cluster(int type, char *key, char *user, char *passwd, char *ip, int port, int top_groupid)
{
	DB_RESULT	sql_result;
	DB_ROW		row;

	zbx_vector_ptr_t v_uuids;
	zbx_vector_ptr_create(&v_uuids);

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, type=%d, key=%s, user=%s", __func__, type, key, user);

	// 数据中心2，集群3
	sql_result = zbx_db_select("select uuid from hstgrp where type = %d or type = %d", type, HSTGRP_TYPE_VC);
	while (NULL != (row = zbx_db_fetch(sql_result)))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s append uuid=%s",  __func__, row[0]);
		zbx_vector_str_append(&v_uuids,zbx_strdup(NULL, row[0]));
	}
	zbx_db_free_result(sql_result);

	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED;
 
	char *value = NULL;
	vmware_recv(&value, key, user, passwd, ip, port, 3);
	if(NULL == value || strlen(value) == 0)
	{
		return;
	}
	
	int fgroupid = -1;
	const char	*p=NULL;
	char  uuid[128];
	char  name[256];
	if (SUCCEED != zbx_json_open(value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"zbx_json_open fail");
		return;
	}
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
		{
			memset(uuid, 0, sizeof(uuid));
			memset(name, 0, sizeof(name));
			
			// 数据中心2，集群3
			switch (type)
			{
				case HSTGRP_TYPE_DATACENTER:  // 数据中心2
					zbx_json_value_by_name(&jp_params, "{#DATACENTERID}", uuid, sizeof(uuid), NULL);
					zbx_json_value_by_name(&jp_params, "{#DATACENTER}", name, sizeof(name), NULL);
					break;
				case HSTGRP_TYPE_CLUSTER:  // 集群3
					zbx_json_value_by_name(&jp_params, "{#CLUSTER.ID}", uuid, sizeof(uuid), NULL);
					zbx_json_value_by_name(&jp_params, "{#CLUSTER.NAME}", name, sizeof(name), NULL);
					break;
				default:
					break;
			}
			zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, update vmware_dc_or_cluster, type=%d, uuid=%s, name=%s", __func__, type, uuid, name);
			if(strlen(uuid) > 0 && strlen(name) > 0)
			{
				//最顶层的groupid 默认为"3"-服务器, 如果key包括 dc 或 cluster 扫描，说明是vCenter扫描，要增加vc层。
				if(HSTGRP_GROUPID_SERVER == top_groupid) top_groupid = get_discover_vc_groupid(HSTGRP_TYPE_VC, ip, DEFAULT_NOPROXY_HOSTID);
				// 数据中心上层是VC
				if(HSTGRP_TYPE_DATACENTER == type) fgroupid = top_groupid;  

				if(FAIL != zbx_vector_str_search(&v_uuids, uuid, ZBX_DEFAULT_STR_COMPARE_FUNC))
				{
					zbx_db_execute("update hstgrp set name='%s' where uuid = '%s' and type = %d", name, uuid, type);
				}
				else
				{
					int groupid = zbx_db_get_maxid("hstgrp");
					zbx_db_execute("insert into hstgrp (groupid, name, uuid, type, fgroupid, fgroupids) values(%d, '%s', '%s', %d, %d, '%d')",
						groupid, name, uuid, type, fgroupid, fgroupid);
				}
			}
		} 
	}
	zbx_free(value); 
	zbx_vector_ptr_clear_ext(&v_uuids, zbx_ptr_free);
	zbx_vector_ptr_destroy(&v_uuids);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
	return top_groupid;
}

 
void vmware_register_hostmacro(int type, int hostid, char *url, char *user, char *passwd, char *hv_uuid, char *vm_uuid)
{
	DB_RESULT	result;
	DB_ROW		row;

	if(0 == hostid)  return;

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s type=%d,hostid:%d, hv_uuid=%s, vm_uuid=%s", __func__, type,hostid,hv_uuid,vm_uuid);
	
	result = zbx_db_select("select hostmacroid,hostid,macro,value,description,type,automatic from hostmacro"
			" where hostid=" ZBX_FS_UI64, hostid);
	int url_id=0,username_id=0,password_id=0,uuid_id=0,hv_uuid_id=0,vm_uuid_id=0;
	while (NULL != (row = zbx_db_fetch(result)))
	{
		char *macro = row[2];
		if (zbx_strcmp_null(macro, "{$VMWARE.URL}") == 0){
			url_id = zbx_atoi(row[0]);
		}
		else if (zbx_strcmp_null(macro, "{$VMWARE.USERNAME}") == 0){
			username_id = zbx_atoi(row[0]);
		}
		else if (zbx_strcmp_null(macro, "{$VMWARE.PASSWORD}") == 0){
			password_id = zbx_atoi(row[0]);
		}
		else if(zbx_strcmp_null(macro, "{$VMWARE.HV.UUID}") == 0){
			hv_uuid_id = zbx_atoi(row[0]);
		}
		else if(zbx_strcmp_null(macro, "{$VMWARE.VM.UUID}") == 0){
			vm_uuid_id = zbx_atoi(row[0]);
		}
	}
	zbx_db_free_result(result);

	update_hostmacro_data(url_id, hostid, "{$VMWARE.URL}", url, "");
	update_hostmacro_data(username_id, hostid, "{$VMWARE.USERNAME}", user, "");
	update_hostmacro_data(password_id, hostid, "{$VMWARE.PASSWORD}", passwd, "");
	if(type == DEVICE_TYPE_HV)
	{
		update_hostmacro_data(hv_uuid_id, hostid, "{$VMWARE.HV.UUID}", hv_uuid, "");
	}
	else
	{
		//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s type=%d,hostid:%d, hv_uuid_id=%d, vm_uuid_id=%d", __func__, type,hostid,hv_uuid_id,vm_uuid_id);
	
		update_hostmacro_data(hv_uuid_id, hostid, "{$VMWARE.HV.UUID}", hv_uuid, "");
		update_hostmacro_data(vm_uuid_id, hostid, "{$VMWARE.VM.UUID}", vm_uuid, "");
	}
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

static void discovery_register_vmware(int vmware_stype, vmware_server *p_server, const zbx_db_drule *drule, const DB_DCHECK *dcheck, 
	zbx_vector_ptr_t *v_hstgrps, char *user, char *passwd, char *ip, char * port)
{
	// zbx_db_dhost		dhost;
	// int			host_status, now;
	char dns[ZBX_INTERFACE_DNS_LEN_MAX];
	zbx_gethost_by_ip(p_server->ip, dns, sizeof(dns));

	// memset(&dhost, 0, sizeof(dhost));
	// host_status = -1;
		
	char vmware_url[256];
	DB_HOST host;
	DB_INTERFACE interface;
	DB_HOST_INVENTORY inventory;

	memset(&host, 0, sizeof(DB_HOST));
	memset(&interface, 0, sizeof(DB_INTERFACE));
	memset(&inventory, 0, sizeof(DB_HOST_INVENTORY));
	zbx_snprintf(vmware_url, sizeof(vmware_url), "https://%s/sdk", ip);  // 填入ip地址

	make_inventory_json_data(p_server); 
  
	// host.hostid = drule->main_hostid;
	//入库host对应的接口
	int  ret = discovery_register_host(&host, &inventory, p_server, p_server->ip, dns, port, DOBJECT_STATUS_UP, dcheck);
	if(SUCCEED == ret)
	{
		// 物理机，先在hstgrp创建目录结构, hosts表中的hstgrpid指向该数据
		if(DEVICE_TYPE_HV == vmware_stype){ 
			update_discover_hv_groupid(v_hstgrps, HSTGRP_TYPE_HV, host.hostid, p_server->uuid, p_server->name, p_server->hstgrpid);
		}
		if(p_server->totalMemory > 0) interface.available = 1;

		// 入库host对应的接口
		discovery_register_interface(&host, &interface, p_server->ip, dns, port, dcheck);
		// 入库host_inventory对应的接口
		discovery_register_host_inventory(&inventory);
		if(DEVICE_TYPE_HV == vmware_stype){
			vmware_register_hostmacro(vmware_stype, host.hostid, vmware_url, user, passwd, p_server->uuid, NULL);
		}else{
			vmware_register_hostmacro(vmware_stype, host.hostid, vmware_url, user, passwd, p_server->hvUuid, p_server->uuid);
		}
		// status 0已监控，1已关闭，2未纳管, 未纳管的设备返回给前端实时显示
		if(host.status == HOST_STATUS_UNREACHABLE || interface.status  == HOST_STATUS_UNREACHABLE)
		{
			if(DEVICE_TYPE_VM == vmware_stype){
				host.hstgrpid = HSTGRP_GROUPID_VM;
			}else{
				host.hstgrpid = HSTGRP_GROUPID_SERVER;
			}
			discoverer_bind_templateid(&host);
			user_discover_add_hostid(dcheck->druleid, host.hostid);
		}
	}

	discovered_next_ip(drule->druleid, vmware_stype, 1);
	db_hosts_free(&host);

}
static void flush_dc_ct_fgroupid(zbx_vector_ptr_t *v_hstgrps, vmware_server *p_server, int top_groupid, int *out_dc_groupid, int *out_ct_groupid)
{

	int index, dc_groupid = 0, ct_groupid = 0; 
	discover_hstgrp d_hstgrp;
	if(NULL != p_server->dataCenterName && strlen(p_server->dataCenterName) > 0)
	{
		d_hstgrp.type = HSTGRP_TYPE_DATACENTER;
		d_hstgrp.name = p_server->dataCenterName;
		if (FAIL != (index = zbx_vector_ptr_search(v_hstgrps, &d_hstgrp, dc_compare_hstgrp)))
		{
			discover_hstgrp *p_vc_hstgrp = v_hstgrps->values[index];

			dc_groupid = p_vc_hstgrp->groupid;	
			// 重新刷新一下 数据中心上一级对应的VCid
			if(dc_groupid > 0 && p_vc_hstgrp->fgroupid != top_groupid){
				p_vc_hstgrp->fgroupid = top_groupid;
				zbx_db_execute("update hstgrp set fgroupid=%d,fgroupids='%d' where groupid = %d"
					, p_vc_hstgrp->fgroupid, p_vc_hstgrp->fgroupid, p_vc_hstgrp->groupid);
			}
		}
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, DataCenterName search. index=%d, dc_groupid=%d",  __func__, index, dc_groupid);
	}

	if(NULL != p_server->clusterName && strlen(p_server->clusterName) > 0)
	{
		d_hstgrp.type = HSTGRP_TYPE_CLUSTER;
		d_hstgrp.name = p_server->clusterName;
		if (FAIL != (index = zbx_vector_ptr_search(v_hstgrps, &d_hstgrp, dc_compare_hstgrp)))
		{
			discover_hstgrp *p_ct_hstgrp = v_hstgrps->values[index];
			ct_groupid = p_ct_hstgrp->groupid;
			zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, ClusterName search. index=%d, ct_groupid=%d",  __func__, index, ct_groupid);
			
			// 重新刷新一下 集群上一级对应的数据中心id
			if(ct_groupid > 0 && p_ct_hstgrp->fgroupid != ct_groupid){
				p_ct_hstgrp->fgroupid = dc_groupid;
				zbx_db_execute("update hstgrp set fgroupid=%d,fgroupids='%d' where groupid = %d"
					, p_ct_hstgrp->fgroupid, p_ct_hstgrp->fgroupid, p_ct_hstgrp->groupid);
			}
		}
	}
	*out_dc_groupid = dc_groupid;
	*out_ct_groupid = ct_groupid;

}
static void discover_vmware_hv(const zbx_db_drule *drule, const DB_DCHECK *dcheck, char *key, char *user, char *passwd, 
	char *ip, char * port, int top_groupid)
{
	zbx_vector_ptr_t v_hstgrps;
	zbx_vector_ptr_create(&v_hstgrps);
 
	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED;

	char *value = NULL;
	vmware_recv(&value, key, user, passwd, ip, port, 3);
	if(NULL == value || strlen(value) == 0)
		return;
	
	int index;
	zbx_vector_ptr_t v_vmware_hv;
	zbx_vector_ptr_create(&v_vmware_hv);
	
	__parse_vmware_hv_data(user, passwd, ip, port, value, &v_vmware_hv);
	
	discovery_add_total_ip_num(drule->druleid, DEVICE_TYPE_HV, v_vmware_hv.values_num);
	if(v_vmware_hv.values_num > 0)
	{
		// 获得hstgrps表上所有的数据中心、集群和物理机的信息
		get_discover_hstgrp(&v_hstgrps);
	}
	for(int i = 0; i < v_vmware_hv.values_num; i ++)
	{
		int dc_groupid = 0,ct_groupid = 0;
		discover_hstgrp d_hstgrp;

		vmware_server *p_server = (vmware_server *)v_vmware_hv.values[i];

		//获取vmware扩展数据
		discover_get_hv_extend_data(user, passwd, ip, port, p_server);

		flush_dc_ct_fgroupid(&v_hstgrps, p_server, top_groupid, &dc_groupid, &ct_groupid);
		p_server->hstgrpid = top_groupid;
		if(NULL != p_server->parentType && strlen(p_server->parentType) > 0)
		{
			if(ct_groupid > 0 && zbx_strcasecmp(p_server->parentType,"ClusterComputeResource") == 0)
			{
				p_server->hstgrpid = ct_groupid;
			}
			else if(dc_groupid > 0 && zbx_strcasecmp(p_server->parentType,"Datacenter") == 0)
			{
				p_server->hstgrpid = dc_groupid;
			}
		}

		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, id=%s, name=%s, ip=%s, dataCenterName=%s, clusterName=%s, parentName=%s,hstgrpid=%d, macs=%s", 
				__func__, p_server->id, p_server->name,p_server->ip, p_server->dataCenterName, p_server->clusterName, 
				p_server->parentName, p_server->hstgrpid, p_server->macs);
		

		discovery_register_vmware(DEVICE_TYPE_HV, p_server, drule, dcheck, &v_hstgrps, user, passwd, ip, port);
 
	}
	
	discovered_next_ip(drule->druleid, DEVICE_TYPE_HV, v_vmware_hv.values_num);
	
	zbx_free(value);
	free_discover_hstgrp(&v_hstgrps);

	zbx_vector_ptr_clear_ext(&v_vmware_hv, (zbx_mem_free_func_t)wmware_free_vmware_server_ptr);
	zbx_vector_ptr_destroy(&v_vmware_hv);
}


static void discover_vmware_vm(const zbx_db_drule *drule, const DB_DCHECK *dcheck, char *key, char *user, char *passwd, 
	char *ip, int port, int top_groupid)
{
	zbx_vector_ptr_t v_hstgrps;
	zbx_vector_ptr_create(&v_hstgrps);

	zbx_vector_ptr_t v_hosts;
	zbx_vector_ptr_create(&v_hosts);

	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED;

	// 接收所有虚拟机的数据
	char *value = NULL;
	vmware_recv(&value, key, user, passwd, ip, port, 3);
	if(NULL == value || strlen(value) == 0)
		return;

	int index;
	zbx_vector_ptr_t v_vmware_vm;
	zbx_vector_ptr_create(&v_vmware_vm);
	__parse_vmware_vm_data(user, passwd, ip, port, value, &v_vmware_vm);
	discovery_add_total_ip_num(drule->druleid, DEVICE_TYPE_VM, v_vmware_vm.values_num);

	if(v_vmware_vm.values_num > 0){

		// 获得hstgrps表上所有的数据中心和集群的信息 
		get_discover_hstgrp(&v_hstgrps);

		// 获得hosts表上所有的物理机的信息
		get_discover_hosts(&v_hosts);
	}
	
	for(int i = 0; i < v_vmware_vm.values_num; i ++)
	{
		int dc_groupid = 0,ct_groupid = 0, hv_hostid = 0;
		discover_hstgrp d_hstgrp;

		vmware_server *p_server = (vmware_server *)v_vmware_vm.values[i];
		
		//获取vmware扩展数据
		discover_get_vm_extend_data(user, passwd, ip, port, p_server);
		
		flush_dc_ct_fgroupid(&v_hstgrps, p_server, top_groupid, &dc_groupid, &ct_groupid);

		p_server->hstgrpid = HSTGRP_GROUPID_VM; //默认是虚拟机id
		// 根据物理机的uuid找到hosts表中对应的物理机的hostid，并把该物理机对应的hstgrpid更新为集群groupid或数据中心groupid
		if(NULL != p_server->hvUuid && strlen(p_server->hvUuid) > 0)
		{
			int hstgrpid = 0;
			if(ct_groupid > 0){
				hstgrpid = ct_groupid;
			}else if(dc_groupid > 0){
				hstgrpid = dc_groupid;
			}
			
			discover_hstgrp d_hstgrp;
			d_hstgrp.type = HSTGRP_TYPE_HV;
			d_hstgrp.uuid = p_server->hvUuid;
			if (FAIL != (index = zbx_vector_ptr_search(&v_hstgrps, &d_hstgrp, dc_compare_hstgrp_uuid)))
			{
				discover_hstgrp *hstgrp = v_hstgrps.values[index]; 

				// 虚拟机的hstgrpid为物理机的groupid
				p_server->hstgrpid = hstgrp->groupid; 

				// 重新刷新一下 物理机对应上一级的主机群
				if(hstgrpid > 0 && hstgrp->fgroupid != hstgrpid)
				{
					hstgrp->fgroupid = hstgrpid;
					zbx_db_execute("update hstgrp set fgroupid=%d,fgroupids='%d' where groupid = %d", 
						hstgrpid, hstgrpid, hstgrp->groupid);
				}
			}

			discover_hosts d_hosts;
			d_hosts.device_type = DEVICE_TYPE_HV;
			d_hosts.uuid = p_server->hvUuid;
			if (FAIL != (index = zbx_vector_ptr_search(&v_hosts, &d_hosts, dc_compare_hosts)))
			{
				discover_hosts *p_host = v_hosts.values[index];
 
				// 重新刷新一下 物理机对应上一级的主机群
				if(hstgrpid > 0 && p_host->hstgrpid != hstgrpid)
				{
					p_host->hstgrpid = hstgrpid;
					zbx_db_execute("update hosts set hstgrpid=%d where uuid = '%s'", hstgrpid, p_host->uuid);
				}
			}
		}

		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, id=%s, name=%s, ip=%s, dataCenterName=%s, clusterName=%s, hvUuid=%s, hstgrpid=%d, macs=%s", 
				__func__, p_server->id, p_server->name,p_server->ip, p_server->dataCenterName, p_server->clusterName, 
				p_server->hvUuid, p_server->hstgrpid, p_server->macs); 
		
		discovery_register_vmware(DEVICE_TYPE_VM, p_server, drule, dcheck, &v_hstgrps, user, passwd, ip, port);
		 
	}
	discovered_next_ip(drule->druleid, DEVICE_TYPE_VM, v_vmware_vm.values_num);
	zbx_free(value);

	
	free_discover_hstgrp(&v_hstgrps); 
	free_discover_hosts(&v_hosts);

	zbx_vector_ptr_clear_ext(&v_vmware_vm, (zbx_mem_free_func_t)wmware_free_vmware_server_ptr);
	zbx_vector_ptr_destroy(&v_vmware_vm);
	  
}
void do_discover_vmware(const zbx_db_drule *drule, const DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port)
{
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, druleid=%d, ip=%s, user=%s, key=%s", __func__, drule->druleid, ip, user, keys);
	int top_groupid = HSTGRP_GROUPID_SERVER; // 扫描的最顶层群组id，默认是Esxi扫描最顶层为服务器
	zbx_vector_str_t v_keys;
	zbx_vector_str_create(&v_keys);
	str_to_vector(&v_keys, keys, ",");
	
	for(int i = 0; i < v_keys.values_num; i++)
	{
		char key[256];
		zbx_snprintf(key, sizeof(key), v_keys.values[i], ip);  // 填入ip地址
		if(0 == zbx_strncasecmp(key,"vmware.dc.discovery", 19))
		{
			top_groupid = discover_vmware_dc_or_cluster(HSTGRP_TYPE_DATACENTER, key, dcheck->user, dcheck->password, ip, port, top_groupid);
			discovered_next_ip(drule->druleid, -1, 5);
		}
		else if(0 == zbx_strncasecmp(key,"vmware.cluster.discovery", 24))
		{
			top_groupid = discover_vmware_dc_or_cluster(HSTGRP_TYPE_CLUSTER, key, dcheck->user, dcheck->password, ip, port, top_groupid);
			discovered_next_ip(drule->druleid, -1, 5);
		}
		else if(0 == zbx_strncasecmp(key,"vmware.hv.discovery", 19))
		{
			discover_vmware_hv(drule, dcheck, key, dcheck->user, dcheck->password, ip, port, top_groupid);
		}
		else if(0 == zbx_strncasecmp(key,"vmware.vm.discovery", 19))
		{
			discover_vmware_vm(drule, dcheck, key, dcheck->user, dcheck->password, ip, port, top_groupid);
		}
	}
	zbx_vector_ptr_clear(&v_keys);
	zbx_vector_ptr_destroy(&v_keys);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
}
void* discover_vmware_thread_handler(void* arg) 
{
	vmware_arg *p_vmarg = (vmware_arg *)arg;
	do_discover_vmware(p_vmarg->drule, p_vmarg->dcheck, p_vmarg->key, p_vmarg->user, p_vmarg->passwd, 
		p_vmarg->ip, p_vmarg->port);
} 
void discover_vmware_thread(const zbx_db_drule *drule, const DB_DCHECK *dcheck, char *key, char *user, char *passwd, char *ip, int port)
{
	pthread_t ds_thread;
	vmware_arg vmware_arg;
	memset(&vmware_arg, 0, sizeof(vmware_arg));
	vmware_arg.drule = drule;
	vmware_arg.dcheck = dcheck;
	vmware_arg.key = key;
	vmware_arg.user = user;
	vmware_arg.passwd = passwd;
	vmware_arg.ip = ip;
	vmware_arg.port = port;

	if (pthread_create(&ds_thread, NULL, discover_vmware_thread_handler, &vmware_arg))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s create thread fail.",__func__);
		return FAIL;
	}
	if (pthread_join(ds_thread, NULL))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s join thread fail", __func__);
	}
}

void discover_vmware(zbx_db_drule *drule, const DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port)
{
	if(NULL == drule || NULL == dcheck){
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, drule or dcheck is null.", __func__);
		return;
	}

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, druleid=%d, ip=%s, user=%s, key=%s", __func__, drule->druleid, ip, user, keys);
	int is_used_thread = 1;
	if(is_used_thread){
		discover_vmware_thread(drule, dcheck, keys, dcheck->user, dcheck->password, ip, port);
	}else{
		do_discover_vmware(drule, dcheck, keys, user, passwd, ip, port);
	}
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
}