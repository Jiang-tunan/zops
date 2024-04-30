#include "discoverer.h"
#include "discoverer_manager.h"
#include "user_discoverer.h"
#include "discoverer_single.h"
#include "discoverer_nutanix.h"
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
#include "zbxdiscovery.h"

#ifdef HAVE_LIBEVENT
#	include <event.h>
#	include <event2/thread.h>
#endif

extern int	g_running_program_type;

void wmware_free_nutanix_server_ptr(nutanix_server *p_server)
{
	zbx_free(p_server->fUuid); 
    zbx_free(p_server->uuid); 
	zbx_free(p_server->name); 
    zbx_free(p_server->ip); 

	zbx_free(p_server->serial); 
	zbx_free(p_server->block_serial); 
	zbx_free(p_server->block_model_name);

	zbx_free(p_server->disk);
	zbx_free(p_server->cpu); 
	zbx_free(p_server->bios);
	zbx_free(p_server->memory); 
	zbx_free(p_server->macs); 
	zbx_free(p_server);
}

static int	dc_compare_nutainx_uuid(const void *d1, const void *d2)
{
	const nutanix_server	*ptr1 = *((const nutanix_server * const *)d1);
	const nutanix_server	*ptr2 = *((const nutanix_server * const *)d2);
	// zabbix_log(LOG_LEVEL_DEBUG,"%s uuid1=%s, uuid2=%s",  __func__, ptr1->uuid, ptr2->uuid);
	
	if(NULL == ptr1->uuid || 0 == strlen(ptr1->uuid) || NULL == ptr2->uuid )
		return -1;
	return strcmp(ptr1->uuid, ptr2->uuid);
}
 
void discover_get_proxy_nutanix_extend_data(zbx_vector_ptr_t *v_extend, nutanix_server *p_server)
{
	nutanix_server f_nutanix;
	f_nutanix.uuid = p_server->uuid;
	int  index = zbx_vector_ptr_search(v_extend, &f_nutanix, dc_compare_nutainx_uuid);
	if(index >= 0)
	{
		nutanix_server *p_nutanix = v_extend->values[index];
		if(p_nutanix->power_state){
			p_server->macs = zbx_strdup(NULL, p_nutanix->macs);
			p_server->ip = zbx_strdup(NULL, p_nutanix->ip);
			p_server->power_state = p_nutanix->power_state;
		}
	}

	//zabbix_log(LOG_LEVEL_DEBUG,"%s index=%d, uuid=%s, macs=%s",  __func__, index, p_server->uuid, p_server->macs);
}


static void __parse_proxy_nutanix_extend_data(char *value, zbx_vector_ptr_t *v_extend)
{
	if(NULL == value || NULL == v_extend) return;
	
	struct zbx_json_parse	jp, data_jp, jp_params;
	size_t  str_alloc = 0;
	const char		*p=NULL;
	char  tstr[128];
	
	if (SUCCEED != zbx_json_open(value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s  zbx_json_open fail",  __func__);
		return;
	}
	if (SUCCEED == zbx_json_brackets_by_name(&jp, "extend_data", &data_jp))
	{
		while (NULL != (p = zbx_json_next(&data_jp, p)))
		{
			if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
			{
				nutanix_server *p_server = (nutanix_server *)zbx_malloc(NULL, sizeof(nutanix_server));
				memset(p_server, 0, sizeof(nutanix_server)); 
			
				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&jp_params, "uuid", tstr, sizeof(tstr), NULL))
				{
					p_server->uuid = zbx_strdup(NULL, tstr);
				}

				str_alloc = 0;
				zbx_json_value_by_name_dyn(&jp_params, "macs", &p_server->macs, &str_alloc, NULL);
				

				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&jp_params, "ip", tstr, sizeof(tstr), NULL))
				{
					p_server->ip = zbx_strdup(NULL, tstr);
				}

				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&jp_params, "power_state", tstr, sizeof(tstr), NULL))
				{
					p_server->power_state = zbx_atoi(tstr);
				}
				//zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s power_state=%d, uuid=%s, macs=%s",  __func__,  p_server->power_state, p_server->uuid, p_server->macs);
				zbx_vector_ptr_append(v_extend, p_server);
			}
		}
	}
}


static int nutanix_recv(char **out_value, char *key, char *user, char *passwd, char *ip, int port, int maxTry)
{
	AGENT_RESULT	result; 
	DC_ITEM		item;
	char url[256], **pvalue;
	int ret = SUCCEED, count = 0, iRet = DISCOVERY_RESULT_FAIL;

	zbx_init_agent_result(&result);

	memset(&item, 0, sizeof(DC_ITEM));
	zbx_strscpy(item.key_orig, key); 
	item.key = item.key_orig;

	zbx_snprintf(url, sizeof(url), key, ip, port);
	item.url = zbx_strdup(NULL,url);
	item.authtype = HTTPTEST_AUTH_BASIC;
	item.username = user;
	item.password = passwd;
	item.type = ITEM_TYPE_HTTPAGENT;
	item.follow_redirects = 1; 
	item.state = 1;
	
	item.timeout = zbx_strdup(NULL, "3s"); 
	item.status_codes = zbx_strdup(NULL, "200"); 

	item.headers = zbx_strdup(NULL, "");
	item.query_fields = zbx_strdup(NULL, "");
	item.posts = zbx_strdup(NULL, "");
	item.params = zbx_strdup(NULL, "");
	item.ssl_cert_file = zbx_strdup(NULL, "");
	item.ssl_key_file = zbx_strdup(NULL, "");
	item.ssl_key_password = zbx_strdup(NULL, ""); 

	do{
		ret = get_value_http(&item, &result);
		if(SUCCEED == ret && NULL != (pvalue = ZBX_GET_TEXT_RESULT(&result)))
		{
			*out_value = zbx_strdup(NULL, *pvalue);
			iRet = DISCOVERY_RESULT_SUCCESS;
			break;
		}else{
			if(NOTSUPPORTED == ret){
				iRet = DISCOVERY_RESULT_CREDENTIAL_FAIL;
			}
			count ++;
			zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s fail. url=%s,count=%d,result=%d",
				__func__, url, count, ret);
			zbx_sleep(2);
		}
	}
	while (count < maxTry);
	
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, iRet=%d, url=%s, user=%s, ip=%s, port=%d, recv value=%s", 
		__func__, iRet, url, user, ip, port, *out_value);
	  
	zbx_free_agent_result(&result);
	return iRet;
}


static void nutanix_get_network_data(char *user, char *passwd, char *ip, int port, nutanix_server *p_server)
{
    char *value = NULL;
	char key[512];
	memset(key, 0, 512);
	zbx_snprintf(key, 512, "https://%s/PrismGateway/services/rest/v2.0/vms/%s/nics/","%s:%d", p_server->uuid);
	 
    nutanix_recv(&value, key, user, passwd, ip, port, 2);
	if(NULL == value || strlen(value) == 0)
		return;

	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	struct zbx_json_parse	jp_entities;
	int		ret = SUCCEED;
	
	zbx_vector_ptr_t v_nework;
	zbx_vector_ptr_create(&v_nework);

	const char *p=NULL;
	char  tstr[128], ipmacs[512], *fmacaddr=NULL;
	
	if (SUCCEED != zbx_json_open(value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s zbx_json_open fail", __func__);
		return;
	}
	if (SUCCEED != zbx_json_brackets_by_name(&jp, "entities", &jp_entities))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s parse entities fail", __func__);
		return;
	}

	memset(ipmacs, 0, sizeof(ipmacs));
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp_entities, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
		{
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "ip_address", tstr, sizeof(tstr), NULL))
			{  
				p_server->ip = zbx_strdup(NULL, tstr);
			}else{
				p_server->ip = zbx_strdup(NULL, ZERO_IP_ADDRESS);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "mac_address", tstr, sizeof(tstr), NULL))
			{  
				fmacaddr = format_mac_address(tstr);
				if (strncmp(fmacaddr, ZBX_DSERVICE_ILLEGAL_MACADDRS, ZBX_DSERVICE_ILLEGAL_MACADDRS_LEN) != 0)
				{
					strcat(ipmacs,fmacaddr);
					strcat(ipmacs,"/");
				}
				zbx_free(fmacaddr);
			}
		}
	}
	p_server->macs = zbx_strdup(NULL, ipmacs);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s mac=%s", __func__, p_server->macs);
}
  
 
static void __parse_hv_data(char *user, char *passwd, char *ip, int port, char *hv_value, zbx_vector_ptr_t *v_nutanix_servers)
{
	zabbix_log(LOG_LEVEL_DEBUG, "In %s() ", __func__);
	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	struct zbx_json_parse	jp_entities;
	int		ret = SUCCEED;
 
	const char		*p=NULL;
	char  tstr[256], buf[64];
	
	if (SUCCEED != zbx_json_open(hv_value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s zbx_json_open fail", __func__);
		return;
	}
	if (SUCCEED != zbx_json_brackets_by_name(&jp, "entities", &jp_entities))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s parse entities fail", __func__);
		return;
	}
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp_entities, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
		{
			nutanix_server *p_server = (nutanix_server *)zbx_malloc(NULL, sizeof(nutanix_server));
			memset(p_server, 0, sizeof(nutanix_server));
			p_server->type = DEVICE_TYPE_HV;

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "cluster_uuid", tstr, sizeof(tstr), NULL))
			{
				p_server->fUuid = zbx_strdup(NULL, tstr);
			}
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "uuid", tstr, sizeof(tstr), NULL))
			{
				p_server->uuid = zbx_strdup(NULL, tstr);
			}
			
			// 获取nutanix CVM的IP来snmp监控，不能使用hypervisor_address来监控（service_vmexternal_ip）
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "hypervisor_address", tstr, sizeof(tstr), NULL))
			{
				p_server->ip = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "name", tstr, sizeof(tstr), NULL))
			{
				p_server->name = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "serial", tstr, sizeof(tstr), NULL))
			{
				p_server->serial = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "block_serial", tstr, sizeof(tstr), NULL))
			{
				p_server->block_serial = zbx_strdup(NULL, tstr);
			}

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "block_model_name", tstr, sizeof(tstr), NULL))
			{
				p_server->block_model_name = zbx_strdup(NULL, tstr);
			}  

			// 分析内存
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "memory_capacity_in_bytes", tstr, sizeof(tstr), NULL))
			{
				struct zbx_json jmemory;
				zbx_json_init(&jmemory, ZBX_JSON_STAT_BUF_LEN); 

				long capacity = zbx_atol(tstr); 
				capacity = capacity/1024/1024/1024;
				memset(buf, 0, sizeof(buf));
				zbx_snprintf(buf, sizeof(buf),"%dG", capacity);
				zbx_json_addstring(&jmemory, "capacity", buf, ZBX_JSON_TYPE_STRING);

				zbx_json_close(&jmemory);
				p_server->memory = strdup(jmemory.buffer);
				zbx_json_free(&jmemory);
			}  


			// "cpu_num": 2,   //CPU数量，总共有几个CPU
			// "core_num": 24,  //CPU核数, 一个CPU有几核
			// "mf":"Intel(R) Corporation" , //CPU厂家
			// "name":"Intel(R) Xeon(R) Gold 5115 CPU @ 2.40GHz"  //CPU名称
			struct zbx_json jcpu;
			zbx_json_init(&jcpu, ZBX_JSON_STAT_BUF_LEN); 
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "cpu_model", tstr, sizeof(tstr), NULL))
			{
				zbx_json_addstring(&jcpu, "name", tstr, ZBX_JSON_TYPE_STRING);
			} 
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "num_cpu_cores", tstr, sizeof(tstr), NULL))
			{
				zbx_json_addint64(&jcpu, "core_num", zbx_atoi(tstr));
			} 
			zbx_json_close(&jcpu);
			p_server->cpu = strdup(jcpu.buffer);
			zbx_json_free(&jcpu); 

			//  "mf": "HPE",         //BIOS 厂家
			// "model": "U30",   //BIOS 类型
			// "version":"03/16/2023" //BIOS版本
			struct zbx_json jbios;
			zbx_json_init(&jbios, ZBX_JSON_STAT_BUF_LEN); 
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "bios_version", tstr, sizeof(tstr), NULL))
			{
				zbx_json_addstring(&jbios, "version", tstr, ZBX_JSON_TYPE_STRING);
			} 
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "bios_model", tstr, sizeof(tstr), NULL))
			{
				zbx_json_addstring(&jbios, "model", tstr, ZBX_JSON_TYPE_STRING);
			} 
			zbx_json_close(&jbios);
			p_server->bios = strdup(jbios.buffer);
			zbx_json_free(&jbios);	
			//zabbix_log(LOG_LEVEL_DEBUG, "%s, bios=%s", __func__, p_server->bios);
	 
			struct zbx_json_parse	jp_ustats;
			if (SUCCEED == zbx_json_brackets_by_name(&jp_params, "usage_stats", &jp_ustats))
			{
				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&jp_ustats, "storage.capacity_bytes", tstr, sizeof(tstr), NULL))
				{
					p_server->disk_capacity = zbx_atol(tstr);
				}   
			}
			struct zbx_json_parse	jp_disk;
			if (SUCCEED == zbx_json_brackets_by_name(&jp_params, "disk_hardware_configs", &jp_disk))
			{
				int index = 0;
				char indexstr[32];
				const char	*pdisk=NULL;
				struct zbx_json_parse	jp_disk_params;
				
				struct zbx_json jdisk;
				zbx_json_init(&jdisk, ZBX_JSON_STAT_BUF_LEN); 
				zbx_json_adduint64(&jdisk, "capacity", p_server->disk_capacity);
				
				zbx_json_addarray(&jdisk, "disk");
				while (NULL != (pdisk = zbx_json_next(&jp_disk, pdisk)))
				{
					index ++;
					memset(indexstr, 0, sizeof(indexstr));
					zbx_snprintf(indexstr, sizeof(indexstr), "%d", index);
					if (SUCCEED == zbx_json_brackets_by_name(&jp_disk, indexstr, &jp_disk_params))
					{
						zbx_json_addobject(&jdisk, NULL);
						memset(tstr, 0, sizeof(tstr));
						if (SUCCEED == zbx_json_value_by_name(&jp_disk_params, "serial_number", tstr, sizeof(tstr), NULL))
						{
							zbx_json_addstring(&jdisk, "serial", tstr, ZBX_JSON_TYPE_STRING);
						}

						memset(tstr, 0, sizeof(tstr));
						if (SUCCEED == zbx_json_value_by_name(&jp_disk_params, "model", tstr, sizeof(tstr), NULL))
						{
							zbx_json_addstring(&jdisk, "model", tstr, ZBX_JSON_TYPE_STRING);
						} 

						memset(tstr, 0, sizeof(tstr));
						if (SUCCEED == zbx_json_value_by_name(&jp_disk_params, "mount_path", tstr, sizeof(tstr), NULL))
						{
							zbx_json_addstring(&jdisk, "name", tstr, ZBX_JSON_TYPE_STRING);
						} 
						
						memset(tstr, 0, sizeof(tstr));
						if (SUCCEED == zbx_json_value_by_name(&jp_disk_params, "current_firmware_version", tstr, sizeof(tstr), NULL))
						{
							zbx_json_addstring(&jdisk, "firmware_version", tstr, ZBX_JSON_TYPE_STRING);
						}
						zbx_json_close(&jdisk);
					}
				}
				zbx_json_close(&jdisk);
				p_server->disk = strdup(jdisk.buffer);
				zbx_json_free(&jdisk); 
				//zabbix_log(LOG_LEVEL_DEBUG, "%s, disk=%s", __func__, p_server->disk);
			}
  
			zbx_vector_ptr_append(v_nutanix_servers, p_server);
		}
	}
	zabbix_log(LOG_LEVEL_DEBUG, "%s() end", __func__);
}

//获取nutanix扩展数据
static void discover_get_vm_extend_data(char *user, char *passwd, char *ip, int port, nutanix_server *p_server)
{ 
	//获取ip地址和mac地址
	if(p_server->power_state){
		nutanix_get_network_data(user, passwd, ip, port, p_server);
	}
}

static void __parse_vm_data(char *user, char *passwd, char *ip, int port, char *hv_value, zbx_vector_ptr_t *v_nutanix_servers)
{
	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	struct zbx_json_parse	jp_entities;
	int		ret = SUCCEED;
 
	const char		*p=NULL;
	char  tstr[256], buf[64];
	//zabbix_log(LOG_LEVEL_DEBUG,"In %s()", __func__);
	if (SUCCEED != zbx_json_open(hv_value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s zbx_json_open fail", __func__);
		return;
	}
	if (SUCCEED != zbx_json_brackets_by_name(&jp, "entities", &jp_entities))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s parse entities fail", __func__);
		return;
	}
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp_entities, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &jp_params))
		{
			int power_state = 0;
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "power_state", tstr, sizeof(tstr), NULL))
			{
				if(zbx_strcasecmp(tstr,"on") == 0)
					power_state = 1;
				else
					power_state = 0;
			} 
			// 如果虚拟机没开机，则不监控
			if(!power_state) continue;

			nutanix_server *p_server = (nutanix_server *)zbx_malloc(NULL, sizeof(nutanix_server));
			memset(p_server, 0, sizeof(nutanix_server));
			p_server->type = DEVICE_TYPE_VM;
			p_server->power_state = power_state;

			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "host_uuid", tstr, sizeof(tstr), NULL))
			{
				p_server->fUuid = zbx_strdup(NULL, tstr);
			}
			
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "uuid", tstr, sizeof(tstr), NULL))
			{
				p_server->uuid = zbx_strdup(NULL, tstr);
			}
 
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "name", tstr, sizeof(tstr), NULL))
			{
				p_server->name = zbx_strdup(NULL, tstr);
			}

			// 获取CPU信息
			struct zbx_json jcpu;
			zbx_json_init(&jcpu, ZBX_JSON_STAT_BUF_LEN); 
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "num_cores_per_vcpu", tstr, sizeof(tstr), NULL))
			{
				zbx_json_addint64(&jcpu, "core_num", zbx_atoi(tstr));
			}
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "num_vcpus", tstr, sizeof(tstr), NULL))
			{
				zbx_json_addint64(&jcpu, "cpu_num", zbx_atoi(tstr));
			}
			zbx_json_close(&jcpu);
			p_server->cpu = strdup(jcpu.buffer);
			zbx_json_free(&jcpu); 

			// 获取内存信息
			memset(tstr, 0, sizeof(tstr));
			if (SUCCEED == zbx_json_value_by_name(&jp_params, "memory_mb", tstr, sizeof(tstr), NULL))
			{
				struct zbx_json jmemory;
				zbx_json_init(&jmemory, ZBX_JSON_STAT_BUF_LEN); 

				long capacity = zbx_atol(tstr); 
				capacity = capacity/1024;
				memset(buf, 0, sizeof(buf));
				zbx_snprintf(buf, sizeof(buf),"%dG", capacity);
				zbx_json_addstring(&jmemory, "capacity", buf, ZBX_JSON_TYPE_STRING);
				zbx_json_close(&jmemory);
				p_server->memory = strdup(jmemory.buffer);
				zbx_json_free(&jmemory);
			}

			zbx_vector_ptr_append(v_nutanix_servers, p_server);
		}
	}
	//zabbix_log(LOG_LEVEL_DEBUG,"End %s() size=%d", __func__, v_nutanix_servers->values_num);
}
 
static nutanix_server * __parse_cluster_data(char *value)
{
	struct zbx_json_parse	jp;
	int	ret = SUCCEED; 
	if (SUCCEED != zbx_json_open(value, &jp))
	{
		zabbix_log(LOG_LEVEL_DEBUG,"%s, json open fail", __func__);
		return NULL;
	}

	char  tstr[256];
	const char	*p=NULL; 
	nutanix_server *p_server = (nutanix_server *)zbx_malloc(NULL, sizeof(nutanix_server));
	memset(p_server, 0, sizeof(nutanix_server));
	p_server->type = DEVICE_TYPE_CLUSTER;
	//遍历list的json
	while (NULL != (p = zbx_json_next(&jp, p)))
	{ 
		
		memset(tstr, 0, sizeof(tstr));
		if (SUCCEED == zbx_json_value_by_name(&jp, "uuid", tstr, sizeof(tstr), NULL))
		{
			p_server->uuid = zbx_strdup(NULL, tstr);
		}

		memset(tstr, 0, sizeof(tstr));
		if (SUCCEED == zbx_json_value_by_name(&jp, "name", tstr, sizeof(tstr), NULL))
		{
			p_server->name = zbx_strdup(NULL, tstr);
		}

		memset(tstr, 0, sizeof(tstr));
		if (SUCCEED == zbx_json_value_by_name(&jp, "cluster_external_ipaddress", tstr, sizeof(tstr), NULL))
		{
			p_server->ip = zbx_strdup(NULL, tstr);
		} 
		
	}
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, uuid=%s, name=%s, ip=%s",
			 __func__, p_server->uuid, p_server->name, p_server->ip);
	return p_server;
}
  

void nutanix_register_hostmacro(int type, int hostid, char *url, char *user, char *passwd, char *uuid)
{
	DB_RESULT	result;
	DB_ROW		row;
	
	if(0 == hostid)  return;

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s type=%d, hostid:%d, uuid=%s", __func__, type, hostid, uuid);
	

	result = zbx_db_select("select hostmacroid,hostid,macro,value,description,type,automatic from hostmacro"
			" where hostid=" ZBX_FS_UI64, hostid);
	int url_id=0,username_id=0,password_id=0,uuid_id=0,hv_uuid_id=0,vm_uuid_id=0;
	while (NULL != (row = zbx_db_fetch(result)))
	{
		char *macro = row[2];
		if (zbx_strcmp_null(macro, "{$NUTANIX.URL}") == 0){
			url_id = zbx_atoi(row[0]);
		}
		else if (zbx_strcmp_null(macro, "{$NUTANIX.USER}") == 0){
			username_id = zbx_atoi(row[0]);
		}
		else if (zbx_strcmp_null(macro, "{$NUTANIX.PASSWORD}") == 0){
			password_id = zbx_atoi(row[0]);
		}
		else if(zbx_strcmp_null(macro, "{$NUTANIX.UUID}") == 0){
			hv_uuid_id = zbx_atoi(row[0]);
		}
	}
	zbx_db_free_result(result);

	update_hostmacro_data(url_id, hostid, "{$NUTANIX.URL}", url, "");
	update_hostmacro_data(username_id, hostid, "{$NUTANIX.USER}", user, "");
	update_hostmacro_data(password_id, hostid, "{$NUTANIX.PASSWORD}", passwd, "");
	update_hostmacro_data(hv_uuid_id, hostid, "{$NUTANIX.UUID}", uuid, "");

	
	//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s type=%d,hostid:%d, hv_uuid_id=%d, vm_uuid_id=%d", __func__, type,hostid,hv_uuid_id,vm_uuid_id);
	

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}


static void discovery_register_nutanix(int nutanix_stype, nutanix_server *p_server, zbx_db_drule *drule, DB_DCHECK *dcheck, 
	DB_HOST *host, zbx_vector_ptr_t *v_hstgrps, char *user, char *passwd, char *ip, char * port, zbx_vector_ptr_t *dhosts)
{ 
	DB_INTERFACE interface;
	DB_HOST_INVENTORY inventory;
	char *dns = zbx_strdup(NULL,"");
	int ret = FAIL, old_decheck_type;

	memset(host, 0, sizeof(DB_HOST));
	memset(&interface, 0, sizeof(DB_INTERFACE));
	memset(&inventory, 0, sizeof(DB_HOST_INVENTORY));
 
	host->proxy_hostid =  drule->proxy_hostid;

	//入库host对应的接口
	ret = discovery_register_host(host, &inventory, p_server, p_server->ip, dns, port, DOBJECT_STATUS_UP, dcheck);
	if(SUCCEED == ret)
	{
		char nutanix_url[256]; 
		// 物理机，先在hstgrp创建目录结构, hosts表中的hstgrpid指向该数据
		switch (nutanix_stype)
		{
		case DEVICE_TYPE_CLUSTER:
			host->groupid = update_discover_hv_groupid(v_hstgrps, HSTGRP_TYPE_CLUSTER, host->hostid, p_server->uuid, p_server->name, p_server->hstgrpid);
			// 先添加interface接口，防止代理snmpv3扫码找不到对应的主机
			old_decheck_type = dcheck->type;
			dcheck->type = SVC_SNMPv3;
			discovery_register_interface(host, &interface, p_server->ip, dns, 161, dcheck);
			drule->main_hostid = host->hostid;
			dcheck->type = old_decheck_type;
			break;
		case DEVICE_TYPE_HV:
			host->groupid = update_discover_hv_groupid(v_hstgrps, HSTGRP_TYPE_HV, host->hostid, p_server->uuid, p_server->name, p_server->hstgrpid);
			discovery_register_interface(host, &interface, p_server->ip, dns, port, dcheck);
			zbx_snprintf(nutanix_url, sizeof(nutanix_url), "https://%s:%d/PrismGateway/services/rest/v2.0/hosts/%s", ip, port, p_server->uuid);  // 填入ip地址
			nutanix_register_hostmacro(nutanix_stype, host->hostid, nutanix_url, user, passwd, p_server->uuid);
			break;
		case DEVICE_TYPE_VM:
			discovery_register_interface(host, &interface, p_server->ip, dns, port, dcheck);
			zbx_snprintf(nutanix_url, sizeof(nutanix_url), "https://%s:%d/PrismGateway/services/rest/v2.0/vms/%s", ip, port, p_server->uuid);
			nutanix_register_hostmacro(nutanix_stype, host->hostid, user, nutanix_url, passwd, p_server->uuid);
			break;
		default:
			break;
		}
		
		// 入库host_inventory对应的接口
		discovery_register_host_inventory(&inventory);
		
		if(DEVICE_TYPE_VM == nutanix_stype){
			host->hstgrpid = HSTGRP_GROUPID_VM;
		}else{
			host->hstgrpid = HSTGRP_GROUPID_SERVER;
		}
		
		if(NULL != dhosts)
		{
			// dhosts不为NULL，表示这个是服务端处理代理请求，因为zbx_db_begin原因，要在zbx_db_commit后执行绑定模板等操作
			zbx_db_dhost *p_dhost = (zbx_db_dhost *)zbx_malloc(NULL,sizeof(zbx_db_dhost));
			p_dhost->hostid = host->hostid;
			p_dhost->templateid = host->templateid;
			p_dhost->hstgrpid = host->hstgrpid;
			p_dhost->hstatus = host->status;
			p_dhost->istatus = interface.status;
			p_dhost->druleid = drule->druleid;
			p_dhost->proxy_hostid = host->proxy_hostid; 
			
			zbx_vector_ptr_append(dhosts, p_dhost);
		}
		// status 0已监控，1已关闭，2未纳管, 未纳管的设备返回给前端实时显示
		else if(host->status == HOST_STATUS_UNREACHABLE || interface.status  == HOST_STATUS_UNREACHABLE)
		{
			discoverer_bind_templateid(host);
			user_discover_add_hostid(dcheck->druleid, host->hostid);
		}
	}
	db_hosts_free(host);

	if(NULL == dhosts){
		discovered_next_ip(drule->druleid, nutanix_stype, 1);
	}else{
		server_discovered_proxy_next_ip(drule->druleid, nutanix_stype, 1);
	}
}


// 返回vc_groupid
static int discover_nutanix_cluster(zbx_db_drule *drule, DB_DCHECK *dcheck, const char *key, 
	const char *user, const char *passwd, const char *ip, int port, int *top_groupid, char *bvalue, zbx_vector_ptr_t *dhosts)
{ 
	int ret = DISCOVERY_RESULT_FAIL;
	char *value = NULL;
	if(NULL != key){
		nutanix_recv(&value, key, user, passwd, ip, port, 3);
		user_discover_add_result(drule->druleid, ret);
	}else{
		value = bvalue;
	}
	if(NULL == value || strlen(value) == 0) 
		return DISCOVERY_RESULT_FAIL; 
	
	zbx_vector_ptr_t v_hstgrps;
	zbx_vector_ptr_create(&v_hstgrps);

	DB_HOST host;
	int index, fgroupid = -1;
	zbx_vector_ptr_t v_nutanix_hv;
	zbx_vector_ptr_create(&v_nutanix_hv);
	nutanix_server *p_server = __parse_cluster_data(value);
	if(NULL != p_server && 0 != strlen(p_server->ip))
	{
		get_discover_hstgrp(&v_hstgrps);
		//最顶层的groupid 默认为"3"-服务器, 如果key包括 dc 或 cluster 扫描，说明是vCenter扫描，要增加vc层。
		if(HSTGRP_GROUPID_SERVER == *top_groupid) *top_groupid = get_discover_vc_groupid(HSTGRP_TYPE_NTX, ip, dcheck->proxy_hostid);
		// 集群上层是NTX
		p_server->hstgrpid = *top_groupid; 
		 
		discovery_register_nutanix(DEVICE_TYPE_CLUSTER, p_server, drule, dcheck, &host, &v_hstgrps, user, passwd, ip, port, dhosts);

		*top_groupid = host.groupid;
		ret = DISCOVERY_RESULT_SUCCESS;
	} 
	
	if(NULL != key) zbx_free(value); 
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end, ret=%d, top_groupid=%d", __func__,ret, *top_groupid);
	return ret;
}

static void discover_nutanix_hv(const zbx_db_drule *drule, const DB_DCHECK *dcheck, const char *key, 
	const char *user, const char *passwd, const char *ip, int port, int top_groupid, char *bvalue, zbx_vector_ptr_t *dhosts)
{
	zbx_vector_ptr_t v_hstgrps;
	zbx_vector_ptr_create(&v_hstgrps);

	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED;

	char *value = NULL, *extend_value = NULL;
	if(NULL != key){
		ret = nutanix_recv(&value, key, user, passwd, ip, port, 3);
		user_discover_add_result(drule->druleid, ret);
	}else{
		parse_tsf_data(bvalue, &value, &extend_value);
	}
	if(NULL == value || strlen(value) == 0)
		return;

	int index;
	zbx_vector_ptr_t v_nutanix_hv;
	zbx_vector_ptr_create(&v_nutanix_hv);

	// // 获得hosts表上所有的物理机的信息
	// zbx_vector_ptr_t v_hosts;
	// zbx_vector_ptr_create(&v_hosts);
	__parse_hv_data(user, passwd, ip, port, value, &v_nutanix_hv);
	
	if(NULL == dhosts){
		discovery_add_total_ip_num(drule->druleid, DEVICE_TYPE_HV, v_nutanix_hv.values_num);
	}else{
		server_discovery_proxy_add_total_ip_num(drule->druleid, DEVICE_TYPE_HV, v_nutanix_hv.values_num);
	}

	if(v_nutanix_hv.values_num > 0)
	{
		get_discover_hstgrp(&v_hstgrps);
		// get_discover_hosts(&v_hosts);
	}

	for(int i = 0; i < v_nutanix_hv.values_num; i ++)
	{
		nutanix_server *p_server = (nutanix_server *)v_nutanix_hv.values[i];
		
		p_server->hstgrpid = top_groupid; //默认是cluster 集群服务器的id
		
		// 根据物理机的uuid找到hosts表中对应的物理机的hostid，并把该物理机对应的hstgrpid更新为集群groupid或数据中心groupid
		if(NULL != p_server->fUuid && strlen(p_server->fUuid) > 0)
		{
			discover_hstgrp d_hstgrp;
			d_hstgrp.type = DEVICE_TYPE_CLUSTER;
			d_hstgrp.uuid = p_server->fUuid;
			if (FAIL != (index = zbx_vector_ptr_search(&v_hstgrps, &d_hstgrp, dc_compare_hstgrp_uuid)))
			{
				discover_hstgrp *hstgrp = v_hstgrps.values[index]; 

				zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, find success. fUuid=%s, groupid=%d", 
					__func__,  p_server->fUuid, hstgrp->groupid);
		
				// 虚拟机的hstgrpid为物理机的groupid
				p_server->hstgrpid = hstgrp->groupid; 
			}
		} 
 
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, name=%s, ip=%s, hstgrpid=%d, fUuid=%s, macs=%s", 
				__func__,p_server->name,p_server->ip, p_server->hstgrpid, p_server->fUuid, p_server->macs);
		
		DB_HOST host;
		discovery_register_nutanix(DEVICE_TYPE_HV, p_server, drule, dcheck, &host, &v_hstgrps, user, passwd, ip, port, dhosts);
 
	}
	
	if(NULL == dhosts){
		discovered_next_ip(drule->druleid, DEVICE_TYPE_HV, v_nutanix_hv.values_num);
	}else{
		server_discovered_proxy_next_ip(drule->druleid, DEVICE_TYPE_HV, v_nutanix_hv.values_num);
	}

	zbx_free(value);
	zbx_free(extend_value);
	free_discover_hstgrp(&v_hstgrps); 
	zbx_vector_ptr_clear_ext(&v_nutanix_hv, (zbx_mem_free_func_t)wmware_free_nutanix_server_ptr);
	zbx_vector_ptr_destroy(&v_nutanix_hv);
}


static void discover_nutanix_vm(const zbx_db_drule *drule, const DB_DCHECK *dcheck, const char *key, 
	const char *user, const char *passwd, const char *ip, int port, int top_groupid, char *bvalue, zbx_vector_ptr_t *dhosts)
{
	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED, index = 0;

	// 接收所有虚拟机的数据
	char *value = NULL, *extend_value = NULL;

	if(NULL != key){
		ret = nutanix_recv(&value, key, user, passwd, ip, port, 3);
		user_discover_add_result(drule->druleid, ret);
	}else{
		parse_tsf_data(bvalue, &value, &extend_value);
	}
	if(NULL == value || strlen(value) == 0)
		return;

	zbx_vector_ptr_t v_hstgrps;
	zbx_vector_ptr_create(&v_hstgrps);

	// zbx_vector_ptr_t v_hosts;
	// zbx_vector_ptr_create(&v_hosts);
	zbx_vector_ptr_t v_nutanix_vm;
	zbx_vector_ptr_create(&v_nutanix_vm);
	__parse_vm_data(user, passwd, ip, port, value, &v_nutanix_vm);
	
	zbx_vector_ptr_t v_extend;
	zbx_vector_ptr_create(&v_extend);
	__parse_proxy_nutanix_extend_data(extend_value, &v_extend);

	if(NULL == dhosts){
		discovery_add_total_ip_num(drule->druleid, DEVICE_TYPE_VM, v_nutanix_vm.values_num);
	}else{ 
		server_discovery_proxy_add_total_ip_num(drule->druleid, DEVICE_TYPE_VM, v_nutanix_vm.values_num);
	}

	if(v_nutanix_vm.values_num > 0){

		// 获得hstgrps表上所有的数据中心和集群的信息 
		get_discover_hstgrp(&v_hstgrps);

		// 获得hosts表上所有的物理机的信息
		// get_discover_hosts(&v_hosts);
	}
	
	for(int i = 0; i < v_nutanix_vm.values_num; i ++)
	{
		nutanix_server *p_server = (nutanix_server *)v_nutanix_vm.values[i];
		
		if(NULL != key){ 
			discover_get_vm_extend_data(user, passwd, ip, port, p_server);
		}else{
			discover_get_proxy_nutanix_extend_data(&v_extend, p_server);
		}
		if(NULL == p_server->ip || strlen(p_server->ip) == 0)
		{
			p_server->ip = zbx_strdup(NULL, ZERO_IP_ADDRESS);
		}

		p_server->hstgrpid = HSTGRP_GROUPID_VM; //默认是集群groupid
		// 根据虚拟机的父亲uuid找到hosts表中对应的物理机的hostid，并把该物理机对应的hstgrpid更新为集群groupid
		if(NULL != p_server->fUuid && strlen(p_server->fUuid) > 0)
		{
			discover_hstgrp d_hstgrp;
			d_hstgrp.type = HSTGRP_TYPE_HV;
			d_hstgrp.uuid = p_server->fUuid;
			if (FAIL != (index = zbx_vector_ptr_search(&v_hstgrps, &d_hstgrp, dc_compare_hstgrp_uuid)))
			{
				discover_hstgrp *hstgrp = v_hstgrps.values[index]; 

				// 虚拟机的hstgrpid为物理机的groupid
				p_server->hstgrpid = hstgrp->groupid; 
			}
		}

		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, name=%s, ip=%s, uuid=%s, hstgrpid=%d, macs=%s", 
				__func__, p_server->name,p_server->ip, p_server->uuid, p_server->hstgrpid, p_server->macs); 
		DB_HOST host;
		discovery_register_nutanix(DEVICE_TYPE_VM, p_server, drule, dcheck, &host, &v_hstgrps, user, passwd, ip, port, dhosts);
	}
	
	
	if(NULL == dhosts){
		discovered_next_ip(drule->druleid, DEVICE_TYPE_VM, v_nutanix_vm.values_num);
	}else{
		server_discovered_proxy_next_ip(drule->druleid, DEVICE_TYPE_VM, v_nutanix_vm.values_num);
	}

	zbx_free(value);

	free_discover_hstgrp(&v_hstgrps);

	zbx_vector_ptr_clear_ext(&v_nutanix_vm, (zbx_mem_free_func_t)wmware_free_nutanix_server_ptr);
	zbx_vector_ptr_destroy(&v_nutanix_vm);
	
}
char* sub_nutanix_key(char **newstr, char *str, size_t llen)
{ 
	size_t  newlen = 0, alloc = 0,offset = 0, size = 0;
	newlen = strlen(str);
	size = newlen - llen - 1;
	zbx_str_memcpy_alloc(newstr, &alloc, &offset, str + llen, size); 
	//zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, newstr=%s", __func__, *newstr);
	return newstr; 
} 

/**
 * 	集群： "https://%s:%d/PrismGateway/services/rest/v2.0/clusters/"
	物理机："https://%s:%d/PrismGateway/services/rest/v2.0/hosts/"
	虚拟机："https://%s:%d/PrismGateway/services/rest/v2.0/vms/"
*/
void do_discover_nutanix(zbx_db_drule *drule, const DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port)
{
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, druleid=%d, ip=%s, user=%s, key=%s", __func__, drule->druleid, ip, user, keys);
	int ret = SUCCEED,  top_groupid = HSTGRP_GROUPID_SERVER; // 扫描的最顶层群组id，默认是Esxi扫描最顶层为服务器
	zbx_vector_str_t v_keys;
	zbx_vector_str_create(&v_keys);
	str_to_vector(&v_keys, keys, ",");

	char *urlkey=NULL, *key = NULL;
	for(int i = 0; i < v_keys.values_num; i++)
	{
		key = v_keys.values[i]; 

		if(0 == zbx_strncasecmp(key,"nutanix.cluster.discovery", 25))
		{
			sub_nutanix_key(&urlkey, key, (size_t)26);
			ret = discover_nutanix_cluster(drule, dcheck, urlkey, dcheck->user, dcheck->password, ip, port, &top_groupid, NULL, NULL);
			discovered_next_ip(drule->druleid, -1, 10);
		}
		else if(0 == zbx_strncasecmp(key,"nutanix.hv.discovery", 20))
		{
			sub_nutanix_key(&urlkey, key, (size_t)21);
			discover_nutanix_hv(drule, dcheck, urlkey, dcheck->user, dcheck->password, ip, port, top_groupid, NULL, NULL);
		}
		else if(0 == zbx_strncasecmp(key,"nutanix.vm.discovery", 20))
		{
			sub_nutanix_key(&urlkey, key, (size_t)21);
			discover_nutanix_vm(drule, dcheck, urlkey, dcheck->user, dcheck->password, ip, port, top_groupid, NULL, NULL);
		}
		zbx_free(urlkey);
		urlkey=NULL;
		if(SUCCEED != ret) break;
	}
	
	zbx_vector_ptr_clear(&v_keys);
	zbx_vector_ptr_destroy(&v_keys);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
}

static void proxy_discover_nutanix_hv_vm(int scan_type, const zbx_db_drule *drule, const DB_DCHECK *dcheck, char *key, char *user, char *passwd, 
	char *ip, int port, char **bigvalue)
{ 
	struct zbx_json j;
	struct zbx_json_parse jp_params;
	struct zbx_json_parse	jp;
	int		ret = SUCCEED, value_len = 0, extend_data_len = 0;
	char *value = NULL,*extend_data = NULL;
	size_t	bigvalue_alloc = 0, bigvalue_offset = 0;

	nutanix_recv(&value, key, user, passwd, ip, port, 3);
	value_len = (value == NULL?0:strlen(value));
	if(value_len == 0){
		return;
	}
	
	zbx_vector_ptr_t v_nutanix;
	zbx_vector_ptr_create(&v_nutanix);
	
	if(PROXY_TSF_TYPE_NUTANIX_HV == scan_type){
		__parse_hv_data(user, passwd, ip, port, value, &v_nutanix);
	}else{
		__parse_vm_data(user, passwd, ip, port, value, &v_nutanix);
	}
	
	// 开始"data"数组
	zbx_json_init(&j, ZBX_JSON_PROXY_DATA_BUF_LEN);
	zbx_json_addarray(&j, "extend_data");
	for(int i = 0; i < v_nutanix.values_num; i ++)
	{
		nutanix_server *p_server = (nutanix_server *)v_nutanix.values[i];
		// 只有虚拟机才有扩展数据
		if(PROXY_TSF_TYPE_NUTANIX_WM == scan_type){
			discover_get_vm_extend_data(user, passwd, ip, port, p_server);
			zbx_json_addobject(&j,NULL);
			zbx_json_addstring(&j, "uuid", p_server->uuid, ZBX_JSON_TYPE_STRING);
			zbx_json_addstring(&j, "macs", p_server->macs, ZBX_JSON_TYPE_STRING);
			zbx_json_addstring(&j, "ip", p_server->ip, ZBX_JSON_TYPE_STRING);
			zbx_json_addint64(&j, "power_state", p_server->power_state);
			zbx_json_close(&j); 
		}
	}
	zbx_json_close(&j);
	extend_data = j.buffer;
	extend_data_len = strlen(extend_data);
	zbx_snprintf_alloc(bigvalue, &bigvalue_alloc, &bigvalue_offset, "%08d%04d%s%08d%04d%s",
					value_len, PROXY_TSF_TYPE_DATA, value, 
					extend_data_len,PROXY_TSF_TYPE_EXTEND_DATA,extend_data);
	zbx_json_free(&j);
	zbx_vector_ptr_clear_ext(&v_nutanix, (zbx_mem_free_func_t)wmware_free_nutanix_server_ptr);
	zbx_vector_ptr_destroy(&v_nutanix);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
}

void do_proxy_discover_nutanix(zbx_db_drule *drule, DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port)
{ 
	zbx_vector_str_t v_keys;
	zbx_vector_str_create(&v_keys);
	
	char *bigvalue = NULL, *value = NULL, *sessions = NULL;
	size_t	bigvalue_alloc = 0, bigvalue_offset = 0;
	int value_len = 0, now = 0, scan_type;
	char *key = NULL, *urlkey=NULL;

	int ret = proxy_get_sessions(drule->druleid, &sessions);
	value_len = (sessions==NULL ? 0:strlen(sessions));
	
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, druleid=%d, sessions=%s, ip=%s, user=%s, key=%s", __func__, drule->druleid, sessions, ip, user, keys);
	
	if(SUCCEED == ret){
		zbx_snprintf_alloc(&bigvalue, &bigvalue_alloc, &bigvalue_offset, "%08d%04d%s",
					value_len, PROXY_TSF_TYPE_SESSION, sessions);
	}else{
		zbx_snprintf_alloc(&bigvalue, &bigvalue_alloc, &bigvalue_offset, "%08d%04d",
					value_len, PROXY_TSF_TYPE_SESSION);
	}

	str_to_vector(&v_keys, keys, ",");

	for(int i = 0; i < v_keys.values_num; i++)
	{
		key = v_keys.values[i]; 
		
		if(0 == zbx_strncasecmp(key,"nutanix.cluster.discovery", 25))
		{
			scan_type = PROXY_TSF_TYPE_NUTANIX_CLUSTER;
			sub_nutanix_key(&urlkey, key, (size_t)26);
		}
		else if(0 == zbx_strncasecmp(key,"nutanix.hv.discovery", 20))
		{
			scan_type = PROXY_TSF_TYPE_NUTANIX_HV;
			sub_nutanix_key(&urlkey, key, (size_t)21);
		}
		else if(0 == zbx_strncasecmp(key,"nutanix.vm.discovery", 20))
		{
			scan_type = PROXY_TSF_TYPE_NUTANIX_WM;
			sub_nutanix_key(&urlkey, key, (size_t)21);
		}
		switch (scan_type)
		{
		case PROXY_TSF_TYPE_NUTANIX_CLUSTER:
			nutanix_recv(&value, urlkey, user, passwd, ip, port, 3);
			value_len = (value==NULL ? 0:strlen(value));
			if(value == NULL) value = zbx_strdup(NULL, "");
			zbx_snprintf_alloc(&bigvalue, &bigvalue_alloc, &bigvalue_offset, "%08d%04d%s",
				value_len, scan_type, value);
			discovered_next_ip(drule->druleid, -1, 10);
			break;
		case PROXY_TSF_TYPE_NUTANIX_HV:
		case PROXY_TSF_TYPE_NUTANIX_WM:
			proxy_discover_nutanix_hv_vm(scan_type, drule, dcheck, urlkey, user, passwd, ip, port,  &value);
			value_len = (value==NULL ? 0:strlen(value));
			if(value == NULL) value = zbx_strdup(NULL, "");
			zbx_snprintf_alloc(&bigvalue, &bigvalue_alloc, &bigvalue_offset, "%08d%04d%s",
					value_len, scan_type, value);
			break;
		default:
			break;
		} 
		
		zbx_free(urlkey);
		urlkey=NULL;
		zbx_free(value);
		value=NULL;
	}
	
	if(bigvalue != NULL){
		now = time(NULL);
		dc_proxy_update_hosts(drule->druleid, dcheck->dcheckid, ip,
			"", port, 0, "", now, PROXY_SCAN_TYPE_NUTANIX, bigvalue);
	}
	// proxy_discover_finished(drule->druleid);
	
	zbx_vector_ptr_clear(&v_keys);
	zbx_vector_ptr_destroy(&v_keys);
	zbx_free(bigvalue);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
}

void* discover_nutanix_thread_handler(void* arg) 
{
	nutanix_arg *p_vmarg = (nutanix_arg *)arg;
	do_discover_nutanix(p_vmarg->drule, p_vmarg->dcheck, p_vmarg->key, p_vmarg->user, p_vmarg->passwd, 
		p_vmarg->ip, p_vmarg->port);
} 
void discover_nutanix_thread(zbx_db_drule *drule, const DB_DCHECK *dcheck, char *key, char *user, char *passwd, char *ip, int port)
{
	pthread_t ds_thread;
	nutanix_arg nutanix_arg;
	memset(&nutanix_arg, 0, sizeof(nutanix_arg));
	nutanix_arg.drule = drule;
	nutanix_arg.dcheck = dcheck;
	nutanix_arg.key = key;
	nutanix_arg.user = user;
	nutanix_arg.passwd = passwd;
	nutanix_arg.ip = ip;
	nutanix_arg.port = port;

	if (pthread_create(&ds_thread, NULL, discover_nutanix_thread_handler, &nutanix_arg))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s create thread fail.",__func__);
		return ;
	}
	if (pthread_join(ds_thread, NULL))
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s join thread fail", __func__);
	}
}

void discover_nutanix(zbx_db_drule *drule, DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port)
{
	if(NULL == drule || NULL == dcheck){
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, drule or dcheck is null.", __func__);
		return;
	}

	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, druleid=%d, proxy_hostid=%d, ip=%s, user=%s, key=%s", 
	__func__, drule->druleid, ip, user, dcheck->proxy_hostid, keys);


	if(ZBX_PROGRAM_TYPE_PROXY == g_running_program_type) 
	{	// 代理服务端执行
		do_proxy_discover_nutanix(drule, dcheck, keys, user, passwd, ip, port);
	}
	else
	{
		int is_used_thread = 1;
		
		// zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, used_thread=%d, druleid=%d, ip=%s, user=%s, key=%s", __func__, is_used_thread, drule->druleid, ip, user, keys);
		
		if(is_used_thread){
			discover_nutanix_thread(drule, dcheck, keys, dcheck->user, dcheck->password, ip, port);
		}else{
			do_discover_nutanix(drule, dcheck, keys, user, passwd, ip, port);
		}
	}
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end", __func__);
}


void server_discover_nutanix_from_proxy(int scan_type, zbx_db_drule *drule, DB_DCHECK *dcheck,
	 zbx_vector_ptr_t *dhosts, char *bigvalue, char *ip, int port)
{
	int  ret = SUCCEED, top_groupid = HSTGRP_GROUPID_SERVER; // 扫描的最顶层群组id，默认是Esxi扫描最顶层为服务器
	zbx_vector_ptr_t bvalues;
	zbx_vector_ptr_create(&bvalues);
 
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s druleid=%d, ip=%s, bigvalue=%s", 
		__func__, drule->druleid, ip,  print_content(bigvalue));
	
	if(NULL == bigvalue) return;

	parse_bigvalue(&bvalues, bigvalue);

	for(int i = 0; i < bvalues.values_num; i ++)
	{
		zbx_bigvalue_t *pvalue = (zbx_bigvalue_t *)bvalues.values[i];
		char *value = pvalue->value;
		switch (pvalue->scan_type)
		{
		case PROXY_TSF_TYPE_SESSION:
			drule->sessions = zbx_strdup(NULL,value);
			// 这个host是为了让上层能调用server_discover_proxy_finished，执行结束命令
			zbx_db_dhost *p_dhost = (zbx_db_dhost *)zbx_malloc(NULL,sizeof(zbx_db_dhost));
			p_dhost->hostid = 0;
			p_dhost->druleid = drule->druleid; 
			p_dhost->session = zbx_strdup(NULL, drule->sessions);
			zbx_vector_ptr_append(dhosts, p_dhost);
			break;
		case PROXY_TSF_TYPE_NUTANIX_CLUSTER:
			ret = discover_nutanix_cluster(drule, dcheck, NULL, dcheck->user, dcheck->password, ip, port, &top_groupid, value, dhosts);
			break;
		case PROXY_TSF_TYPE_NUTANIX_HV:
			discover_nutanix_hv(drule, dcheck, NULL, dcheck->user, dcheck->password, ip, port, top_groupid, value, dhosts);
			break;
		case PROXY_TSF_TYPE_NUTANIX_WM:
			discover_nutanix_vm(drule, dcheck, NULL, dcheck->user, dcheck->password, ip, port, top_groupid, value, dhosts);
			break;
		default:
			break;
		}
		if(SUCCEED != ret) break;
	}

	server_discovered_proxy_next_ip(drule->druleid, -1, 1);

	free_bigvalues(&bvalues);
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s end, ret=%d", __func__, ret);
}

 