#include "discoverer.h"
#include "discoverer_protocol.h"
#include "discoverer_manager.h"
#include "zbxdiscovery.h"
#include "user_discoverer.h"
#include "discoverer_single.h"
#include "zbxserver.h"


//传入一个json数据 解析出对应字段
static int	make_dechecks_from_json(const struct zbx_json_parse *jp, zbx_vector_ptr_t *dchecks)
{
	struct zbx_json_parse jp_params, jp_node;
	const char *pnext = NULL;
	int ret = DISCOVERY_RESULT_SUCCESS;

	if (SUCCEED != zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &jp_params))
	{
		return DISCOVERY_RESULT_JSON_PARSE_FAIL;
	}

	int valuesize = 16;
	char int_value[valuesize];
	 
	while (NULL != (pnext = zbx_json_next(&jp_params, pnext)))
	{
		if (SUCCEED != zbx_json_brackets_open(pnext, &jp_node))
			continue;

		// 每次循环读取数据，必须重新初始化为0，否则会crash
		size_t ip_size=0, ports_size=0, community_size=0;
		size_t securityname_size=0, authpassphrase_size=0;
		size_t privpassphrase_size=0, contextname_size=0;
		size_t snmp_community_size=0;

		// 获取每个发现方式的数据，一个IP可能有多个发现方式，如:SNMP v2,AGENT等
		DB_DCHECK *dcheck = (DB_DCHECK *)zbx_malloc(NULL, sizeof(DB_DCHECK));
		memset(dcheck, 0, sizeof(DB_DCHECK));
		dcheck->type = -100; 

		zbx_vector_ptr_append(dchecks, dcheck);

		// zbx_json_value_by_name_dyn 方法会自动malloc内存，所以可以传空指针进去
		if (SUCCEED != zbx_json_value_by_name_dyn(&jp_node, "ip", &dcheck->ip, &ip_size, NULL))
			return DISCOVERY_RESULT_JSON_PARSE_FAIL;
	
		if (SUCCEED != zbx_json_value_by_name_dyn(&jp_node, "ports", &dcheck->ports, &ports_size, NULL))
			return DISCOVERY_RESULT_JSON_PARSE_FAIL;
		
		
		if (SUCCEED == zbx_json_value_by_name(&jp_node, "type", int_value, sizeof(int_value), NULL))
		{
			zbx_lrtrim(int_value, ZBX_WHITESPACE);
			zbx_is_uint64(int_value, &dcheck->type);
			
			switch (dcheck->type)
			{
				case SVC_SNMPv1:
				case SVC_SNMPv2c:
				case SVC_SNMPv3:
					dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_SNMP_KEY);
					break;
				case SVC_AGENT:
					dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_AGENT_KEY);
					break;
				default:
					break;
			}
			
			memset(int_value, 0 , valuesize);
			
		}else{
			return DISCOVERY_RESULT_JSON_PARSE_FAIL;
		}

		if (SUCCEED != zbx_json_value_by_name_dyn(&jp_node, "snmp_community", &dcheck->snmp_community, &snmp_community_size, NULL))
		{
			switch (dcheck->type)
			{
				case SVC_SNMPv1:
				case SVC_SNMPv2c:
				case SVC_SNMPv3:
					dcheck->snmp_community = zbx_strdup(NULL, SNMP_COMMUNITY);
					break;
				case SVC_AGENT:
					dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_AGENT_KEY);
					break;
				default:
					break;
			}
		}

		if (SUCCEED != zbx_json_value_by_name_dyn(&jp_node, "snmpv3_securityname", &dcheck->snmpv3_securityname, &securityname_size, NULL))
			dcheck->snmpv3_securityname=zbx_strdup(NULL,"");
		
		if (SUCCEED != zbx_json_value_by_name_dyn(&jp_node, "snmpv3_authpassphrase", &dcheck->snmpv3_authpassphrase, &authpassphrase_size, NULL))
			dcheck->snmpv3_authpassphrase=zbx_strdup(NULL,"");
		
		if (SUCCEED != zbx_json_value_by_name_dyn(&jp_node, "snmpv3_privpassphrase", &dcheck->snmpv3_privpassphrase, &privpassphrase_size, NULL))
			dcheck->snmpv3_privpassphrase=zbx_strdup(NULL,"");
		
		if (SUCCEED != zbx_json_value_by_name_dyn(&jp_node, "snmpv3_contextname", &dcheck->snmpv3_contextname, &contextname_size, NULL))
			dcheck->snmpv3_contextname=zbx_strdup(NULL,"");

		if (SUCCEED == zbx_json_value_by_name(&jp_node, "snmpv3_securitylevel", int_value, sizeof(int_value), NULL))
		{
			zbx_lrtrim(int_value, ZBX_WHITESPACE);
			dcheck->snmpv3_securitylevel = (unsigned char)atoi(int_value);
			memset(int_value, 0 , valuesize);
		}
		
		if (SUCCEED == zbx_json_value_by_name(&jp_node, "snmpv3_authprotocol", int_value, sizeof(int_value), NULL))
		{
			zbx_lrtrim(int_value, ZBX_WHITESPACE);
			dcheck->snmpv3_authprotocol = (unsigned char)atoi(int_value);
			memset(int_value, 0 , valuesize);
		}

		if (SUCCEED == zbx_json_value_by_name(&jp_node, "snmpv3_privprotocol", int_value, sizeof(int_value), NULL))
		{
			zbx_lrtrim(int_value, ZBX_WHITESPACE);
			dcheck->snmpv3_privprotocol = (unsigned char)atoi(int_value);
			memset(int_value, 0 , valuesize);
		}
		
		// if(dcheck->ip == NULL || dcheck->ports == NULL || dcheck->type == -100)
		// {
		// 	ret = DISCOVERY_RESULT_SCAN_FAIL;
		// 	zabbix_log(LOG_LEVEL_WARNING,"#ZOPS#make_dechecks_from_json fail! ret=%d, ip=%s, ports=%s,type=%d",ret, dcheck->ip, dcheck->ports, dcheck->type);	
		// 	return ret;
		// }
	}
			
	return ret;
}


static int	discovery_single_parsing_fields(const char *value, const int dcheck_type, char **sysname, char **sysdesc,char **ifphysaddress,char **ifphysaddresses, 
		char **entphysicalserialnum, char **entphysicalmodelname, char **os, char **dns, int *groupid, int *manufacturerid, int *templateid)
{
	zabbix_log(LOG_LEVEL_INFORMATION, "func[%s] single scan parsing value:[%s]", __func__, value);
	zbx_vector_str_t	macs_dis;
	zbx_vector_str_create(&macs_dis);

	if (NULL == *sysname || 0==zbx_strcmp_natural(*sysname, ""))
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSNAME,sysname);

	if (NULL == *sysdesc || 0==zbx_strcmp_natural(*sysdesc, ""))
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_SYSDESC,sysdesc);

	discovery_parsing_macs(value,&macs_dis);
	if (NULL == *ifphysaddress || 0==zbx_strcmp_natural(*ifphysaddress, ""))
	{
		if (macs_dis.values_num) 
			*ifphysaddress = zbx_strdup(NULL, macs_dis.values[0]);
		else
			*ifphysaddress = zbx_strdup(NULL, "");
	}

	char *ifphysaddresses_=NULL;
	vector_to_str(&macs_dis, &ifphysaddresses_, "/");
	if (NULL == *ifphysaddresses || 0==zbx_strcmp_natural(*ifphysaddresses, ""))
	{
		zbx_free(*ifphysaddresses);
		*ifphysaddresses = ifphysaddresses_;
	}
		
	if (NULL == *entphysicalserialnum || 0==zbx_strcmp_natural(*entphysicalserialnum, ""))
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM,entphysicalserialnum);

	if (NULL == *entphysicalmodelname || 0==zbx_strcmp_natural(*entphysicalmodelname, ""))
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME,entphysicalmodelname);

	if (NULL == *os || 0==zbx_strcmp_natural(*os, ""))
		discovery_parsing_value_os(*sysdesc, os);

	*dns = zbx_strdup(NULL, "");
	
	int groupid_, manufacturerid_, templateid_;
	discovery_parsing_value_model(*entphysicalmodelname, *sysdesc, dcheck_type, &groupid_, &manufacturerid_, &templateid_);

	if (0 == *groupid)
		*groupid = groupid_;

	if (0 == *manufacturerid)
		*manufacturerid = manufacturerid_;

	if (0 == *templateid)
		*templateid = templateid_;

	zbx_vector_str_clear_ext(&macs_dis, zbx_str_free);
	zbx_vector_str_destroy(&macs_dis);
}


//传入一个json数据 解析出对应字段
static char* make_json_from_value(int result, char *session, 
		zbx_vector_ptr_t *dchecks, zbx_vector_str_t *values)
{
	
	//资产名称 主机描述 mac地址 macs 序列号 模板id os dns
	char *sysname=NULL, *sysdesc=NULL, *ifphysaddress=NULL, *ifphysaddresses=NULL;
	char *entphysicalserialnum=NULL, *entphysicalmodelname=NULL, *os=NULL, *dns=NULL;
	//硬件型号 设备类型id 厂商id 
	int groupid=0, manufacturerid=0, templateid=0; 

	struct zbx_json	json;
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);

	zbx_json_addstring(&json, "response", DISCOVERY_CMD_SINGLE_SCAN, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json, "session", session, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&json, "result", result);
	zbx_json_addarray(&json, "data");
	
	if (DISCOVERY_RESULT_SUCCESS == result)
	{
		for (int i=0; i<values->values_num; i++)
		{
			DB_DCHECK *dcheck = dchecks->values[i];
			discovery_single_parsing_fields(values->values[i],dcheck->type,&sysname,&sysdesc,&ifphysaddress,&ifphysaddresses,
					&entphysicalserialnum,&entphysicalmodelname,&os,&dns,&groupid,&manufacturerid,&templateid);
		}
		
		zbx_json_addobject(&json, NULL);
		zbx_json_addstring(&json, "sysname", sysname, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "sysdesc", sysdesc, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "ifphysaddress", ifphysaddress, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "ifphysaddresses", ifphysaddresses, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "entphysicalserialnum", entphysicalserialnum, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "entphysicalmodelname", entphysicalmodelname, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "os", os, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "dns", dns, ZBX_JSON_TYPE_STRING);
		zbx_json_addint64(&json, "groupid", groupid);
		zbx_json_addint64(&json, "manufacturerid", manufacturerid);
		zbx_json_addint64(&json, "templateid", templateid);
		
	} 
 	zbx_json_close(&json);


	char *sjson = strdup(json.buffer);

	zbx_json_free(&json);
	zbx_free(sysname);
	zbx_free(sysdesc);
	zbx_free(ifphysaddress);
	zbx_free(ifphysaddresses);
	zbx_free(entphysicalserialnum);
	zbx_free(entphysicalmodelname);
	zbx_free(os);
	zbx_free(dns);
 
	return sjson;
}

void* discover_single_thread_function(void* arg) 
{
	int result = DISCOVERY_RESULT_SCAN_FAIL;
	zbx_vector_str_t scan_values;
	zbx_vector_str_create(&scan_values);
	
    struct single_thread_arg *thread_arg = (struct single_thread_arg *)arg;
	char *session = thread_arg->session;
	int socket = thread_arg->socket;
	zbx_vector_ptr_t *dchecks = thread_arg->dchecks; 

	zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#discover_single_thread_function,dcheck_size=%d",dchecks->values_num);
	char *value = NULL;
	for (int i = 0; i < dchecks->values_num; i++)
	{
		int config_timeout = 2;
		size_t value_alloc = 128;
		value = (char *)zbx_malloc(value, value_alloc);

		DB_DCHECK *dcheck = dchecks->values[i];
		zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#discover_service, type=%d,ip=%s,ports=%s",dcheck->type, dcheck->ip,dcheck->ports);

		if(SUCCEED == discover_service(dcheck, dcheck->ip, atoi(dcheck->ports), config_timeout, &value, &value_alloc))
		{
			zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#discover_service success, value=%s", value);
			zbx_vector_str_append(&scan_values, value);
		}else{
			zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#discover_service fail.");
		}
		
	}
	
	if (scan_values.values_num <= 0)
	{
		result = DISCOVERY_RESULT_SCAN_FAIL;
	}else{
		result = DISCOVERY_RESULT_SUCCESS;
	}
	char *response = make_json_from_value(result, session, dchecks, &scan_values);
	discover_response_replay(socket, response);

	zbx_vector_str_clear_ext(&scan_values, zbx_str_free);
	zbx_vector_str_destroy(&scan_values);

} 
int	discover_single_scan(int socket, char *session, const struct zbx_json_parse *jp, char **response)
{
	
	pthread_t ds_thread;
	struct single_thread_arg thread_arg;
	
	zbx_vector_ptr_t dchecks;
	zbx_vector_ptr_create(&dchecks);

	int result = FAIL; 
	
	zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS# begin session:%s", session);

	if (SUCCEED != (result = make_dechecks_from_json(jp, &dchecks)))
	{
		*response = make_json_from_value(result, session, &dchecks, NULL);
		goto out;
	}
	
	zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#make_dechecks_from_json ret=%d",result);	

	thread_arg.session = session;
	thread_arg.dchecks = &dchecks;
	thread_arg.socket = socket;
 
	if (pthread_create(&ds_thread, NULL, discover_single_thread_function, &thread_arg))
	{
		zabbix_log(LOG_LEVEL_ERR, "#ZOPS#discover_single_scan. create thread fail.");
		return FAIL;
	}
	if (pthread_join(ds_thread, NULL))
	{
		zabbix_log(LOG_LEVEL_ERR, "#ZOPS#discover_single_scan. join thread fail");
	}
 
out:
	zbx_vector_ptr_clear_ext(&dchecks, (zbx_clean_func_t)DB_dcheck_free);
	zbx_vector_ptr_destroy(&dchecks);

	return result;
	
}

// static void	discoverer_single_scan_func_test(zbx_vector_ptr_t *dchecks, char **ip)
// {
// 	DB_DCHECK *dcheck;
// 	dcheck = (DB_DCHECK *)zbx_malloc(NULL, sizeof(DB_DCHECK));
// 	memset(dcheck, 0, sizeof(DB_DCHECK));
// 	dcheck->ports=zbx_strdup(NULL,"161");
// 	dcheck->key_=zbx_strdup(NULL,"discovery[{#SYSNAME},1.3.6.1.2.1.1.5,{#SYSDESC},1.3.6.1.2.1.1.1,{#ENTPHYSICALSERIALNUM},1.3.6.1.2.1.47.1.1.1.1.11,{#IFPHYSADDRESS},1.3.6.1.2.1.2.2.1.6,{#ENTPHYSICALMODELNAME},1.3.6.1.2.1.47.1.1.1.1.13]");
// 	dcheck->snmp_community=zbx_strdup(NULL,"{$SNMP_COMMUNITY}");
// 	dcheck->snmpv3_securityname=zbx_strdup(NULL,"");
// 	dcheck->snmpv3_authpassphrase=zbx_strdup(NULL,"");
// 	dcheck->snmpv3_privpassphrase=zbx_strdup(NULL,"");
// 	dcheck->snmpv3_contextname=zbx_strdup(NULL,"");
// 	dcheck->type=11;
// 	dcheck->snmpv3_securitylevel=0;
// 	dcheck->snmpv3_authprotocol=0;
// 	dcheck->snmpv3_privprotocol=0;
// 	dcheck->houseid=0;
// 	zbx_vector_ptr_append(dchecks, dcheck);

// 	/*
// 	dcheck = (DB_DCHECK *)zbx_malloc(NULL, sizeof(DB_DCHECK));
// 	memset(dcheck, 0, sizeof(DB_DCHECK));
// 	dcheck->ports=zbx_strdup(NULL,"10050");
// 	dcheck->key_=zbx_strdup(NULL,"get_discover_value");
// 	dcheck->snmp_community=zbx_strdup(NULL,"");
// 	dcheck->snmpv3_securityname=zbx_strdup(NULL,"");
// 	dcheck->snmpv3_authpassphrase=zbx_strdup(NULL,"");
// 	dcheck->snmpv3_privpassphrase=zbx_strdup(NULL,"");
// 	dcheck->snmpv3_contextname=zbx_strdup(NULL,"");
// 	dcheck->type=9;
// 	dcheck->snmpv3_securitylevel=0;
// 	dcheck->snmpv3_authprotocol=0;
// 	dcheck->snmpv3_privprotocol=0;
// 	dcheck->houseid=0;
// 	zbx_vector_ptr_append(dchecks, dcheck);
// 	*/

// 	*ip=zbx_strdup(NULL,"192.168.31.19");
// }
 
// static void	*discoverer_worker_entry(void *args)
// {

//     zbx_discoverer_worker_t	*worker = (zbx_discoverer_worker_t *)args;

//     zbx_ipc_socket_t	worker_socket;
// 	zbx_ipc_message_t	message;
// 	char			*error = NULL;

//     if (FAIL == zbx_ipc_socket_open(&worker_socket, ZBX_IPC_SERVICE_DISCOVERER, SEC_PER_MIN, &error))
// 	{
// 		zabbix_log(LOG_LEVEL_CRIT, "worker cannot connect to discoverer manager service: %s", error);
// 		return NULL;
// 	}
    
// 	pthread_t thread = pthread_self();
//     zbx_ipc_socket_write(&worker_socket, ZBX_IPC_DISCOVERER_WORKER_REGISTER, (unsigned char *)&thread, sizeof(thread));

// 	while (1)
// 	{
//         //阻塞
// 		if (SUCCEED != zbx_ipc_socket_read(&worker_socket, &message))
// 		{
// 			zabbix_log(LOG_LEVEL_CRIT, "worker cannot read discoverer manager service request");
// 			break;
// 		}

// 		switch (message.code)
// 		{
// 			case ZBX_IPC_DISCOVERER_SINGLE_SCAN:
// 				discover_single_scan(&worker_socket, &message);
// 				break;
// 		}
// 	}
// }


// int discoverer_workers_init(zbx_discoverer_worker_t *workers, int num)
// {
// 	int err;
// 	for (int i = 0; i < num; i++)
// 	{
// 		zbx_discoverer_worker_t *worker = &workers[i];
// 		if (0 != (err = pthread_create(&worker->thread, NULL, discoverer_worker_entry, (void *)worker)))
// 		{
// 			zabbix_log(LOG_LEVEL_CRIT, "cannot create discoverer manager thread: %s", zbx_strerror(err));
// 			return FAIL;
// 		}
// 	}

// 	return SUCCEED;
// }


