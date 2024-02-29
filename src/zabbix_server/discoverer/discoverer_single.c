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
	int ret = DISCOVERY_RESULT_SUCCESS;

	struct zbx_json_parse jp_params;
	if (SUCCEED != zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &jp_params))
	{
		return DISCOVERY_RESULT_JSON_PARSE_FAIL;
	}

	int valuesize = 16;
	char int_value[valuesize];
	char *ip = NULL, *credentialid = NULL;
	size_t ip_size=0, credentialid_size=0;  // 每次循环读取数据，必须重新初始化为0，否则会crash
	int houseid = 0, managerid = 0;
	
	// zbx_json_value_by_name_dyn 方法会自动malloc内存，所以可以传空指针进去
	if (SUCCEED != zbx_json_value_by_name_dyn(&jp_params, "ip", &ip, &ip_size, NULL))
		return DISCOVERY_RESULT_JSON_PARSE_FAIL;
	 
	if (SUCCEED == zbx_json_value_by_name(&jp_params, "houseid", int_value, sizeof(int_value), NULL))
	{
		zbx_lrtrim(int_value, ZBX_WHITESPACE);
		houseid = (unsigned char)zbx_atoi(int_value);
		memset(int_value, 0 , valuesize);
	} 
	if (SUCCEED == zbx_json_value_by_name(&jp_params, "managerid", int_value, sizeof(int_value), NULL))
	{
		zbx_lrtrim(int_value, ZBX_WHITESPACE);
		managerid = (unsigned char)zbx_atoi(int_value);
		memset(int_value, 0 , valuesize);
	} 

	if (SUCCEED == zbx_json_value_by_name_dyn(&jp_params, "credentialid", &credentialid, &credentialid_size, NULL))
	{ 
		zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s ip=%s, houseid=%d, managerid=%d, credentialid=%s", 
			__func__, ip, houseid, managerid, credentialid);

		DB_RESULT	result;
		DB_ROW		row;
		char		sql[MAX_STRING_LEN];
		size_t		offset = 0;

		offset += zbx_snprintf(sql + offset, sizeof(sql) - offset,
						"SELECT id,type,PORT, USER, PASSWORD, snmpv3_securitylevel, " \
						"snmpv3_authpassphrase, snmpv3_privpassphrase, snmpv3_authprotocol, snmpv3_privprotocol " \
						"FROM  credentials " \
						" WHERE id in(%s", credentialid); 
		zbx_snprintf(sql + offset, sizeof(sql) - offset, ")"); 
		result = zbx_db_select("%s", sql);

		while (NULL != (row = zbx_db_fetch(result)))
		{
			
			int k = 0;
			DB_DCHECK *dcheck = (DB_DCHECK *)zbx_malloc(NULL, sizeof(DB_DCHECK));
			memset(dcheck, 0, sizeof(DB_DCHECK)); //必须对dcheck初始化，否则会crash
			
			ret = DISCOVERY_RESULT_SUCCESS;

			dcheck->credentialid = zbx_atoi(row[k++]);
			char *type = row[k++];
			if(zbx_strncasecmp(type, "SNMPv1/v2", strlen("SNMPv1/v2")) == 0)
			{
				dcheck->type = SVC_SNMPv2c;
				dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_SNMP_KEY);
			}
			else if(zbx_strncasecmp(type, "SNMPv3", strlen("SNMPv3")) == 0)
			{
				dcheck->type = SVC_SNMPv3;
				dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_SNMP_KEY);
			}
			else if(zbx_strncasecmp(type, "Agent", strlen("Agent")) == 0)
			{
				dcheck->type = SVC_AGENT;
				dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_AGENT_KEY);
			} 
			else if(zbx_strncasecmp(type, "IPMI", strlen("IPMI")) == 0)
			{
				dcheck->type = SVC_AGENT;
				dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_AGENT_KEY);
			} 
			else
			{
				ret = DISCOVERY_RESULT_CREDENTIAL_FAIL;
			}

			if(ret == DISCOVERY_RESULT_SUCCESS)
			{
				zbx_vector_ptr_append(dchecks, dcheck);
				dcheck->ip = zbx_strdup(NULL, ip);
				dcheck->ports = zbx_strdup(NULL, row[k++]);
				dcheck->user = zbx_strdup(NULL, row[k++]);
				dcheck->password = zbx_strdup(NULL, row[k++]);
				dcheck->snmp_community = zbx_strdup(NULL, dcheck->password);
				dcheck->snmpv3_securityname = zbx_strdup(NULL, dcheck->user);
				dcheck->snmpv3_contextname = zbx_strdup(NULL, dcheck->password);

				dcheck->snmpv3_securitylevel = (unsigned char)zbx_atoi(row[k++]);
				dcheck->snmpv3_authpassphrase = zbx_strdup(NULL, row[k++]);
				dcheck->snmpv3_privpassphrase = zbx_strdup(NULL, row[k++]);
				dcheck->snmpv3_authprotocol = (unsigned char)zbx_atoi(row[k++]);
				dcheck->snmpv3_privprotocol = (unsigned char)zbx_atoi(row[k++]);
				dcheck->houseid = houseid;
				dcheck->managerid = managerid;
			}else{
				zbx_free(dcheck);
				break;
			}
		}
		zbx_db_free_result(result);
		
	}else{
		ret = DISCOVERY_RESULT_JSON_PARSE_FAIL;
	}
	
	zbx_free(ip);
	zbx_free(credentialid);
	return ret;
}


static int	discovery_single_parsing_fields(const char *value, const int dcheck_type, char **sysname, char **sysdesc,char **ifphysaddress,char **ifphysaddresses, 
		char **entphysicalserial, char **entphysicalmodel, char **os, char **dns, int *groupid, char **manufacturer, int *templateid)
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
	}

	char *ifphysaddresses_=NULL;
	vector_to_str_max(&macs_dis, &ifphysaddresses_, "/", MAX_MACADDRESS_NUM);
	if (NULL == *ifphysaddresses || 0==zbx_strcmp_natural(*ifphysaddresses, ""))
	{
		zbx_free(*ifphysaddresses);
		*ifphysaddresses = ifphysaddresses_;
	}
		
	if (NULL == *entphysicalserial || 0==zbx_strcmp_natural(*entphysicalserial, ""))
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM,entphysicalserial);

	if (NULL == *entphysicalmodel || 0==zbx_strcmp_natural(*entphysicalmodel, ""))
		discovery_parsing_value(value,ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME,entphysicalmodel);

	if (NULL == *os || 0==zbx_strcmp_natural(*os, ""))
		discovery_parsing_value_os(*sysdesc, os);
	 
	int groupid_, manufacturerid_, templateid_;
	discovery_parsing_value_model(*entphysicalmodel, *sysdesc, dcheck_type, &groupid_, &manufacturer, &templateid_);

	if (0 == *groupid)
		*groupid = groupid_;
 
	if (0 == *templateid)
		*templateid = templateid_;

	zbx_vector_str_clear_ext(&macs_dis, zbx_str_free);
	zbx_vector_str_destroy(&macs_dis);
}


//传入一个json数据 解析出对应字段
static char* make_json_from_value(int result, char *session, 
		zbx_vector_ptr_t *dchecks, zbx_vector_str_t *values, DB_HOST_INVENTORY *inventory)
{
	
	//资产名称 主机描述 mac地址 macs 序列号 模板id os dns
	char *sysname=NULL, *sysdesc=NULL, *manufacturer=NULL, *ifphysaddress=NULL, *ifphysaddresses=NULL;
	char *entphysicalserial=NULL, *entphysicalmodel=NULL, *os=NULL, *dns=NULL;

	//硬件型号 设备类型id 厂商id 
	int groupid=0, templateid=0; 

	struct zbx_json	json;
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);

	zbx_json_addstring(&json, "response", DISCOVERY_CMD_SINGLE_SCAN, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json, "session", session, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&json, "result", result);
	zbx_json_addarray(&json, "data");
	
	if (DISCOVERY_RESULT_SUCCESS == result)
	{
		int managerid = 0, houseid = 0, dunique_type = DUNIQUE_TYPE_UNKNOW;
		char *ip = NULL, *dunique = NULL;
		for (int i=0; i<values->values_num; i++)
		{
			DB_DCHECK *dcheck = dchecks->values[i];
			managerid = dcheck->managerid;
			houseid = dcheck->houseid;
			ip = dcheck->ip;

			discovery_single_parsing_fields(values->values[i],dcheck->type,&sysname,&sysdesc,&ifphysaddress,&ifphysaddresses,
					&entphysicalserial,&entphysicalmodel,&os,&dns,&groupid,&manufacturer,&templateid);
		}
		
		zbx_json_addobject(&json, NULL);

		sysname = get_str_field(sysname);
		sysdesc = get_str_field(sysdesc);
		ifphysaddress = get_str_field(ifphysaddress);
		ifphysaddresses = get_str_field(ifphysaddresses);
		entphysicalserial = get_str_field(entphysicalserial);
		entphysicalmodel=get_str_field(entphysicalmodel);
		os = get_str_field(os);
		dns = get_str_field(dns);
		manufacturer = get_str_field(manufacturer);

		if(ifphysaddresses != NULL && strlen(ifphysaddresses) > 5)
		{
			dunique_type = DUNIQUE_TYPE_MACS;
			dunique = ifphysaddresses;
			zbx_json_addstring(&json, "dunique", ifphysaddresses, ZBX_JSON_TYPE_STRING);
		}
		else if(entphysicalserial != NULL && strlen(entphysicalserial) > 5)
		{
			dunique_type = DUNIQUE_TYPE_DEFAULT;
			dunique = entphysicalserial;
			zbx_json_addstring(&json, "dunique", entphysicalserial, ZBX_JSON_TYPE_STRING);
		}
		else if(ip != NULL && strlen(ip) > 5)
		{
			dunique_type = DUNIQUE_TYPE_IP;
			dunique = ip;
			zbx_json_addstring(&json, "dunique", ip, ZBX_JSON_TYPE_STRING);
		}
		zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS%s dunique_type=%d, dunique=%s", __func__, dunique_type, dunique);
	

		zbx_json_addstring(&json, "sysname", sysname, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "sysdesc", sysdesc, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "ifphysaddress", ifphysaddress, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "ifphysaddresses", ifphysaddresses, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "entphysicalserial", entphysicalserial, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "entphysicalmodel", entphysicalmodel, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "os", os, ZBX_JSON_TYPE_STRING);
		zbx_json_addstring(&json, "dns", dns, ZBX_JSON_TYPE_STRING);
		zbx_json_addint64(&json, "groupid", groupid);
		zbx_json_addstring(&json, "manufacturer", manufacturer, ZBX_JSON_TYPE_STRING);
		zbx_json_addint64(&json, "templateid", templateid);
		

		if(inventory != NULL)
		{
			inventory->dunique_type = dunique_type;
			inventory->dunique = zbx_strdup(NULL, dunique);
			inventory->name = zbx_strdup(NULL, sysname);
			inventory->description = zbx_strdup(NULL, sysdesc);
			inventory->manufacturer = zbx_strdup(NULL, manufacturer);
			inventory->physical_serial = zbx_strdup(NULL, entphysicalserial);
			inventory->physical_model = zbx_strdup(NULL, entphysicalmodel);
			inventory->os_short = zbx_strdup(NULL, os);
			inventory->groupid = groupid;
			inventory->houseid = houseid;
			inventory->managerid = managerid;
		}
		dunique = NULL;
		
	} 

	zbx_free(dns);
	zbx_free(ifphysaddress);
	zbx_free(sysname);
	zbx_free(sysdesc);
	zbx_free(manufacturer);
	zbx_free(ifphysaddresses);
	zbx_free(entphysicalserial);
	zbx_free(entphysicalmodel);
	zbx_free(os);
	
 	zbx_json_close(&json);
	char *sjson = strdup(json.buffer);
	zbx_json_free(&json);
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

	zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#%s,dcheck_size=%d",__func__, dchecks->values_num);
	char *value = NULL;
	for (int i = 0; i < dchecks->values_num; i++)
	{
		int config_timeout = 2;
		size_t value_alloc = 128;
		value = (char *)zbx_malloc(value, value_alloc);

		DB_DCHECK *dcheck = dchecks->values[i];
		zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#%s, type=%d,ip=%s,ports=%s",
			__func__,dcheck->type, dcheck->ip,dcheck->ports);

		if(SUCCEED == discover_service(NULL, dcheck, dcheck->ip, atoi(dcheck->ports), config_timeout, &value, &value_alloc))
		{
			zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#%s success, value=%s", __func__, value);
			zbx_vector_str_append(&scan_values, value);
		}else{
			zabbix_log(LOG_LEVEL_DEBUG,"#ZOPS#%s discover service fail.",__func__);
		}
	}
	
	if (scan_values.values_num <= 0)
	{
		result = DISCOVERY_RESULT_SCAN_FAIL;
	}else{
		result = DISCOVERY_RESULT_SUCCESS;
	}
	DB_HOST_INVENTORY inventory;
	memset(&inventory, 0, sizeof(DB_HOST_INVENTORY));
	char *response = make_json_from_value(result, session, dchecks, &scan_values, &inventory);

	// 更新资产信息
	if(NULL != inventory.dunique && strlen(inventory.dunique) > 0)
	{
		discovery_register_host_inventory(&inventory);
	}	
	
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
		*response = make_json_from_value(result, session, &dchecks, NULL, NULL);
		goto out;
	}
	
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


