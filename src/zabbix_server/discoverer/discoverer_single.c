#include "discoverer.h"
#include "discoverer_protocol.h"
#include "discoverer_manager.h"
#include "zbxdiscovery.h"
#include "user_discoverer.h"
#include "discoverer_single.h"
#include "zbxserver.h"
#include "zbx_host_constants.h"
#include "zbxsysinfo.h"
#include "../poller/checks_db.h"
#include "zbxhttp.h"
#include "discoverer_kubernetes.h"
#include "discoverer_comm.h"

extern int g_running_program_type;


static int get_result_by_values(DB_DCHECK *dcheck, char *value)
{
	int result = DISCOVERY_RESULT_SCAN_FAIL;
	regex_t regex;
	regmatch_t match;
	switch (dcheck->devicetype)
	{
	case DEVICE_TYPE_APACHE:
		if (zbx_strncasecmp(value, dcheck->ip, strlen(dcheck->ip)) == 0)
			result = DISCOVERY_RESULT_SUCCESS;
		break;
	case DEVICE_TYPE_RABBITMQ_CLUSTER:
		if (zbx_strncasecmp(value, "{\"management_version\"", 21) == 0)
			result = DISCOVERY_RESULT_SUCCESS;
		break;
	case DEVICE_TYPE_RABBITMQ_NODE:
		if (zbx_strncasecmp(value, "{\"memory\"", 9) == 0)
			result = DISCOVERY_RESULT_SUCCESS;
		break;
	case DEVICE_TYPE_NGINX:
		if (zbx_strncasecmp(value, "Active connections:", 19) == 0)
			result = DISCOVERY_RESULT_SUCCESS;
		break;
	case DEVICE_TYPE_TOMCAT:
		if (zbx_strncasecmp(value, "Apache Tomcat", 13) == 0)
			result = DISCOVERY_RESULT_SUCCESS;
		break;
	case DEVICE_TYPE_KAFKA:
		// 判断是否返回版本号
    	regcomp(&regex, "^([0-9])+(.([0-9])+){0,6}", REG_EXTENDED);
    	if (SUCCEED == regexec(&regex, value, 1, &match, 0))  
			result = DISCOVERY_RESULT_SUCCESS;
		regfree(&regex);
		break;
	case DEVICE_TYPE_IIS:
		// 判断是否返回数字
		regcomp(&regex, "^([0-9])+(.([0-9])+)", REG_EXTENDED);
    	if (SUCCEED == regexec(&regex, value, 1, &match, 0))  
			result = DISCOVERY_RESULT_SUCCESS;
		regfree(&regex);
		break;
	case DEVICE_TYPE_PROCESS:
		if (strstr(value, dcheck->path) != NULL)
			result = DISCOVERY_RESULT_SUCCESS;
		// [{"name":"nginx","processes":13,"vsize":1991778304,"pmem":1.189498,"rss":99254272,"data":36151296,"exe":13950976,"lck":0,"lib":266747904,"pin":0,"pte":3457024,"size":51859456,"stk":1757184,"swap":8318976,"cputime_user":4.860000,"cputime_system":8.040000,"ctx_switches":75525,"threads":13,"page_faults":1}]
		break;
	case DEVICE_TYPE_DOCKER:
		if (strstr(value, "\"Id\"") != NULL)
			result = DISCOVERY_RESULT_SUCCESS;
		break;
	case DEVICE_TYPE_REDIS: 	
		if (strlen(value) && strstr(value,"redis_version")) {
			result = DISCOVERY_RESULT_SUCCESS;
		}		
		break;		
	case DEVICE_TYPE_MEMCACHED: 	
		if (strlen(value) && strstr(value,"version")) {
			result = DISCOVERY_RESULT_SUCCESS;
		}
		break;	
	case DEVICE_TYPE_KUBERNETES: 	
		if (strlen(value) && strstr(value,"ping ok")) {
			result = DISCOVERY_RESULT_SUCCESS;
		}
		break;	
	case DEVICE_TYPE_MYSQL:
	case DEVICE_TYPE_MSSQL:
	case DEVICE_TYPE_ORACLE:
	case DEVICE_TYPE_PING:
	default:
		result = DISCOVERY_RESULT_SUCCESS;
		break;
	}
	return result;
}

static int parse_json_get_credentials(zbx_vector_ptr_t *dchecks, char *credentialid, int proxy_hostid, int devicetype, 
	char *ip, char *port, char *name, char *path, char *database, int houseid, int managerid)
{		
	int ret = DISCOVERY_RESULT_CREDENTIAL_FAIL;
	DB_RESULT	result;
	DB_ROW		row;
	char		sql[MAX_STRING_LEN];
	size_t		offset = 0;
	DB_DCHECK *dcheck = NULL;

	offset += zbx_snprintf(sql + offset, sizeof(sql) - offset,
					"SELECT id,type,PORT, USER, PASSWORD, snmpv3_securitylevel, " \
					"snmpv3_authpassphrase, snmpv3_privpassphrase, snmpv3_authprotocol, snmpv3_privprotocol, " \
					"ssh_privprotocol,ssh_privatekey FROM  credentials " \
					" WHERE id in(%s", credentialid); 
	zbx_snprintf(sql + offset, sizeof(sql) - offset, ")"); 
	result = zbx_db_select("%s", sql);

	while (NULL != (row = zbx_db_fetch(result)))
	{
		
		int k = 0;
		const int user_id = 3;
		const int passwd_id = 4;
		dcheck = (DB_DCHECK *)zbx_malloc(NULL, sizeof(DB_DCHECK));
		memset(dcheck, 0, sizeof(DB_DCHECK)); //必须对dcheck初始化，否则会crash
		dcheck->result = FAIL;

		ret = DISCOVERY_RESULT_SUCCESS;

		dcheck->proxy_hostid = proxy_hostid;
		dcheck->credentialid = zbx_atoi(row[k++]);
		char *type = row[k++];
		if(zbx_strcasecmp(type, "SNMPv1/v2") == 0)
		{
			dcheck->type = SVC_SNMPv2c;
			dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_SNMP_KEY);
		}
		else if(zbx_strcasecmp(type, "SNMPv3") == 0)
		{
			dcheck->type = SVC_SNMPv3;
			dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_SNMP_KEY);
		}
		else if(zbx_strcasecmp(type, "Agent") == 0)
		{
			char keyvalue[256];
			dcheck->type = SVC_AGENT;
			switch (devicetype)
			{
			case DEVICE_TYPE_IIS:
				dcheck->key_ = zbx_strdup(NULL, "perf_counter_en[\"\\Web Service(_Total)\\Service Uptime\"]");
				break;
			case DEVICE_TYPE_PROCESS:
				zbx_snprintf(keyvalue, sizeof(keyvalue), "proc.get[%s,,,summary]",path);
				dcheck->key_ = zbx_strdup(NULL, keyvalue);
				break;
			case DEVICE_TYPE_DOCKER:
				dcheck->key_ = zbx_strdup(NULL, "docker.info");
				break;
			case DEVICE_TYPE_REDIS:	
				zbx_snprintf(keyvalue, sizeof(keyvalue), "redis.info[tcp://%s]",path);
				dcheck->key_ = zbx_strdup(NULL, keyvalue);					
				break;
			case DEVICE_TYPE_MEMCACHED:		
				zbx_snprintf(keyvalue, sizeof(keyvalue), "memcached.stats[tcp://%s]",path);
				dcheck->key_ = zbx_strdup(NULL, keyvalue);			
				break;
			default:
				dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_AGENT_KEY);
				break;
			}
		} 
		else if(zbx_strcasecmp(type, "IPMI") == 0)
		{
			dcheck->type = SVC_IPMI;
			dcheck->key_ = zbx_strdup(NULL, SNMP_DEFAULT_AGENT_KEY);
		} 
		else if(zbx_strcasecmp(type, "Http") == 0 || zbx_strcasecmp(type, "Https") == 0)
		{
			if(zbx_strcasecmp(type, "Http") == 0)
				dcheck->type = SVC_HTTP;
			else
				dcheck->type = SVC_HTTPS; 
			
			dcheck->key_ = zbx_strdup(NULL, "");
			switch (devicetype)
			{
			case DEVICE_TYPE_RABBITMQ_CLUSTER:
				dcheck->key_ = zbx_strdup(dcheck->key_, "rabbitmq.get_overview");
				path = zbx_strdup(path, "api/overview");
				break;
			case DEVICE_TYPE_RABBITMQ_NODE:  //path 为节点名称，H5传过来的值
				dcheck->key_ = zbx_strdup(dcheck->key_, "rabbitmq.get_nodes");
				break;
			case DEVICE_TYPE_KUBERNETES:  //k8s 集群扫描
				dcheck->key_ = zbx_strdup(dcheck->key_, "kube.livez");
				break;
			default:
				break;
			}
			
		} 
		else if(zbx_strcasecmp(type, "JMX") == 0)
		{
			dcheck->type = SVC_JMX;
			
			switch (devicetype)
			{
			case DEVICE_TYPE_TOMCAT:
				dcheck->key_ = zbx_strdup(NULL, "jmx[\"Catalina:type=Server\",serverInfo]");
				break;
			case DEVICE_TYPE_KAFKA:
				dcheck->key_ = zbx_strdup(NULL, "jmx[\"kafka.server:type=app-info\",\"version\"]");
			default:
				break;
			}
		}
		else if(zbx_strcasecmp(type, "Ping") == 0)
		{
			dcheck->type = SVC_ICMPPING;
			dcheck->key_ = zbx_strdup(NULL, "");
		}
		else if(zbx_strcasecmp(type, "Nutanix") == 0)
		{ 
			dcheck->type = SVC_NUTANIX;
			dcheck->key_ = zbx_strdup(NULL, "");
		}
		else if(zbx_strcasecmp(type, "ODBC") == 0)
		{
			dcheck->type = SVC_ODBC;
			char dcheck_key[MAX_STRING_LEN];
			char dsn_name[MAX_STRING_LEN];
			char driver[MAX_STRING_LEN];

			// DSN 名称使用 ip + port + credentialid 校验唯一性
			if( DEVICE_TYPE_ORACLE != devicetype)
			{
				const char *devicetype_str = (devicetype == DEVICE_TYPE_MYSQL) ? "MySQL" : "MSSQL";
				zbx_snprintf(dsn_name, sizeof(dsn_name), "%s-%s-%s-%d",devicetype_str, ip,port, dcheck->credentialid);
				dcheck->dsn_name = zbx_strdup(NULL, dsn_name);
			}

			switch (devicetype)
			{
			case DEVICE_TYPE_MYSQL:
				zbx_snprintf(dcheck_key, sizeof(dcheck_key), "db.odbc.select[ping,\"%s\"]",dsn_name);
				dcheck->key_ = zbx_strdup(NULL, dcheck_key);
				dcheck->params = zbx_strdup(NULL, "select \"1\"");
				dcheck->driver = zbx_strdup(NULL, MYSQL_DRIVER);
				break;
			case DEVICE_TYPE_ORACLE:
				zbx_snprintf(dcheck_key, sizeof(dcheck_key), "db.odbc.get[ping,,\"Driver=%s;DBQ=//%s:%s/%s;\"]",ORACLE_DRIVER, ip, port,database);
				dcheck->key_ = zbx_strdup(NULL, dcheck_key);
				dcheck->params = zbx_strdup(NULL, "SELECT \
													decode(status,'STARTED',1,'MOUNTED',1,'OPEN',1,'OPEN MIGRATE',1, 0) AS STATUS \
													FROM v$instance;");
				dcheck->driver = zbx_strdup(NULL, ORACLE_DRIVER);
				break;
			case DEVICE_TYPE_MSSQL:
				zbx_snprintf(dcheck_key, sizeof(dcheck_key), "db.odbc.select[dbname,\"%s\"]",dsn_name);
				dcheck->key_ = zbx_strdup(NULL, dcheck_key);
				dcheck->params = zbx_strdup(NULL, "SELECT object_name\
													FROM sys.dm_os_performance_counters\
													WHERE [object_name] LIKE '%Buffer Manager%'\
													AND [counter_name] = 'Page life expectancy'");
				dcheck->driver = zbx_strdup(NULL, MSSQL_DRIVER);
				break;
			case DEVICE_TYPE_POSTGRE:
				zbx_snprintf(driver, sizeof(driver), "Servername=%s;Port=%s;Driver=%s",ip, port, POSTGRESQL_DRIVER);
				zbx_snprintf(dcheck_key, sizeof(dcheck_key), "db.odbc.select[pgsql.ping,,\"Database=%s;%s\"]",database, driver);
				dcheck->key_ = zbx_strdup(NULL, dcheck_key);
				dcheck->params = zbx_strdup(NULL, "SELECT 1");
				dcheck->driver = zbx_strdup(NULL, driver);
				break;
			case DEVICE_TYPE_MONGODB:
			case DEVICE_TYPE_MONGODB_CLUSTER:
				// ip 端口 账号 密码
				zbx_snprintf(driver, sizeof(driver), "tcp://%s:%s",ip, port);
				zbx_snprintf(dcheck_key, sizeof(dcheck_key), "mongodb.server.status[\"%s\",\"%s\",\"%s\"]", driver, row[user_id], row[passwd_id]);
				dcheck->key_ = zbx_strdup(NULL, dcheck_key);
				dcheck->type = SVC_AGENT;
				break;
			case DEVICE_TYPE_HANA:
				zbx_snprintf(dcheck_key, sizeof(dcheck_key), "db.odbc.get[ping,,\"DRIVER=%s;SERVERNODE=%s:%s;DATABASENAME=%s;\"]", SAPHANA_DRIVER, ip, port, database);
				dcheck->key_ = zbx_strdup(NULL, dcheck_key);
				dcheck->params = zbx_strdup(NULL, "SELECT 1 FROM DUMMY;");
				dcheck->driver = zbx_strdup(NULL, SAPHANA_DRIVER);
				break;
			default:
				break;
			}
		}
		else
		{
			ret = DISCOVERY_RESULT_CREDENTIAL_FAIL;
		}

		if(ret == DISCOVERY_RESULT_SUCCESS)
		{
			zbx_vector_ptr_append(dchecks, dcheck);
			if(NULL == port || strlen(port) == 0){
				dcheck->ports = zbx_strdup(NULL, row[k++]);
			}
			else
			{
				k++;

				if (devicetype == DEVICE_TYPE_MONGODB || devicetype == DEVICE_TYPE_MONGODB_CLUSTER)
					dcheck->ports = zbx_strdup(NULL, ZBX_DEFAULT_AGENT_PORT_STR);
				else
					dcheck->ports = zbx_strdup(NULL, port);
			}
			
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

			dcheck->ssh_privprotocol = zbx_atoi(row[k++]);
			dcheck->ssh_privatekey = zbx_strdup(NULL, row[k++]);
			
			dcheck->ip = zbx_strdup(NULL, ip);
			dcheck->name = zbx_strdup(NULL, name);
			dcheck->path = zbx_strdup(NULL, path);
			dcheck->database = zbx_strdup(NULL,database);
			dcheck->houseid = houseid;
			dcheck->managerid = managerid;
			dcheck->devicetype = devicetype;
		}else{
			zbx_free(dcheck);
			break;
		}
	}
	zbx_db_free_result(result);
	return ret;
	
}

static int parse_proxy_resp_to_dechecks(struct zbx_json_parse *jp_params, zbx_vector_ptr_t *dchecks)
{
	struct zbx_json_parse jp_poxy, jp_poxy_data;
	int icredentialid = 0, iresult = 0, valuesize = 16;
	size_t value_alloc = MAX_STRING_LEN;
	char *value, int_value[valuesize];
	const char		*p = NULL;
	DB_DCHECK *dcheck = NULL;

	if (SUCCEED == zbx_json_brackets_by_name(jp_params, PROXY_DISCOVERY_RULES_RESP, &jp_poxy))
	{
		while (NULL != (p = zbx_json_next(&jp_poxy, p)))
		{
			if (SUCCEED != zbx_json_brackets_open(p, &jp_poxy_data))
				break;
			icredentialid = 0, iresult = FAIL;
			if (SUCCEED == zbx_json_value_by_name(&jp_poxy_data, "credentialid", int_value, sizeof(int_value), NULL))
			{
				zbx_lrtrim(int_value, ZBX_WHITESPACE);
				icredentialid = zbx_atoi(int_value);
				memset(int_value, 0 , valuesize);
			}
			if (SUCCEED == zbx_json_value_by_name(&jp_poxy_data, "result", int_value, sizeof(int_value), NULL))
			{
				zbx_lrtrim(int_value, ZBX_WHITESPACE);
				iresult = zbx_atoi(int_value);
			}
			
			for(int i = 0 ; i < dchecks->values_num; i ++)
			{
				dcheck = dchecks->values[i];
				if(dcheck->credentialid == icredentialid)
				{
					dcheck->result = iresult;
					value = (char *)zbx_malloc(NULL, value_alloc);
					memset(value, 0 , value_alloc);
					if (SUCCEED == zbx_json_value_by_name_dyn(&jp_poxy_data, "value", &value, &value_alloc, NULL))
					{
						dcheck->resp_value = zbx_strdup(NULL,value);
					} 
					zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s credentialid=%d,result=%d,value=%s", 
						__func__, dcheck->credentialid, dcheck->result, print_content(dcheck->resp_value));
					zbx_free(value);
				}
			}
		}
		
	}
}

//把json数据 解析到DB_DCHECK结构对象
static int	parse_json_to_dechecks(const struct zbx_json_parse *jp, zbx_vector_ptr_t *dchecks, int proxy_hostid)
{
	int ret = DISCOVERY_RESULT_SUCCESS;
	int valuesize = 16;
	char int_value[valuesize];
	struct zbx_json_parse jp_params;
	DB_DCHECK *dcheck = NULL;

	if (SUCCEED != zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &jp_params))
	{
		return DISCOVERY_RESULT_JSON_PARSE_FAIL;
	}

	char *ip = NULL, *port = NULL, *credentialid = NULL, *name = NULL, *path = NULL, *database = NULL;
	size_t ip_size=0, port_size=0, credentialid_size=0, name_size=0, path_size=0, database_size = 0;  // 每次循环读取数据，必须重新初始化为0，否则会crash
	int  houseid = 0, managerid = 0, devicetype = 0;		
	
	// zbx_json_value_by_name_dyn 方法会自动malloc内存，所以可以传空指针进去
	if (SUCCEED != zbx_json_value_by_name_dyn(&jp_params, "ip", &ip, &ip_size, NULL))
		return DISCOVERY_RESULT_JSON_PARSE_FAIL;

	zbx_json_value_by_name_dyn(&jp_params, "port", &port, &port_size, NULL);
	zbx_json_value_by_name_dyn(&jp_params, "name", &name, &name_size, NULL);
	zbx_json_value_by_name_dyn(&jp_params, "path", &path, &path_size, NULL);
	zbx_json_value_by_name_dyn(&jp_params, "database", &database, &database_size, NULL);

	if (SUCCEED == zbx_json_value_by_name(&jp_params, "houseid", int_value, sizeof(int_value), NULL))
	{
		zbx_lrtrim(int_value, ZBX_WHITESPACE);
		houseid = zbx_atoi(int_value);
		memset(int_value, 0 , valuesize);
	} 
	if (SUCCEED == zbx_json_value_by_name(&jp_params, "managerid", int_value, sizeof(int_value), NULL))
	{
		zbx_lrtrim(int_value, ZBX_WHITESPACE);
		managerid = zbx_atoi(int_value);
		memset(int_value, 0 , valuesize);
	} 

	if (SUCCEED == zbx_json_value_by_name(&jp_params, "devicetype", int_value, sizeof(int_value), NULL))
	{
		zbx_lrtrim(int_value, ZBX_WHITESPACE);
		devicetype = zbx_atoi(int_value);
		memset(int_value, 0 , valuesize);
	} 
	
	if (SUCCEED == zbx_json_value_by_name_dyn(&jp_params, "credentialid", &credentialid, &credentialid_size, NULL))
	{ 

		ret = parse_json_get_credentials(dchecks, credentialid, proxy_hostid, devicetype, ip, port, name, path, database, houseid, managerid);
		
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ret=%d, ip=%s, port=%s, houseid=%d, managerid=%d, credentialid=%s, devicetype=%d, name=%s,path=%s", 
			__func__, ret, ip, port, houseid, managerid, credentialid, devicetype, name, path);
	}else{
		ret = DISCOVERY_RESULT_JSON_PARSE_FAIL;
	}

	// 解析代理程序返回扫描结果json
	parse_proxy_resp_to_dechecks(&jp_params, dchecks);
	
	zbx_free(ip);
	zbx_free(port);
	zbx_free(name);
	zbx_free(path);
	zbx_free(credentialid);
	zbx_free(database);
	return ret;
}

 
static char* build_single_resp_json(int result, char *session, int hostid, char* templateids)
{ 
	struct zbx_json	json;
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);

	zbx_json_addstring(&json, "response", DISCOVERY_CMD_SINGLE_SCAN, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json, "session", session, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&json, "result", result);
	zbx_json_addarray(&json, "data");
	
	if (DISCOVERY_RESULT_SUCCESS == result)
	{
		zbx_json_addobject(&json, NULL);
		zbx_json_addint64(&json, "hostid", hostid); 
		if(NULL != templateids)
			zbx_json_addstring(&json, "templateid", templateids, ZBX_JSON_TYPE_STRING);
	}  
 	zbx_json_close(&json);
	char *sjson = strdup(json.buffer);
	zbx_json_free(&json);
	return sjson;
}



 
void single_register_hostmacro(DB_HOST *host, const DB_DCHECK *dcheck)
{
	DB_RESULT	result;
	DB_ROW		row;

	if(NULL == host || 0 == host->hostid){
		return;
	}
 
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s devicetype=%d,hostid:%d, path=%s", __func__, dcheck->devicetype,host->hostid,dcheck->path);
	
	result = zbx_db_select("select hostmacroid,hostid,macro,value,description,type,automatic from hostmacro"
			" where hostid=" ZBX_FS_UI64, host->hostid);
	int name_id=0,user_id=0,passwd_id=0,scheme_id=0,ip_id=0,port_id=0,path_id=0;
	int dsn_id=0,driver_id=0,database_id=0,instance_id=0;
	int redis_id=0;
	int memcached_id=0;
	while (NULL != (row = zbx_db_fetch(result)))
	{
		char *macro = row[2];
		switch (dcheck->devicetype)
		{
		case DEVICE_TYPE_NGINX:
			if (zbx_strcmp_null(macro, "{$NGINX.STUB_STATUS.PATH}") == 0){
				path_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$NGINX.STUB_STATUS.PORT}") == 0){
				port_id = zbx_atoi(row[0]);
			}
			break;
		case DEVICE_TYPE_RABBITMQ_CLUSTER:
		case DEVICE_TYPE_RABBITMQ_NODE:
			if (zbx_strcmp_null(macro, "{$RABBITMQ.API.USER}") == 0){
				user_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$RABBITMQ.CLUSTER.NAME}") == 0){
				name_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$RABBITMQ.API.PASSWORD}") == 0){
				passwd_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$RABBITMQ.API.SCHEME}") == 0){
				scheme_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$RABBITMQ.API.CLUSTER_HOST}") == 0){
				ip_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$RABBITMQ.API.PORT}") == 0){
				port_id = zbx_atoi(row[0]);
			}
			break;
		case DEVICE_TYPE_KAFKA:
			if (zbx_strcmp_null(macro, "{$KAFKA.USER}") == 0){
				user_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$KAFKA.PASSWORD}") == 0){
				passwd_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$KAFKA.PORT}") == 0){
				port_id = zbx_atoi(row[0]);
			}
			break;
		case DEVICE_TYPE_APACHE:
			if (zbx_strcmp_null(macro, "{$APACHE.STATUS.PATH}") == 0){
				path_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$APACHE.STATUS.PORT}") == 0){
				port_id = zbx_atoi(row[0]);
			}
			break;
		case DEVICE_TYPE_TOMCAT:
			if (zbx_strcmp_null(macro, "{$TOMCAT.USER}") == 0){
				user_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$TOMCAT.PASSWORD}") == 0){
				passwd_id = zbx_atoi(row[0]);
			}else if (zbx_strcmp_null(macro, "{$TOMCAT.PORT}") == 0){
				port_id = zbx_atoi(row[0]);
			}
			break;
		case DEVICE_TYPE_IIS:
			if (zbx_strcmp_null(macro, "{$IIS.PORT}") == 0){
				port_id = zbx_atoi(row[0]);
			} 
			break;
		case DEVICE_TYPE_MYSQL:
			if (zbx_strcmp_null(macro, "{$MYSQL.USER}") == 0)
				user_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$MYSQL.PASSWORD}") == 0)
				passwd_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$MYSQL.DSN}") == 0)
				dsn_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$MYSQL.PORT}") == 0)
				port_id = zbx_atoi(row[0]);
			break;
		case DEVICE_TYPE_ORACLE:
			if (zbx_strcmp_null(macro, "{$ORACLE.USER}") == 0)
				user_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$ORACLE.PASSWORD}") == 0)
				passwd_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$ORACLE.DRIVER}") == 0)
				driver_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$ORACLE.SERVICE}") == 0)
				database_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$ORACLE.PORT}") == 0)
				port_id = zbx_atoi(row[0]);
			break;
		case DEVICE_TYPE_MSSQL:
			if (zbx_strcmp_null(macro, "{$MSSQL.USER}") == 0)
				user_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$MSSQL.PASSWORD}") == 0)
				passwd_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$MSSQL.DSN}") == 0)
				dsn_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$MSSQL.INSTANCE}") == 0)
				instance_id = zbx_atoi(row[0]);
			else if (zbx_strcmp_null(macro, "{$MSSQL.PORT}") == 0)
				port_id = zbx_atoi(row[0]);
			break;
		case DEVICE_TYPE_PROCESS:
			if (zbx_strcmp_null(macro, "{$PROC.NAME.MATCHES}") == 0)
				name_id = zbx_atoi(row[0]);
			break;
		case DEVICE_TYPE_DOCKER:
			if (zbx_strcmp_null(macro, "{$DOCKER.LLD.FILTER.CONTAINER.MATCHES}") == 0)
				name_id = zbx_atoi(row[0]);
			break;
		case DEVICE_TYPE_REDIS:	
			if (zbx_strcmp_null(macro, "{$REDIS.CONN.URI}") == 0)
				redis_id = zbx_atoi(row[0]);
			break;		
		case DEVICE_TYPE_MEMCACHED: 
			if (zbx_strcmp_null(macro, "{$MEMCACHED.CONN.URI}") == 0)
				memcached_id = zbx_atoi(row[0]);
			break;
		case DEVICE_TYPE_POSTGRE:
			break;
		case DEVICE_TYPE_HANA:
			break;
		default:
			break;
		}
	}
	
	zbx_db_free_result(result);

	char value[256];
	switch (dcheck->devicetype)
	{
	case DEVICE_TYPE_NGINX:
		update_hostmacro_data(path_id, host->hostid, "{$NGINX.STUB_STATUS.PATH}", dcheck->path, "");
		update_hostmacro_data(port_id, host->hostid, "{$NGINX.STUB_STATUS.PORT}", dcheck->ports, "");
		break;
	case DEVICE_TYPE_RABBITMQ_CLUSTER:
		update_hostmacro_data(ip_id, host->hostid, "{$RABBITMQ.API.CLUSTER_HOST}", dcheck->ip, "");
	case DEVICE_TYPE_RABBITMQ_NODE:
		update_hostmacro_data(name_id, host->hostid, "{$RABBITMQ.CLUSTER.NAME}", dcheck->path, "");

		update_hostmacro_data(user_id, host->hostid, "{$RABBITMQ.API.USER}", dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$RABBITMQ.API.PASSWORD}", dcheck->password, "");
		update_hostmacro_data(port_id, host->hostid, "{$RABBITMQ.API.PORT}", dcheck->ports, "");
		if(SVC_HTTPS == dcheck->type)
			update_hostmacro_data(scheme_id, host->hostid, "{$RABBITMQ.API.SCHEME}", "https", "");
		else
			update_hostmacro_data(scheme_id, host->hostid, "{$RABBITMQ.API.SCHEME}", "http", "");
		break;
	case DEVICE_TYPE_KAFKA:
		update_hostmacro_data(user_id, host->hostid, "{$KAFKA.USER}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$KAFKA.PASSWORD}",  dcheck->password, "");
		update_hostmacro_data(port_id, host->hostid, "{$KAFKA.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_APACHE:
		update_hostmacro_data(path_id, host->hostid, "{$APACHE.STATUS.PATH}",  dcheck->path, "");
		update_hostmacro_data(port_id, host->hostid, "{$APACHE.STATUS.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_TOMCAT:
		update_hostmacro_data(user_id, host->hostid, "{$TOMCAT.USER}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$TOMCAT.PASSWORD}",  dcheck->password, "");
		update_hostmacro_data(port_id, host->hostid, "{$TOMCAT.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_IIS:
		update_hostmacro_data(port_id, host->hostid, "{$IIS.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_MYSQL:
		update_hostmacro_data(user_id, host->hostid, "{$MYSQL.USER}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$MYSQL.PASSWORD}",  dcheck->password, "");
		update_hostmacro_data(dsn_id, host->hostid, "{$MYSQL.DSN}",  dcheck->dsn_name, "");
		update_hostmacro_data(port_id, host->hostid, "{$MYSQL.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_ORACLE:
		update_hostmacro_data(user_id, host->hostid, "{$ORACLE.USER}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$ORACLE.PASSWORD}",  dcheck->password, "");
		update_hostmacro_data(driver_id, host->hostid, "{$ORACLE.DRIVER}",  dcheck->driver, "");
		update_hostmacro_data(database_id, host->hostid, "{$ORACLE.SERVICE}",  dcheck->database, "");
		update_hostmacro_data(port_id, host->hostid, "{$ORACLE.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_MSSQL:
		update_hostmacro_data(user_id, host->hostid, "{$MSSQL.USER}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$MSSQL.PASSWORD}",  dcheck->password, "");
		update_hostmacro_data(dsn_id, host->hostid, "{$MSSQL.DSN}",  dcheck->dsn_name, "");
		update_hostmacro_data(instance_id, host->hostid, "{$MSSQL.INSTANCE}",  dcheck->params, "");
		update_hostmacro_data(port_id, host->hostid, "{$MSSQL.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_PROCESS:
		update_hostmacro_data(name_id, host->hostid, "{$PROC.NAME.MATCHES}", dcheck->path, "");
		break;
	case DEVICE_TYPE_DOCKER:
		update_hostmacro_data(name_id, host->hostid, "{$DOCKER.LLD.FILTER.CONTAINER.MATCHES}", dcheck->path, "");
		break;
	case DEVICE_TYPE_REDIS:	
		zbx_snprintf(value, sizeof(value), "tcp://%s",dcheck->path);
		update_hostmacro_data(redis_id, host->hostid, "{$REDIS.CONN.URI}",  value, "");
		break;		
	case DEVICE_TYPE_MEMCACHED: 	
		zbx_snprintf(value, sizeof(value), "tcp://%s",dcheck->path);
		update_hostmacro_data(memcached_id, host->hostid, "{$MEMCACHED.CONN.URI}",	value, "");
		break;
	case DEVICE_TYPE_POSTGRE:
		update_hostmacro_data(user_id, host->hostid, "{$PG.USER}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$PG.PASSWORD}",  dcheck->password, "");
		update_hostmacro_data(driver_id, host->hostid, "{$PG.CONNSTRING}",  dcheck->driver, "");
		update_hostmacro_data(database_id, host->hostid, "{$PG.DATABASE}",  dcheck->database, "");
		update_hostmacro_data(database_id, host->hostid, "{$PG.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_HANA:
		update_hostmacro_data(user_id, host->hostid, "{$HDB.USR}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$HDB.PWD}",  dcheck->password, "");
		update_hostmacro_data(driver_id, host->hostid, "{$HDB.DRIVER}",  dcheck->driver, "");
		update_hostmacro_data(database_id, host->hostid, "{$HDB.DATABASE}",  dcheck->database, "");
		update_hostmacro_data(port_id, host->hostid, "{$HDB.PORT}",  dcheck->ports, "");
		break;
	case DEVICE_TYPE_MONGODB:
	case DEVICE_TYPE_MONGODB_CLUSTER:
		update_hostmacro_data(user_id, host->hostid, "{$MONGODB.USER}",  dcheck->user, "");
		update_hostmacro_data(passwd_id, host->hostid, "{$MONGODB.PASSWORD}",  dcheck->password, "");
		update_hostmacro_data(driver_id, host->hostid, "{$MONGODB.CONNSTRING}",  dcheck->driver, "");
		break;
	default:
		break;
	}
	 
	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}
static int discovery_register_single(int devicetype, char *value, DB_HOST *host, DB_DCHECK *dcheck)
{
	int ret = FAIL, port = 0;
	char dns[ZBX_INTERFACE_DNS_LEN_MAX]; 
	DB_INTERFACE interface;
	DB_HOST_INVENTORY inventory;
	
	memset(&interface, 0, sizeof(DB_INTERFACE));
	memset(&inventory, 0, sizeof(DB_HOST_INVENTORY));

	zbx_gethost_by_ip(dcheck->ip, dns, sizeof(dns));
	port = zbx_atoi(dcheck->ports);

	//入库host对应的接口
	if(devicetype < DEVICE_TYPE_HW_MAX){
		ret = discovery_register_host(host, &inventory, value, dcheck->ip, dns, port, DOBJECT_STATUS_UP, dcheck);
	}else{
		ret = discovery_register_soft(host, &inventory, NULL, dcheck->ip, dns, port, DOBJECT_STATUS_UP, dcheck);
	}

	if(SUCCEED == ret)
	{
		// 入库host对应的接口
		discovery_register_interface(host, &interface, dcheck->ip, dns, port, dcheck);
		// 入库host_inventory对应的接口
		discovery_register_host_inventory(&inventory); 

		// mssql获取的值用于更新hostmacro表
		if(dcheck->devicetype == DEVICE_TYPE_MSSQL)
		{
			int value_num = 2;
			char *token[2] = {0};
			zbx_split(value,":",token,&value_num);
			dcheck->params =  zbx_strdup(NULL, token[0]);
		}

		single_register_hostmacro(host, dcheck); 

		// 如果主机和接口都是已经注册过，说明是重复添加。如果主机重复，接口不重复，是增加了监控协议
		if(HOST_STATUS_UNREACHABLE != host->status && HOST_STATUS_MONITORED == interface.status){
			ret = DISCOVERY_RESULT_DUPLICATE_FAIL;
		}else{	 	
			discoverer_bind_templateid(host);
		}
	}else{
		ret = DISCOVERY_RESULT_SCAN_FAIL;
	} 

	db_hosts_free(host);
	return ret;
}

static int discover_service_http(char **out_value, DB_DCHECK *dcheck, int maxTry)
{
	AGENT_RESULT	result; 
	DC_ITEM		item;
	char url[256]={0}, authorization[2048]={0};
	int authtype = HTTPTEST_AUTH_NONE, port = 0;

	port = zbx_atoi(dcheck->ports);
	zbx_init_agent_result(&result);

	memset(&item, 0, sizeof(DC_ITEM));

	if(DEVICE_TYPE_RABBITMQ_NODE == dcheck->devicetype){
		zbx_snprintf(url, sizeof(url), "http://%s:%d/api/nodes/%s?memory=true", dcheck->ip, port, dcheck->path);
	}else if(DEVICE_TYPE_KUBERNETES == dcheck->devicetype){
		zbx_snprintf(url, sizeof(url), "https://%s:%d/livez?verbose", dcheck->ip, port);
	}else if(SVC_HTTPS == dcheck->type){
		zbx_snprintf(url, sizeof(url), "https://%s:%d/%s", dcheck->ip, port, dcheck->path);
	}else {
		zbx_snprintf(url, sizeof(url), "http://%s:%d/%s", dcheck->ip, port, dcheck->path);
	}

	switch (dcheck->devicetype)
	{ 
	case DEVICE_TYPE_RABBITMQ_CLUSTER:
	case DEVICE_TYPE_RABBITMQ_NODE:
		authtype = HTTPTEST_AUTH_BASIC;
		break;
	default:
		break;
	}
	
	zbx_strscpy(item.key_orig, dcheck->key_); 
	item.key = item.key_orig;

	item.url = zbx_strdup(NULL,url);
	item.authtype = authtype;
	item.username = dcheck->user;
	item.password = dcheck->password;
	item.type = ITEM_TYPE_HTTPAGENT;
	item.follow_redirects = 1; 
	item.state = 1;
	item.value_type	= ITEM_VALUE_TYPE_TEXT;
	item.retrieve_mode = ZBX_RETRIEVE_MODE_CONTENT;
	item.timeout = zbx_strdup(NULL, "2s"); 
	item.status_codes = zbx_strdup(NULL, "200"); 

	switch (dcheck->devicetype)
	{ 
	case DEVICE_TYPE_KUBERNETES:
		zbx_snprintf(authorization,sizeof(authorization),"Authorization: Bearer %s", dcheck->ssh_privatekey);
		item.headers = zbx_strdup(NULL, authorization);
		break;
	default:
		item.headers = zbx_strdup(NULL, "");
		break;
	}
	
	item.query_fields = zbx_strdup(NULL, "");
	item.posts = zbx_strdup(NULL, "");
	item.params = zbx_strdup(NULL, "");
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
	
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, ret=%d, url=%s, authtype=%d,user=%s, ip=%s, port=%d, recv value=%s", 
		__func__, iResult, url, authtype, dcheck->user, dcheck->ip, port, *out_value);
	  
	zbx_free_agent_result(&result);
	return iResult;
}


/***
 *  这个函数是服务端执行代码，执行单设备扫描功能。
 *  完整实现设备或软件添加入库功能
 */
void* discover_single_handle(void* arg) 
{
	int result = DISCOVERY_RESULT_SCAN_FAIL, ret = FAIL;
	
    struct single_thread_arg *thread_arg = (struct single_thread_arg *)arg;
	char *session = thread_arg->session;
	char *request = thread_arg->request;
	int recv_type = thread_arg->recv_type;
	zbx_vector_ptr_t *dchecks = thread_arg->dchecks; 
	zbx_vector_str_t templateids;
	
	int devicetype = 0, lasthostid = 0, hostid = 0, config_timeout = 2;
	char *value = NULL, *response = NULL, *str_templateids = NULL;
	size_t value_alloc = 128; 
	DB_DCHECK *dcheck = NULL;
	DB_HOST host;
	
	zabbix_log(LOG_LEVEL_DEBUG,"In %s() dcheck_size=%d",__func__, dchecks->values_num);
	
	init_discovery_hosts(1);
	
	value = (char *)zbx_malloc(value, value_alloc);
	zbx_vector_str_create(&templateids);

	// 一个服务器有不同的协议发现, 如agent，snmp，ipmi等
	for (int i = 0; i < dchecks->values_num; i++)
	{
		dcheck = dchecks->values[i];
		devicetype = dcheck->devicetype;
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, type=%d,ip=%s,ports=%s,devicetype=%d",
			__func__,dcheck->type, dcheck->ip,dcheck->ports,devicetype);
		
		if(DEVICE_TYPE_KUBERNETES == dcheck->devicetype){
			discover_kubernetes(recv_type, session, dcheck);
			return;
		}

		if(SVC_HTTP == dcheck->type || SVC_HTTPS == dcheck->type){
			ret = discover_service_http(&value, dcheck, 2);
		}else{
			ret = discover_service(NULL, dcheck, dcheck->ip, atoi(dcheck->ports), config_timeout, &value, &value_alloc);
		}
		 
		if(SUCCEED == ret) ret = get_result_by_values(dcheck, value);
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s success, ret=%d, value=%s", __func__, ret, value);
		if(DISCOVERY_RESULT_SUCCESS == ret)
		{
			memset(&host, 0, sizeof(DB_HOST));
			host.hostid = lasthostid;  //所有的查找发现都是同一个hostid

			ret = discovery_register_single(devicetype, value,  &host, dcheck);
			
			if(host.hostid > 0) 
				lasthostid = host.hostid;  //获得hostid
			if(SUCCEED == ret)
			{
				result = SUCCEED;
				hostid = host.hostid;
				if(host.templateid > 0) 
					zbx_vector_str_append(&templateids, zbx_itoa(host.templateid));
				
			}else if(SUCCEED != result){ // 多个接口扫描,只要其中一个成功都是成功
				result = ret;
			}
		}
		 
	}
	 
	
	if(DISCOVERY_RESULT_SUCCESS == result && templateids.values_num > 0){
		vector_to_str_max(&templateids, &str_templateids, ",", MAX_TEMPLATEID_NUM);
	}
	response = build_single_resp_json(result, session, hostid, str_templateids);
	 
	discover_response_replay(recv_type, response);
	
	zbx_vector_str_clear_ext(&templateids, zbx_str_free);
	zbx_vector_str_destroy(&templateids);
	zbx_free(value);
	zbx_free(response);
	zbx_free(str_templateids);
} 

/**
 * 这个函数是服务端执行代码，处理代理返回的数据
 */
void* server_discover_single_from_proxy(char *session, int recv_type, zbx_vector_ptr_t *dchecks) 
{
	int result = DISCOVERY_RESULT_SCAN_FAIL, ret = FAIL;
	zbx_vector_str_t templateids; 
	int lasthostid = 0, hostid = 0;
	char *response = NULL, *str_templateids = NULL;
	DB_DCHECK *dcheck = NULL;
	DB_HOST host;
	
	zabbix_log(LOG_LEVEL_DEBUG,"In %s() dcheck_size=%d",__func__, dchecks->values_num);
	zbx_vector_str_create(&templateids);

	init_discovery_hosts(1);

	// 一个服务器有不同的协议发现, 如agent，snmp，ipmi等
	for (int i = 0; i < dchecks->values_num; i++)
	{
		dcheck = dchecks->values[i];
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, type=%d,ip=%s,ports=%s,proxy_hostid=%d,devicetype=%d,result=%d,resp_len=%d",
			__func__,dcheck->type, dcheck->ip,dcheck->ports, dcheck->proxy_hostid, dcheck->devicetype,dcheck->result,
			 (dcheck->resp_value ==NULL?0:strlen(dcheck->resp_value)));
		ret = dcheck->result;
		if(DEVICE_TYPE_KUBERNETES == dcheck->devicetype){
			server_discover_kubernetes_from_proxy(recv_type, session, dcheck);
			return;
		}

		if(DISCOVERY_RESULT_SUCCESS == ret)
		{
			memset(&host, 0, sizeof(DB_HOST));
			host.hostid = lasthostid;  //所有的查找发现都是同一个hostid
			host.proxy_hostid = dcheck->proxy_hostid;

			ret = discovery_register_single(dcheck->devicetype, dcheck->resp_value,  &host, dcheck);
			
			if(host.hostid > 0) 
				lasthostid = host.hostid;  //获得hostid
			if(SUCCEED == ret)
			{
				result = SUCCEED;
				hostid = host.hostid;
				if(host.templateid > 0) 
					zbx_vector_str_append(&templateids, zbx_itoa(host.templateid));
			}else if(SUCCEED != result){ // 多个接口扫描,只要其中一个成功都是成功
				result = ret;
			}
		}
	}
 
	
	if(DISCOVERY_RESULT_SUCCESS == result && templateids.values_num > 0){
		vector_to_str_max(&templateids, &str_templateids, ",", MAX_TEMPLATEID_NUM);
	}
	response = build_single_resp_json(result, session, hostid, str_templateids);
	 
	discover_response_replay(recv_type, response);
	
	zbx_vector_str_clear_ext(&templateids, zbx_str_free);
	zbx_vector_str_destroy(&templateids);
	zbx_free(response);
	zbx_free(str_templateids);
} 


/***
 *  这个函数是代理端执行代码，执行单设备扫描功能。
 *  这里只是实现设备扫描，并且返回结果给服务端
 */
void* proxy_discover_single_handle(void* arg) 
{
	int result = DISCOVERY_RESULT_SCAN_FAIL, ret = FAIL;
	
    struct single_thread_arg *thread_arg = (struct single_thread_arg *)arg;
	char *session = thread_arg->session;
	char *request = thread_arg->request;
	int recv_type = thread_arg->recv_type;
	zbx_vector_ptr_t *dchecks = thread_arg->dchecks; 
 
	int devicetype = 0, config_timeout = 2;
	char *value = NULL, *response = NULL;
	size_t value_alloc = 128; 
	DB_DCHECK *dcheck = NULL;
	DB_HOST host;
	
	value = (char *)zbx_malloc(value, value_alloc);
  
	// 一个服务器有不同的协议发现, 如agent，snmp，ipmi等
	for (int i = 0; i < dchecks->values_num; i++)
	{
		dcheck = dchecks->values[i];
		devicetype = dcheck->devicetype;
		if(DEVICE_TYPE_KUBERNETES == dcheck->devicetype){
			proxy_discover_kubernetes(recv_type, session, request, dcheck);
			return;
		}

		if(SVC_HTTP == dcheck->type || SVC_HTTPS == dcheck->type){
			ret = discover_service_http(&value, dcheck, 2);
		}else{
			ret = discover_service(NULL, dcheck, dcheck->ip, atoi(dcheck->ports), config_timeout, &value, &value_alloc);
		}

		if(SUCCEED == ret) ret = get_result_by_values(dcheck, value);
		dcheck->result = ret; 
		dcheck->resp_value = zbx_strdup(NULL, value); 
		
		zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s, ret=%d, type=%d,ip=%s,ports=%s,devicetype=%d,value=%s",
			__func__, ret, dcheck->type, dcheck->ip,dcheck->ports,devicetype,print_content(value));
	}
	
	// 从代理扫描返回到服务端,这边不要注册hosts
	response = proxy_build_single_resp_json(request, dchecks);
	  
	discover_response_replay(recv_type, response);
	
	zbx_free(value);
	zbx_free(response);
} 


/**
 * 单设备扫描的总入口
*/
int	discover_single_scan(int recv_type, char *session, const struct zbx_json_parse *jp, char *request, char **response)
{
	pthread_t ds_thread;
	struct single_thread_arg thread_arg;
	
	zbx_vector_ptr_t dchecks;
	zbx_vector_ptr_create(&dchecks);

	int result = FAIL, proxy_hostid = 0; 
	char int_value[16];
	zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s begin session:%s", __func__, session);
	 
	// 提取 proxyhostid
	if (SUCCEED == zbx_json_value_by_name(jp, "proxyhostid", int_value, sizeof(int_value), NULL))
	{
		zbx_lrtrim(int_value, ZBX_WHITESPACE);
		proxy_hostid = zbx_atol(int_value);
	}
	
	if (SUCCEED != (result = parse_json_to_dechecks(jp, &dchecks, proxy_hostid)))
	{
		*response = build_single_resp_json(result, session, 0, NULL);
		goto out;
	}
	
	if(proxy_hostid > 0 && ZBX_PROGRAM_TYPE_SERVER == g_running_program_type){ 
		// 服务端处理代理返回的单设备扫描的response数据
		server_discover_single_from_proxy(session,recv_type, &dchecks);
	}else{
		// 代理端和服务端处理单设备扫描
		thread_arg.session = session;
		thread_arg.dchecks = &dchecks;
		thread_arg.recv_type = recv_type;
		thread_arg.request = request;

		if(proxy_hostid > 0 && ZBX_PROGRAM_TYPE_PROXY == g_running_program_type) 
		{	// 代理服务端执行
			if (pthread_create(&ds_thread, NULL, proxy_discover_single_handle, &thread_arg))
			{
				zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s. create thread fail.",__func__);
				return FAIL;
			}
			if (pthread_join(ds_thread, NULL))
			{
				zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s. join thread fail", __func__);
			}

		}
		else
		{
			// 本地服务端执行,无代理
			if (pthread_create(&ds_thread, NULL, discover_single_handle, &thread_arg))
			{
				zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s. create thread fail.",__func__);
				return FAIL;
			}
			if (pthread_join(ds_thread, NULL))
			{
				zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s. join thread fail", __func__);
			}
		}
		
	}
 
out:
	zbx_vector_ptr_clear_ext(&dchecks, (zbx_clean_func_t)DB_dcheck_free);
	zbx_vector_ptr_destroy(&dchecks);

	return result;
	
}

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


