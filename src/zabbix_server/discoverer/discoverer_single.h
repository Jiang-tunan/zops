#ifndef ZABBIX_DISCOVERER_SINGLE_H
#define ZABBIX_DISCOVERER_SINGLE_H

#define DISCOVERER_WORKER_INIT_NONE	0x00
#define PP_WORKER_INIT_THREAD 0x01

#define SNMP_ITEM_FIELDS_LEN 128
#define SNMP_ITEM_KEY_LEN 	 256

// AGENT _KEY 自定义格式(非zabbix定义) "discovery[{#item1}|key1|{#item2}|key2 ....]"
#define SNMP_DEFAULT_AGENT_KEY    "discovery[{#SYSNAME}|system.hostname|{#SYSDESC}|system.sw.os|{#IFPHYSADDRESS}|system.hw.macaddr[,short]" // "get_discover_value"

//#define SNMP_DEFAULT_AGENT_KEY    "discovery[{#SYSNAME}|agent.hostname|{#SYSDESC}|system.uname|{#IFPHYSADDRESS}|system.hw.macaddr[,short]" // "get_discover_value"
 
#define SNMP_DEFAULT_SNMP_KEY     "discovery[{#SYSNAME},1.3.6.1.2.1.1.5,{#SYSDESC},1.3.6.1.2.1.1.1,{#ENTPHYSICALSERIALNUM},1.3.6.1.2.1.47.1.1.1.1.11,{#IFPHYSADDRESS},1.3.6.1.2.1.2.2.1.6,{#ENTPHYSICALMODELNAME},1.3.6.1.2.1.47.1.1.1.1.13]"
//#define SNMP_COMMUNITY            "{$SNMP_COMMUNITY}"
#define SNMP_COMMUNITY            "public"

typedef struct
{
	pthread_t		thread;
    int				status; 
}
zbx_discoverer_worker_t;

struct single_thread_arg {
    int recv_type;  // 消息队列的类型
    char *session;
    char *request;  // php请求的json内容
    zbx_vector_ptr_t *dchecks;
};

// int discoverer_workers_init(zbx_discoverer_worker_t *workers, int num);
int	discover_single_scan(int socket , char *session, const struct zbx_json_parse *jp, char *request, char **response);

#endif



