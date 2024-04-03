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

#ifndef ZABBIX_DISCOVERY_H
#define ZABBIX_DISCOVERY_H

#include "zbxdbhigh.h"
#include <regex.h>

#define ZERO_IP_ADDRESS		"0.0.0.0"	//无用IP地址

// 设备或软件对应组的定义，hstgrp表的groupid定义
#define HSTGRP_GROUPID_NETWORK   			1	//网络设备
#define HSTGRP_GROUPID_VM					2	//虚拟机
#define HSTGRP_GROUPID_SERVER				3	//服务器
#define HSTGRP_GROUPID_HYPERCONVERGENCE		4	//超融合
#define HSTGRP_GROUPID_STORAGE				5	//存储设备
#define HSTGRP_GROUPID_SECURITY				6	//安全设备
#define HSTGRP_GROUPID_DATABASE				9	//数据库
#define HSTGRP_GROUPID_WEBSERVER			10	//WEB
#define HSTGRP_GROUPID_MIDDLEWARE			11	//中间件
#define HSTGRP_GROUPID_NETWORKTOOLS			12	//网络工具
#define HSTGRP_GROUPID_SOFTWARE				13	//应用软件
#define HSTGRP_GROUPID_VIRTUALIZATION		14	//容器/虚拟化


// 模板的定义
#define TEMPLATEID_SERVER_LINUX_BY_AGENT	3	// linux服务器Agent模板
#define TEMPLATEID_SERVER_LINUX_BY_SNMP		4	// linux服务器SNMP模板
#define TEMPLATEID_SERVER_WINDOWS_BY_AGENT	5	// windows服务器Agent模板
#define TEMPLATEID_SERVER_WINDOWS_BY_SNMP	6	// windows服务器SNMP模板
// 1.5版本把这4个多余的模板去掉
// #define TEMPLATEID_VM_LINUX_BY_AGENT		7	// linux虚拟机Agent模板
// #define TEMPLATEID_VM_LINUX_BY_SNMP			8	// linux虚拟机SNMP模板
// #define TEMPLATEID_VM_WINDOWS_BY_AGENT		9	// windows虚拟机Agent模板
// #define TEMPLATEID_VM_WINDOWS_BY_SNMP		10	// windows虚拟机SNMP模板
#define TEMPLATEID_NETWORK_DEVICE_SNMP		11 	// 网络设备SNMP,Agent的模板ID
#define TEMPLATEID_VMWARE_HV_SERVER			12 	// 物理机VMware模板id
#define TEMPLATEID_VMWARE_VM_SERVER			13 	// 虚拟机VMware模板id
#define TEMPLATEID_SERVER_IPMI				14 	// 物理机IPMI模板id
#define TEMPLATEID_NETWORK_PING				15 	// 网络模板id

#define TEMPLATEID_NUTANIX_CLUSTER			16 	// Nutanix Cluster模板id 
#define TEMPLATEID_NUTANIX_HV				17 	// Nutanix HV模板id 
#define TEMPLATEID_NUTANIX_VM				18 	// Nutanix VM模板id 

#define TEMPLATEID_SOFT_MYSQL				19  // MYSQL模板id 
#define TEMPLATEID_SOFT_MSSQL				20  // MSSQL模板id 
#define TEMPLATEID_SOFT_ORACLE				21  // ORACLE模板id 
#define TEMPLATEID_SOFT_APACHE				22 	// Apache web模板id
#define TEMPLATEID_SOFT_TOMCAT				23 	// Tomcat模板id 
#define TEMPLATEID_SOFT_IIS					24 	// IIS模板id

#define TEMPLATEID_SOFT_RABBITMQ_CLUSTER	25 	// RabbitMQ Cluster模板id
#define TEMPLATEID_SOFT_RABBITMQ_NODE		26 	// RabbitMQ node模板id
#define TEMPLATEID_SOFT_KAFKA				27 	// Kafka模板id
#define TEMPLATEID_SOFT_NGINX				28 	// Nginx模板id

#define TEMPLATEID_SOFT_PROCESS				29 	// 自定义软件监控模板id
#define TEMPLATEID_SOFT_DOCKER				30 	// Docker监控模板id

#define TEMPLATEID_SOFT_REDIS				31 	// Redis监控模板id
#define TEMPLATEID_SOFT_MEMCACHED			32 	// memcached监控模板id
#define TEMPLATEID_SOFT_SAPHANA				33 	// hana 监控模板id
#define TEMPLATEID_SOFT_POSTGRE				34 	// postgre 监控模板id
#define TEMPLATEID_SOFT_MONGODB				35 	// mongodb 监控模板id
#define TEMPLATEID_SOFT_MONGODB_CLUSTER		36 	// mongodb_cluster 监控模板id

#define TEMPLATEID_SOFT_KUBERNETES_STATE		37 	// k8s state 监控模板id
#define TEMPLATEID_SOFT_KUBERNETES_API			38 	// k8s api 监控模板id
#define TEMPLATEID_SOFT_KUBERNETES_CONTROLLER	39 	// k8s CONTROLLER 监控模板id
#define TEMPLATEID_SOFT_KUBERNETES_SCHEDULER	40 	// k8s SCHEDULER 监控模板id
#define TEMPLATEID_SOFT_KUBERNETES_KUBELET		41 	// k8s KUBELET 监控模板id


#define TEMPLATEID_BIND_HTTP_REQ_ID			1
#define TEMPLATEID_BIND_HTTP_REQ_AUTH		"8ed72cf4a7f28a05b6cf5b257b4acdfc"


// hstgrp表的type定义
#define HSTGRP_TYPE_VC			2 //VMWare中心
#define HSTGRP_TYPE_DATACENTER	3 //数据中心
#define HSTGRP_TYPE_CLUSTER		4 //集群
#define HSTGRP_TYPE_HV			5 //物理机
#define HSTGRP_TYPE_VM			6 //虚拟机

#define HSTGRP_TYPE_NTX			10 //Nutanix中心

#define HSTGRP_TYPE_KUBERNETES		101 //K8S中心
#define HSTGRP_TYPE_KUBERNETES_SET	102 //K8S包涵的套件


 

// 设备类型定义 device_type
// 硬件设备(1-99):   1:物理机,       2:虚拟机,     3:nutanix集群服务器
// 数据库(100-199):  100:MySQL,      101: MS SQL, 102:Oracle
// web服务(200-299): 200:Apache Web, 201:Tomcat,  202:IIS
// 中间件(300-299):  300:RabbitMO,   301:Kafka,   302:Nginx
// 邮件服务(400-499):
// 工具服务(500-599): 500:ping监控
//硬件设备
#define DEVICE_TYPE_HV      	1 //物理机
#define DEVICE_TYPE_VM			2 //虚拟机
#define DEVICE_TYPE_CLUSTER		3 //集群机

// 硬件限定最大值,包括服务器，虚拟机，网络设备
#define DEVICE_TYPE_HW_MAX					99

//数据库
#define DEVICE_TYPE_MYSQL					100
#define DEVICE_TYPE_MSSQL					101
#define DEVICE_TYPE_ORACLE					102
#define DEVICE_TYPE_POSTGRE					103
#define DEVICE_TYPE_MONGODB					104
#define DEVICE_TYPE_HANA					105
#define DEVICE_TYPE_REDIS					106
#define DEVICE_TYPE_MEMCACHED				107
#define DEVICE_TYPE_MONGODB_CLUSTER			108

//Web服务器
#define DEVICE_TYPE_APACHE					200
#define DEVICE_TYPE_TOMCAT					201
#define DEVICE_TYPE_IIS						202


//中间件
#define DEVICE_TYPE_RABBITMQ_CLUSTER		300
#define DEVICE_TYPE_RABBITMQ_NODE			301
#define DEVICE_TYPE_KAFKA					302
#define DEVICE_TYPE_NGINX					303

#define DEVICE_TYPE_DOCKER					400
#define DEVICE_TYPE_KUBERNETES				401
#define DEVICE_TYPE_KUBERNETES_API			402
#define DEVICE_TYPE_KUBERNETES_CONTROLLER	403
#define DEVICE_TYPE_KUBERNETES_SCHEDULER	404
#define DEVICE_TYPE_KUBERNETES_KUBELET		405 


//工具服务
#define DEVICE_TYPE_PING					500

#define DEVICE_TYPE_PROCESS					600


#define DEFAULT_NOPROXY_HOSTID				0

// 消息队列结构体

#define QUEUE_STR_LEN						81920
struct json_queue
{
    long int type;						// 消息类型
	int recv_type;						// trapper 进程接收的消息类型
    char content[QUEUE_STR_LEN];		// 信息存储
};

typedef struct
{
	int     type;			// 类型，定义 ZBX_JSON_TYPE_STRING, ZBX_JSON_TYPE_INT 
	char	*name;			// TYPE_STRING, TYPE_INT定义对应的替换名称
	char	*svalue;		// TYPE_STRING对应的替换值
	int		ivalue;			// TYPE_INT对应的替换值
}
zbx_map_item_t;

typedef struct
{
	int     type;			// 类型，定义 ZBX_JSON_TYPE_OBJECT、ZBX_JSON_TYPE_STRING, ZBX_JSON_TYPE_INT
	char	*fname; 		// 父亲的名称，类型为ZBX_JSON_TYPE_OBJECT用，如果是NULL则添加到根
	char	*name;			// TYPE_STRING, TYPE_INT定义对应的替换名称
	char	*svalue;		// TYPE_STRING对应的替换值
	int		ivalue;			// TYPE_INT对应的替换值
	zbx_vector_ptr_t items; // OBJECT对应的子项，存储内容为zbx_map_item_t
}
zbx_maps_t;

typedef struct
{
	char	*name;
	char	*value;
}
zbx_map_t;

typedef struct
{
	zbx_uint64_t	dcheckid;
	unsigned short	port;
	char		dns[ZBX_INTERFACE_DNS_LEN_MAX];
	char		value[ZBX_MAX_DISCOVERED_VALUE_SIZE];
	int		status;
	time_t		itemtime;
}
zbx_dservice_t;


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
	int		    status;

	char *host;
	char *ifphysaddresses;
	char *name;
	char *uuid; 

	int templateid;
	int groupid;
	int hstgrpid;
	int device_type;
	
	zbx_uint64_t proxy_hostid;

	zbx_vector_str_t *macs;
}
DB_HOST;
 
zbx_vector_ptr_t g_DC_HOSTS;

typedef struct
{
	zbx_uint64_t	interfaceid;
	zbx_uint64_t	hostid;
	int             available;
	int             status;
	//char		    *ip;
	//char		    *port;
	//unsigned char	type;
	//unsigned char	main;
	//unsigned char	useip;
}
DB_INTERFACE;



typedef struct
{
	zbx_uint64_t	dcheckid;
	char		*ports;
	char		*key_;
	char		*snmp_community;
	char		*snmpv3_securityname;
	char		*snmpv3_authpassphrase;
	char		*snmpv3_privpassphrase;
	char		*snmpv3_contextname;
	int		type;
	unsigned char	snmpv3_securitylevel;
	unsigned char	snmpv3_authprotocol;
	unsigned char	snmpv3_privprotocol;
	int		       houseid;
	int		       managerid;
	zbx_uint64_t   druleid;
	char		*ip;
	char		*name;
	char		*user;
	char		*password;
	int		    ssh_privprotocol;
	char        *ssh_privatekey;
	char		*path;
	int         credentialid;   // 扫描和监控凭证，正常情况这个必须有值
	int         devicetype;
	
	char		*params;
	char		*dsn_name;		// odbc 数据源名称
	char		*driver;	// odbc 驱动路径
	char		*database;	// odbc 数据库名称

	int         main_type;  //主扫描类型,当一个规则有多个扫描类型时用
	
	int         proxy_hostid;  //代理hostid
	int         result;  	   //代理返回给服务端结果
	char        *resp_value;   //代理返回给服务端check值
}
DB_DCHECK;

#define MAX_MACADDRESS_NUM   	12  // 最多存储mac地址数量
#define MAX_TEMPLATEID_NUM   	8   // 单设备扫描返回最多模板ID数量

#define DUNIQUE_TYPE_UNKNOW  	-1 //未知
#define DUNIQUE_TYPE_DEFAULT	0  //默认
#define DUNIQUE_TYPE_MACS 		1  //mac地址列表
#define DUNIQUE_TYPE_IP   		2  //ip地址
#define DUNIQUE_TYPE_SOFT   	3  //软件地址，‘IP地址-软件名称’ 组成,如:"192.168.31.23-mysql"

typedef struct
{
	int dunique_type;      // 资产表唯一ID类型， 1：唯一标识为mac地址列表，2：IP地址
	char *dunique;		   // 资产表唯一ID
	zbx_uint64_t hostid;   //监控服务器id
	int inventory_mode;	   // 主机资产填写模式.可能值是:-1 - (默认) 关闭;0 - 手动;1 - 自动.'
	int houseid;		   // '机房id'
	int inventory_typeid;  // 资产类型id'
	char *manufacturer;	   //'厂商表名称,如：huawei'
	int managerid;		   //'设备负责人id'
	//int hostgroupid;	   //'记录模板对应id，方便回显'
	int groupid;		   //'设备类型id'
	char *physical_model;  //'设备主机型号'
	char *physical_serial; //'设备主机序列号'
	char *chassis;		   //'机箱型号'
	char *chassis_serial;  // '机箱序列号'
	char *board;		   //'主板型号'
	char *board_serial;	   // '主板序列号'
	char *os_short;		   //'操作系统简称,如:Linux、Windows
	char *ip;			   //'IP'
	char *name;			   //'设备名称'
	char *description;	  //'设备描述,一长串信息'
	char *cpu;			   //'CPU信息,json定义:{\r\n\"cpu_num\": 2, //CPU数量\r\n\"mf\":\"Intel(R) Corporation\"  //CPU厂家\r\n\"name\":\"Intel(R) Xeon(R) Gold 5115 CPU @ 2.40GHz\"  //CPU名称\r\n}',
	char *memory;		   // '内存信息,json定义\r\n{\r\n\"capacity\": 200, //内存总容量\r\n \"memory\":[{\r\n    \"mf\":\"Micron\",  //内存厂商\r\n    \"model\":\"镁光4G\",  //内存型号\r\n    \"serial\":\"0000000\",  //内存序列号\r\n    \"capacity\": \"4 G\",  //内存容量\r\n    }\r\n  ]\r\n}',
	char *disk;			   // '磁盘信息,json定义：\r\n{\r\n\"disk_num\": 2, //磁盘数量\r\n \"disk\":[{\r\n    \"name\":\"镁光MTFDKBA512TFH\",  //磁盘名称\r\n    \"model\":\"Micron MTFDKABA512TFH\",  //磁盘型号\r\n    \"serial\":\"5WBXT0C4DAU2EM\",  //磁盘序列号\r\n    \"capacity\": \"512 G\",  //磁盘容量\r\n    }\r\n  ]\r\n}',
	char *network;		   //'网络信息, json定义: \r\n{\r\n\"port_num\": 48,   //端口数量\r\n\"ethernet_num\": 2,  //网卡数量\r\n\"ethernet\": [{\r\n\"name\": \"HPE Ethernet 1Gb 4-port 331i Adapter - NIC\"\r\n},\r\n{\r\n\"name\": \"HPE Ethernet 2Gb 8-port 689 Adapter - NIC\"\r\n}\r\n]\r\n}',
	char *bios;			   //'bios信息,json定义\r\n{\r\n\"mf\": \"HPE\",         //BIOS 厂家\r\n\"model\": \"U30\",   //BIOS 类型\r\n \"version\":\"03/16/2023\" //BIOS版本\r\n}',
	char *psu;			   //'电源信息,json定义:\r\n{\r\n\"psu_num\": 2, //电源数量\r\n\"mf\":\"DELTA\",  //电源厂家\r\n\"model\":\"865414-B21\",  //电源型号\r\n \"version\":\"1.00\",  //电源版本\r\n \"serial\":\"5WBXT0C4DAU2EM\",  //电源序列号\r\n \"max_power\": 800,  //电源最大功率\r\n}',
	//   int is_updateinfo;          //'是否已经更新过硬件信息，0否，1是'
	//   long update_time;           //'更新时间'
	//   long create_time;           //'创建时间'
	//   char *macs;  //mac地址列表，格式为"ip1/ip2/ip3...",如："74-1f-4a-a2-02-bf/74-1f-4a-a2-02-d1/74-1f-4a-a2-02-ee"
} DB_HOST_INVENTORY;

void	zbx_discovery_update_host(zbx_db_dhost *dhost, int status, int now);
void	zbx_discovery_update_service(zbx_db_drule *drule, zbx_uint64_t dcheckid, zbx_db_dhost *dhost,
		const char *ip, const char *dns, int port, int status, const char *value, int now, DB_DCHECK *dcheck);

int discovery_register_host(DB_HOST *host,DB_HOST_INVENTORY *inventory, const void *value, 
		const char *ip, const char *dns, int port, int status, const DB_DCHECK *dcheck);

void discovery_register_host_inventory(DB_HOST_INVENTORY *inventory);

void discovery_register_interface(const DB_HOST *host, DB_INTERFACE *interface,  
		const char *ip, const char *dns, int port, const DB_DCHECK *dcheck);

void vector_to_str(zbx_vector_str_t *v, char **out, const char *split);
void vector_to_str_max(zbx_vector_str_t *v, char **out, const char *split, int max);
void str_to_vector(zbx_vector_str_t *out, const char *str, const char *split);
char * format_mac_address(char *mac_address);

void discovery_parsing_macs(const char *data, zbx_vector_str_t *out);
void discovery_parsing_value(const char *data, const char *field, char **out);
void discovery_parsing_value_model(const char *entphysicalmodelname, const char *sysdesc, const int dcheck_type, int *groupid, char **manufacturer, int *templateid);
void discovery_parsing_value_os(const char *sysdesc, char **out);


void host_rename(zbx_vector_ptr_t *v_hosts, int self_index, int device_type, char **host_name);

int get_2int_field(int old, int new);
char * get_2str_field(char *old, char *new);
char * get_2str_field_lfree(char *old, char *new);
char * get_2str_field_lrfree(char *old, char *new);
char * get_2str_field_rfree(char *old, char *new);

unsigned char	get_interface_type_by_dservice_type(unsigned char type);
int get_values_by_device_type(int devicetype, char **softdes, int *inventory_typeid, int *templateid);

void db_hosts_free(DB_HOST *host);

void init_discovery_hosts(int refresh);
void update_discovery_hosts(DB_HOST *mhost);
void destroy_discovery_hosts();

int	dc_find_hosts_by_devicetype_host(int device_type, char *host);
int	dc_find_hosts_by_hostid(int hostid);
int	dc_find_hosts_by_mac(int device_type, zbx_vector_str_t *macs);
int	dc_find_hosts_by_uuid(int device_type, char *uuid);
int	dc_find_hosts_by_ip(int dcheck_type, char *ip);

int update_hosts_values(int index, DB_HOST *mhost, char *ip);

int dc_find_update_hosts(DB_HOST *mhost, char *ip, int dcheck_type);
int dc_soft_find_update_hosts(DB_HOST *mhost, char *ip);

int discoverer_bind_templateid(DB_HOST *host);

int discovery_update_other(zbx_db_dhost *dhost);
#endif
