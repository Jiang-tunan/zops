#ifndef DISCOVERER_NUTANIX_H
#define DISCOVERER_NUTANIX_H

#include "zbxalgo.h"
#include "zbxdb.h"
#include "zbxdbschema.h"
#include "zbxstr.h"
#include "zbxnum.h"
#include "zbxversion.h"
#include "zbxdiscovery.h"


typedef struct
{
    //zbx_uint64_t hostid;
	zbx_uint64_t hstgrpid;
    int type;    // 用来标识是hv还是vm。 定义为NUTANIX_SERVER_TYPE_HV和NUTANIX_SERVER_TYPE_VM
	
	char *fUuid;    //hv或vm 上一级的uuid，hv 和 vm协议上获得
    char *uuid;     //hv或vm 的uuid
	char *name;     //hv或vm 的name
    char *ip;       //hv或vm 的ip  
    
	char *serial;   		 //hv 的serial
	char *block_serial;      //hv 的block_serial
	char *block_model_name;  //hv 的block_serial
	char *disk;				 //hv 有磁盘信息
	char *cpu;				 //hv 有cpu信息
	char *bios; 			 //hv 有bios
	char *memory; 			 //hv 和 vm 有内存信息
	long disk_capacity;      //hv 有磁盘总容量

	int power_state;         //vm 的电源状态
	char *macs;              //vm 有mac地址列表
	 
} nutanix_server;

typedef struct
{
	zbx_db_drule *drule;
	const DB_DCHECK *dcheck;
	char *key;
	char *user;
	char *passwd;
	char *ip;
	int port;
} nutanix_arg;
 
void discover_nutanix(zbx_db_drule *drule, DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port);

void server_discover_nutanix_from_proxy(int scan_type, zbx_db_drule *drule, DB_DCHECK *dcheck,
	 zbx_vector_ptr_t *dhosts, char *bigvalue, char *ip, int port);

#endif