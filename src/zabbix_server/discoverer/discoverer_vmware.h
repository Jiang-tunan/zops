#ifndef DISCOVERER_VMWARE_H
#define DISCOVERER_VMWARE_H

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
    int type;    // 用来标识是hv还是vm。 定义为WMWARE_SERVER_TYPE_HV和WMWARE_SERVER_TYPE_VM
	
    char *dataCenterName;   //hv或vm 的dataCenterName
	char *clusterName;      //hv或vm 的clusterName

    char *uuid;     //hv或vm 的uuid
	char *id;       //hv或vm 的id
	char *name;     //hv或vm 的name
    char *ip;       //hv或vm 的ip

    char *parentName;   //hv获得parentName
	char *parentType;   //hv获得parentType
	char *hvNetName;    //hv的NetName，hv协议上获得

    char *hvUuid;       //hv的uuid，vm协议上获得

	char *macs;         //mac地址列表
	char *cpu;
	char *memory;
	
	int cpuNum;
	char *cpuMode;
	long totalMemory;
} vmware_server;

typedef struct
{
	zbx_db_drule *drule;
	const DB_DCHECK *dcheck;
	char *key;
	char *user;
	char *passwd;
	char *ip;
	int port;
} vmware_arg;
 
void discover_vmware(zbx_db_drule *drule, const DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port);

void server_discover_vmware_from_proxy(int scan_type, zbx_db_drule *drule, const DB_DCHECK *dcheck,
	 zbx_vector_ptr_t *dhosts, char *bigvalue, char *ip, int port);
#endif