#ifndef DISCOVERER_VMWARE_H
#define DISCOVERER_VMWARE_H

#include "zbxalgo.h"
#include "zbxdb.h"
#include "zbxdbschema.h"
#include "zbxstr.h"
#include "zbxnum.h"
#include "zbxversion.h"
#include "zbxdiscovery.h"

#define VMWARE_GROUP_TYPE_VC			2 //VC中心
#define VMWARE_GROUP_TYPE_DATACENTER	3 //数据中心
#define VMWARE_GROUP_TYPE_CLUSTER		4 //集群

#define VMWARE_SERVER_HV_GROUPID			3  //服務器的groupid
#define VMWARE_SERVER_VM_GROUPID			2  //虚拟机的groupid

#define VMWARE_SERVER_HV_TEMPLATEID			17 //物理机VMware模板id
#define VMWARE_SERVER_VM_TEMPLATEID			18 //虚拟机VMware模板id

#define VMWARE_SERVER_TYPE_HV       1 //物理机
#define VMWARE_SERVER_TYPE_VM		2 //虚拟机

typedef struct
{
	int groupid;
	char *name;
	char *uuid;
	int type;
	int fgroupid;
}vmware_hstgrp;

typedef struct
{
	int hostid;
	char *uuid;
	int device_type;
	int hstgrpid;
}vmware_hosts;

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
	const zbx_db_drule *drule;
	const DB_DCHECK *dcheck;
	char *key;
	char *user;
	char *passwd;
	char *ip;
	int port;
} vmware_arg;
 
void discover_vmware(const zbx_db_drule *drule, const DB_DCHECK *dcheck,
	char *keys, char *user, char *passwd, char *ip, int port);

#endif