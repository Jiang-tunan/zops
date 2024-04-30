#ifndef DISCOVERER_COMM_H
#define DISCOVERER_COMM_H

#include "zbxalgo.h"
#include "zbxdb.h"
#include "zbxdbschema.h"
#include "zbxstr.h"
#include "zbxnum.h"
#include "zbxversion.h"
#include "zbxdiscovery.h"
#include "zbxcacheconfig.h"
#include "zbxhttp.h"
#include "zbxthreads.h"
#include "zbxsysinfo.h"
 
#define MAX_DB_SELECT_TIMES       		6   // 代理数据库查询重试次数
#define MAX_DB_SELECT_SLEEP_TIME       	3   // 数据库重试间隔时间

typedef struct
{
	int groupid;
	char *name;
	char *uuid;
	int type;
	int fgroupid;
	int hostid;
}discover_hstgrp;

typedef struct
{
	int hostid;
	char *uuid;
	int device_type;
	int hstgrpid;
}discover_hosts;

typedef struct
{
	int		scan_type;
	char	*value;
}
zbx_bigvalue_t;

typedef struct
{
	DB_RESULT result;
	DB_ROW row;
}zbx_db_info_t;

void free_discover_hstgrp(zbx_vector_ptr_t *v_hstgrps);
void free_discover_hosts(zbx_vector_ptr_t *v_host);

int	dc_compare_hstgrp(const void *d1, const void *d2);
int	dc_compare_hstgrp_uuid(const void *d1, const void *d2);
int	dc_compare_hosts(const void *d1, const void *d2);

int update_discover_hv_groupid(zbx_vector_ptr_t *v_hstgrps, int type, int hostid, char *uuid, char *name, int fgroupid);
int get_discover_vc_groupid(int type, char *ip, int proxy_hostid);
void get_discover_hosts(zbx_vector_ptr_t *v_hosts);

void dc_get_dchecks(zbx_db_drule *drule,  int unique, zbx_vector_ptr_t *dchecks, zbx_vector_uint64_t *dcheckids);

void copy_original_json(struct zbx_json_parse *jp, struct zbx_json *json_dest, int depth, zbx_map_t *map);
int copy_original_json2(zbx_json_type_t type, struct zbx_json_parse *jp, struct zbx_json *json_dest, int depth, zbx_map_t *map);

// proxy程序处理server的请求后返回应答
char *proxy_build_single_resp_json(char *request, zbx_vector_ptr_t *dchecks);

char *print_content(char *json);

void dc_proxy_update_hosts(zbx_uint64_t druleid, zbx_uint64_t dcheckid, const char *ip,const char *dns, int port, 
	int status, const char *value, int now, int scan_type, char *bigvalue);

void parse_bigvalue(zbx_vector_ptr_t *values, char *bigvalue);
void free_bigvalues(zbx_vector_ptr_t *values);
void parse_tsf_data(char *bigdata, char **data, char **extend_data);

void tgx_discovery_update_service(int scan_type, zbx_db_drule *drule, DB_DCHECK *dcheck, zbx_vector_ptr_t *dhosts,
		const char *ip, int port, const char *bigvalue);
		
int get_db_select_result(char *sql, zbx_db_info_t *db);
#endif