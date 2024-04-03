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
#endif