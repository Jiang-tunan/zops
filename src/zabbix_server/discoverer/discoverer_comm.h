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

void free_discover_hstgrp_ptr(discover_hstgrp *p_hstgrp);
void free_discover_hosts_ptr(discover_hosts *p_host);

int	dc_compare_hstgrp(const void *d1, const void *d2);
int	dc_compare_hstgrp_uuid(const void *d1, const void *d2);
int	dc_compare_hosts(const void *d1, const void *d2);

int update_discover_hv_groupid(zbx_vector_ptr_t *v_hstgrps, int type, int hostid, char *uuid, char *name, int fgroupid);
int get_discover_vc_groupid(int type, char *ip);
void get_discover_hosts(zbx_vector_ptr_t *v_hosts);

int pack_bind_templateid_json_req(int hostid, int templateid,int groupid,int status,int id,char *auth,char* buf);


int bind_templateid_http_req_rsp(char* json_body_str,char **out_value, DB_DCHECK *dcheck, int maxTry);

#endif