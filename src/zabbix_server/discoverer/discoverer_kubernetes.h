#ifndef DISCOVERER_KUBERNETES_H
#define DISCOVERER_KUBERNETES_H

#include "zbxalgo.h"
#include "zbxdb.h"
#include "zbxdbschema.h"
#include "zbxstr.h"
#include "zbxnum.h"
#include "zbxversion.h"
#include "zbxdiscovery.h"

typedef struct
{
	zbx_uint64_t hstgrpid;
    char *name;
    char *uuid;
	char *os;
	
    char *ip; 
	int  port;
	char *macs;  
	 
} kubernetes_node;

typedef struct
{
	zbx_uint64_t hstgrpid;
    char *ip;
    zbx_vector_ptr_t nodes;
} kubernetes_server;

void discover_kubernetes(int recv_type, char * session, const DB_DCHECK *dcheck);

#endif