
#ifndef ZABBIX_DISCOVERER_MANAGER_H
#define ZABBIX_DISCOVERER_MANAGER_H

//这个进程里面有的线程
//manage      负责接trapper发过来的任务 & 回包 & 分配任务给worker(single单ip扫描)
//worker      负责单ip扫描
//discoverer  负责自动扫描和用户扫描 优先用户扫描
//discoverer2 负责同步用户扫描进度给trapper (这个任务可以放在manger中去做)

#include "zbxalgo.h"
#include "zbxvariant.h"
#include "zbxtime.h"
#include "zbxtimekeeper.h"
#include "zbxipcservice.h"
#include "discoverer_single.h"


#define DISCOVERER_WORKER_NUM	3

typedef struct
{
	pthread_t			thread;
	zbx_ipc_client_t	 *cli;   //manager(svr)和worker(cli)的通信 worker拉起来后会向server注册
}
discoverer_manager_worker_t;

typedef struct
{
	zbx_uint64_t    trapper_id;
    char           *json_buf;
}
discoverer_manager_task_t;

typedef struct 
{
	pthread_t			thread;
	zbx_vector_ptr_t	workers;
	zbx_queue_ptr_t		workers_free;
    int                 workers_num;
    zbx_vector_ptr_t    tasks;
	zbx_ipc_service_t	ipc;
	int				    status; //
}
discoverer_manager_t;

int discoverer_manager_destroy(discoverer_manager_t *manager);
int discoverer_manager_init(discoverer_manager_t *dm, char *error);

#endif







