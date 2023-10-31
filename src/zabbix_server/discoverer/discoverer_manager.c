
#include "discoverer_manager.h"
#include "discoverer_protocol.h"
#include "zbxipcservice.h"
#include "discoverer.h"

static void	dm_register_worker(discoverer_manager_t *manager, zbx_ipc_client_t *client, zbx_ipc_message_t *message)
{
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);
	pthread_t thread;
	memcpy(&thread, message->data, sizeof(thread));
	discoverer_manager_worker_t	*worker = (discoverer_manager_worker_t *)zbx_malloc(NULL, sizeof(discoverer_manager_worker_t));	
	worker->cli = client;
	worker->thread = thread;

	zbx_vector_ptr_append(&manager->workers, worker);
	zbx_queue_ptr_push(&manager->workers_free, worker);
}

static void	dm_process_external_worker_request(discoverer_manager_t *manager, zbx_uint64_t trapper_cli_id, const unsigned char *data)
{
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	//反序列化
	char *json_in=NULL;
	zbx_discoverer_deserialize_json(data, &json_in);

	//加入任务队列
	discoverer_manager_task_t *task = (discoverer_manager_task_t *)zbx_malloc(NULL, sizeof(discoverer_manager_task_t));	
	task->trapper_id = trapper_cli_id;
	task->json_buf = json_in;
	zbx_vector_ptr_append(&manager->tasks,task);
}


static int	dm_process_worker_result(discoverer_manager_t *manager, zbx_ipc_client_t *client, zbx_ipc_message_t *message)
{
	char *json_buf;
	zbx_uint64_t trapper_id;

	zbx_discoverer_deserialize_tid_json(message->data, &trapper_id, &json_buf);

	zbx_ipc_client_t	*trapper_client;
	if (NULL != (trapper_client = zbx_ipc_client_by_id(&manager->ipc, trapper_id)))
	{
		unsigned char	*data;
		zbx_uint32_t	data_len;
		data_len = zbx_discoverer_serialize_json(&data, json_buf);
		zbx_ipc_client_send(trapper_client, ZBX_IPC_TRAPPER_SEND_SINGLE_SCAN, data, data_len);
		zbx_free(data);
	}
	else
		zabbix_log(LOG_LEVEL_DEBUG, "client has disconnected");

	//找到完成任务的worker 加入到free队列里面
	discoverer_manager_worker_t *worker = NULL;
	for (int i; i<manager->workers.values_num; i++)
	{
		discoverer_manager_worker_t *tmp = manager->workers.values[i];
		if (client == tmp->cli)
		{
			worker = tmp;
			break;
		}
	}

	if (!worker)
		zabbix_log(LOG_LEVEL_CRIT, "discoverer worker is NULL");

	zabbix_log(LOG_LEVEL_INFORMATION, "push back cli p:%p", worker->cli);
	zbx_queue_ptr_push(&manager->workers_free, worker);

	zbx_free(json_buf);
}

static void	*discoverer_manager_entry(void *args)
{

    discoverer_manager_t	*manager = (discoverer_manager_t *)args;

    zbx_ipc_client_t		*client;
    zbx_timespec_t			timeout = {1, 0};
    zbx_ipc_message_t		*message;
    int ret;

	while (1)
	{

		while (0 != manager->tasks.values_num)
		{
			//找到空闲的线程把任务分配下去
			discoverer_manager_worker_t *worker = NULL;
			if (NULL == (worker = (discoverer_manager_worker_t *)zbx_queue_ptr_pop(&manager->workers_free)))
				break;

			unsigned char *data = NULL;
			discoverer_manager_task_t *task = manager->tasks.values[0];
			zbx_uint32_t size = zbx_discoverer_serialize_tid_json(&data, task->trapper_id, task->json_buf);
			zbx_ipc_client_send(worker->cli, ZBX_IPC_DISCOVERER_SINGLE_SCAN, data, size);
			zbx_free(task->json_buf);
			zbx_free(task);
			zbx_vector_ptr_remove(&manager->tasks, 0);
			zbx_free(data);
		}

		//阻塞
		ret = zbx_ipc_service_recv(&manager->ipc, &timeout, &client, &message);

		if (NULL != message)
		{
			switch (message->code)
			{
				case ZBX_IPC_DISCOVERER_WORKER_REGISTER:
					dm_register_worker(manager, client, message);
					break;
                case ZBX_IPC_TRAPPER_SEND_SINGLE_SCAN:
					dm_process_external_worker_request(manager, zbx_ipc_client_id(client), message->data);
					break;
				case ZBX_IPC_DISCOVERER_WORKER_RESULT:
					dm_process_worker_result(manager, client, message);
                    break;
			}
			zbx_ipc_message_free(message);	
		}	

		if (NULL != client)
			zbx_ipc_client_release(client);
	}

	while (1)
		zbx_sleep(SEC_PER_MIN);

	discoverer_manager_destroy(manager);
}


int discoverer_manager_init(discoverer_manager_t *dm, char * error)
{
    if (FAIL == zbx_ipc_service_start(&dm->ipc, ZBX_IPC_SERVICE_DISCOVERER, &error))
	{
		zabbix_log(LOG_LEVEL_CRIT, "cannot start preprocessing service: %s", error);
		return FAIL;
	}

	zbx_vector_ptr_create(&dm->workers);
	zbx_vector_ptr_create(&dm->tasks);
	zbx_queue_ptr_create(&dm->workers_free);
	dm->workers_num = DISCOVERER_WORKER_NUM;

	int err;
	if (0 != (err = pthread_create(&dm->thread, NULL, discoverer_manager_entry, (void *)dm)))
	{
		zabbix_log(LOG_LEVEL_CRIT, "cannot create discoverer manager thread: %s", zbx_strerror(err));
		return FAIL;
	}

	return SUCCEED;
}

int discoverer_manager_destroy(discoverer_manager_t *manager)
{
    zbx_ipc_service_close(&manager->ipc);
    return SUCCEED;
}






