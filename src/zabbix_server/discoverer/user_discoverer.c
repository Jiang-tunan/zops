#ifndef ZABBIX_USER_DISCOVERER_C
#define ZABBIX_USER_DISCOVERER_C

#include "user_discoverer.h"
#include "discoverer_single.h"
#include "discoverer_vmware.h"
#include "zbxmutexs.h"
#include "zbxip.h"
#include "zbxserver.h"

zbx_mutex_t		user_discover_lock = ZBX_MUTEX_NULL;
zbx_user_discover_drules_t	*user_discover_g   = NULL;


//清理全部 用户扫描数据，进程退出时调用
void zbx_user_discover_g_free()
{
	LOCK_USER_DISCOVER;
	if (NULL == user_discover_g)
	{
		UNLOCK_USER_DISCOVER;
		return;
	}

	__zbx_user_discover_clean();
	zbx_vector_ptr_destroy(&user_discover_g->drules);
	zbx_free(user_discover_g);
	UNLOCK_USER_DISCOVER;
}


void __zbx_user_discover_session_free(zbx_vector_ptr_t *v_session, int index)
{
	if(NULL == v_session)  return;

	zbx_user_discover_session_t *ptr = (zbx_user_discover_session_t *)v_session->values[index];
	if(ptr->progress >= 0)
	{
		ptr->progress = -1;
		zbx_vector_ptr_clear_ext(&ptr->hostids, zbx_ptr_free);
		zbx_vector_ptr_destroy(&ptr->hostids);
	}
	zbx_vector_ptr_remove(v_session, index);
}


void __zbx_user_discover_drule_free(zbx_user_discover_drule_t *ptr)
{
	zbx_vector_ptr_clear_ext(&ptr->alarms, zbx_ptr_free);
	zbx_vector_ptr_destroy(&ptr->alarms);
	zbx_vector_ptr_clear_ext(&ptr->sessions, zbx_ptr_free);
	zbx_vector_ptr_destroy(&ptr->sessions);
	ptr->status = ZBX_USER_DISCOVER_STATUS_FREE;
}

//清理任务
void __zbx_user_discover_clean()
{
	zbx_vector_ptr_clear_ext(&user_discover_g->drules, (zbx_mem_free_func_t)__zbx_user_discover_drule_free);
	zbx_vector_ptr_clear(&user_discover_g->drules);
	user_discover_g->druleid = 0;
	user_discover_g->need_scan_druleid_num = 0;
}


//只负责按session清理任务 返回:是否还有下一个任务
int __zbx_user_discover_session_timout()
{
	int has_next = 1;
	int now = time(NULL);
	for(int i=0; i<user_discover_g->drules.values_num; i++)
	{
		zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[i];
		for(int j = 0; j < drule->sessions.values_num; j ++)
		{
			int timeout = drule->ip_all_num * USER_DISCOVER_IP_TIME_OUT;
			zbx_user_discover_session_t *session = (zbx_user_discover_session_t *)drule->sessions.values[j];
			if (now < session->sbegin_time + timeout)
				continue;
			__zbx_user_discover_session_clean_from_drule(i, drule, session->session);
		}
		
	}

	return has_next;
}

//用户扫描任务创建
int	user_discover_create(const char *session, zbx_vector_ptr_t *v_drules)
{
	// zbx_vector_uint64_sort(v_drules, ZBX_DEFAULT_UINT64_COMPARE_FUNC);
	// zbx_vector_uint64_uniq(v_drules, ZBX_DEFAULT_UINT64_COMPARE_FUNC);

	char			*sql = NULL;
	size_t			sql_alloc = 0, sql_offset = 0;
	DB_RESULT		result;
	DB_ROW			row;
	int             ret=FAIL;
	zbx_user_discover_drule_t *dr = NULL;

	zbx_vector_uint64_t druleids;
	zbx_vector_uint64_create(&druleids);
	for(int i = 0; i < v_drules->values_num; i ++){
		dr = (zbx_user_discover_drule_t *)v_drules->values[i];
		zbx_vector_uint64_append(&druleids, dr->druleid);  // 将druleid添加到向量中
	}

	zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, "select druleid, iprange from drules where");
	zbx_db_add_condition_alloc(&sql, &sql_alloc, &sql_offset, "druleid", druleids.values, druleids.values_num);
	result = zbx_db_select(sql);

	zbx_vector_uint64_pair_t rid_ipnum;
	zbx_vector_uint64_pair_create(&rid_ipnum);
	while (NULL != (row = zbx_db_fetch(result)))
	{
		zbx_iprange_t iprange;
		if (SUCCEED != zbx_iprange_parse(&iprange, row[1]))
		{
			zabbix_log(LOG_LEVEL_WARNING, "#ZOPS#%s ruleid:%s: wrong format of IP range:%s",__func__, row[0], row[1]);
			continue;
		}

		zbx_uint64_pair_t	pair;
		ZBX_STR2UINT64(pair.first, row[0]);
		pair.second = zbx_iprange_volume(&iprange);
		zbx_vector_uint64_pair_append(&rid_ipnum, pair);
	}

	if (!rid_ipnum.values_num)
		goto out;

	LOCK_USER_DISCOVER;
	if (NULL == user_discover_g)
	{
		goto out;
	}

	// 首先检测整个user_discover_g队列 session是否超时；
	__zbx_user_discover_session_timout();

	for(int i=0; i<v_drules->values_num; i++)
	{
		dr = (zbx_user_discover_drule_t *)v_drules->values[i];
		int index_drule;
		if (FAIL != (index_drule = zbx_vector_ptr_bsearch(&user_discover_g->drules, &(dr->druleid), ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
		{
			zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s druleid:[%d] is in tasks",__func__, dr->druleid);
			zbx_user_discover_drule_t *old_dr = (zbx_user_discover_drule_t *)user_discover_g->drules.values[index_drule];
			if (FAIL == zbx_vector_ptr_bsearch(&old_dr->sessions, session, ZBX_DEFAULT_STR_COMPARE_FUNC))
			{
				zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s druleid:[%d] add session:[%s]", __func__, dr->druleid, session);
				 
				zbx_user_discover_session_t *t_session = (zbx_user_discover_session_t *)zbx_malloc(NULL, sizeof(zbx_user_discover_session_t));
				memset(t_session, 0, sizeof(zbx_user_discover_session_t));
				
				t_session->sbegin_time = time(NULL);
				zbx_strscpy(t_session->session,  session);
				zbx_vector_ptr_create(&t_session->hostids);
				
				zbx_vector_ptr_append(&old_dr->sessions, t_session);
			}
			continue;   //对应的规则id已经找到，说明已经创建过一次，不做任何处理，继续
		}

		zbx_uint64_pair_t pair;
		int index_ipnum;
		pair.first = dr->druleid;
		if (FAIL == (index_ipnum = zbx_vector_uint64_pair_search(&rid_ipnum, pair, ZBX_DEFAULT_UINT64_COMPARE_FUNC)))
			continue;

		// zbx_user_discover_drule_t *dr = (zbx_user_discover_drule_t *)zbx_malloc(NULL, sizeof(zbx_user_discover_drule_t));
		// memset(dr, 0, sizeof(zbx_user_discover_drule_t));
		
		//首次创建任务
		dr->status = ZBX_USER_DISCOVER_STATUS_CREATE;
		
		// dr->druleid=v_drules->values[i];
		// VMWare扫描，这个逻辑比较特殊，先把ip地址多少设置为160
		if(SVC_VMWARE  == dr->check_type){
			dr->ip_all_num= 160;  
		}else{
			dr->ip_all_num=rid_ipnum.values[index_ipnum].second;
		}
		zbx_vector_ptr_create(&dr->alarms);
		zbx_vector_ptr_create(&dr->sessions);
 
		zbx_user_discover_session_t *t_session = (zbx_user_discover_session_t *)zbx_malloc(NULL, sizeof(zbx_user_discover_session_t));
		memset(t_session, 0, sizeof(zbx_user_discover_session_t));
		t_session->sbegin_time = time(NULL);
		zbx_vector_ptr_create(&t_session->hostids);
		zbx_strscpy(t_session->session,  session);

		zbx_vector_ptr_append(&dr->sessions, t_session);
		 
		zbx_vector_ptr_append(&user_discover_g->drules, dr);

		zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s add success. type=%d, druleid=%d, ", __func__, dr->check_type, dr->druleid);
		
		// 需要扫描的规则增加了1个
		user_discover_g->need_scan_druleid_num ++; 
		
		// 通知discover进程立刻处理
		notify_discover_thread();
	}
	ret = SUCCEED;

out:

	UNLOCK_USER_DISCOVER;
	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s result:%d",__func__, ret);
	zbx_vector_uint64_destroy(&druleids); 
	zbx_vector_uint64_pair_destroy(&rid_ipnum);
	zbx_free(sql);
	zbx_db_free_result(result);
	return ret;
}

//只负责按session清理任务 返回:是否还有下一个任务
int __zbx_user_discover_session_clean_from_drule(int index, zbx_user_discover_drule_t *drule, const char *session)
{ 
	int index_session;
	index_session = zbx_vector_ptr_bsearch(&drule->sessions, session, ZBX_DEFAULT_STR_COMPARE_FUNC);
	if(FAIL != index_session){
		__zbx_user_discover_session_free(&drule->sessions,index_session);
	}
	if (drule->sessions.values_num)
		return SUCCEED;
	__zbx_user_discover_drule_free(drule);
	zbx_vector_ptr_remove(&user_discover_g->drules, index);
	user_discover_g->need_scan_druleid_num --;
	return SUCCEED;
}

/****
 * 清理所有session相关的扫描任务
 * 返回: SUCCEED:成功  FAIL: 没有此seesion
 */
int __zbx_user_discover_session_clean(const char *session)
{
	int result = FAIL;
	if (NULL == user_discover_g)
	{
		return FAIL;
	}
	for(int i=0; i<user_discover_g->drules.values_num; i++)
	{
		zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[i];
		
		if(SUCCEED == __zbx_user_discover_session_clean_from_drule(i, drule, session))
		{
			result = SUCCEED;
		}
		
	}

	return result;
}



//用户扫描任务停止
int	user_discover_stop(const char *session)
{
	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s session:[%s]", __func__, session);

	LOCK_USER_DISCOVER;
	
	int result = DISCOVERY_RESULT_SUCCESS;
	//清理该用户的扫描数据
	if(FAIL == __zbx_user_discover_session_clean(session))
	{
		result = DISCOVERY_RESULT_STOP_FAIL;
	}

	UNLOCK_USER_DISCOVER;
	return result;
}

//用户扫描进度
char* user_discover_progress(const char * session, const struct zbx_json_parse *jp)
{
	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s session:[%s]", __func__, session);
 
	return create_progress_json(session, jp);
}
 
//扫描完一个ip 更新数据 ret:是否开始下一个ip段的扫描
void user_discover_next_ip(zbx_uint64_t druleid, int *next_drule)
{
	*next_drule = 0;  // 0:继续扫描， 1：停止
	LOCK_USER_DISCOVER;
	if (NULL == user_discover_g)
		goto out;
 

	int index_drule;
	//规则扫描到半被停止了 下一个规则已经在停止的时候确定了
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&user_discover_g->drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s stop scan. druleid:[%llu]", __func__, druleid);
		*next_drule = 1;
		goto out;
	}

	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[index_drule];
	drule->ip_discovered_num++;
	if(drule->ip_discovered_num >= drule->ip_all_num)
	{
		drule->status = ZBX_USER_DISCOVER_STATUS_FINISH;
	}
	for(int j = 0; j < drule->sessions.values_num; j ++)
	{
		zbx_user_discover_session_t *session = (zbx_user_discover_session_t *)drule->sessions.values[j];
		session->sbegin_time = time(NULL);
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s druleid:[%llu] status:[%d],discovered_num=%d,all_num=%d,next_drule=%d", __func__, druleid, drule->status,
		drule->ip_discovered_num, drule->ip_all_num,*next_drule);

 
out:
	UNLOCK_USER_DISCOVER;
	return;
}

//扫描完一个druleid 更新数据 返回下一个需要扫描的druleid
int user_discover_next_druleid(zbx_uint64_t *druleid)
{
	LOCK_USER_DISCOVER;
	int next = FAIL;  //是否有下一条规则是否需要扫描, FAIL:没有，SUCCEED：有
	if (NULL != user_discover_g && user_discover_g->need_scan_druleid_num > 0 
		&& user_discover_g->drules.values_num)
	{
		for(int i=0; i<user_discover_g->drules.values_num; i++)
		{
			zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[i];
			if(drule->status == ZBX_USER_DISCOVER_STATUS_CREATE)
			{
				drule->status = ZBX_USER_DISCOVER_STATUS_RUN;
				*druleid = drule->druleid;
				user_discover_g->druleid = drule->druleid;
				next = SUCCEED;
				zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s druleid_num:[%d],druleid=%llu,next=%d", __func__, 
					user_discover_g->need_scan_druleid_num, *druleid, next);
				break;
			}
		}
	}
	

	UNLOCK_USER_DISCOVER;
	return next;
}

// VMWare扫出来的ip数不固定，这增加扫描ip数
int vmware_add_ip_num(zbx_uint64_t druleid, int type, int ip_num)
{
	LOCK_USER_DISCOVER;
	if (NULL == user_discover_g)
	{
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	int index_drule;
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&user_discover_g->drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS# %s, search druleid fail. druleid:%s", __func__, druleid);
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[index_drule];
	switch (type)
	{
	case VMWARE_SERVER_TYPE_HV:
		drule->hv_num += ip_num;
		break;
	case VMWARE_SERVER_TYPE_VM:
		drule->vm_num += ip_num;
		break;
	default:
		break;
	} 
	
	UNLOCK_USER_DISCOVER;
	return SUCCEED;
}

// VMWare扫出来的ip数不固定，这增加扫描ip数
int vmware_add_discovered_ip_num(zbx_uint64_t druleid, int type, int ip_num)
{
	LOCK_USER_DISCOVER;
	if (NULL == user_discover_g)
	{
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	int index_drule;
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&user_discover_g->drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s, search druleid fail. druleid:%d", __func__, druleid);
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	int count_num = 0;
	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[index_drule];

	switch (type)
	{
	case VMWARE_SERVER_TYPE_HV:
		if(ip_num <= 1){
			drule->hv_count ++;
			count_num = (int)(((float)drule->hv_count/(float)drule->hv_num)*50);
			if(count_num > 0) drule->hv_count = 0;
			drule->ip_discovered_num += count_num;
		}
		else if(ip_num >= drule->hv_num){
			count_num = ip_num;
			drule->ip_discovered_num = 60;
		}
		
		break;
	case VMWARE_SERVER_TYPE_VM:
		if(ip_num <= 1){
			drule->vm_count += ip_num;
			count_num = (int)(((float)drule->vm_count/(float)drule->vm_num)*100);
			if(count_num > 0) drule->vm_count = 0;
			drule->ip_discovered_num += count_num;
		}else if(ip_num >= drule->vm_num){
			count_num = ip_num;
			drule->ip_discovered_num = 160;
		}
		break;
	default:
		count_num = ip_num;
		drule->ip_discovered_num += count_num;
		break;
	} 
	
	if(drule->ip_discovered_num >= drule->ip_all_num)
	{
		drule->status = ZBX_USER_DISCOVER_STATUS_FINISH;
	}
	for(int j = 0; j < drule->sessions.values_num; j ++)
	{
		zbx_user_discover_session_t *session = (zbx_user_discover_session_t *)drule->sessions.values[j];
		session->sbegin_time = time(NULL);
	}
	zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s, index_drule=%d, type=%d, count_num=%d", __func__, index_drule, type, count_num);
	UNLOCK_USER_DISCOVER;
	return SUCCEED;
}

// 添加已经扫描出来的hostid
int user_discover_add_hostid(zbx_uint64_t druleid, zbx_uint64_t hostid)
{
	if (NULL == user_discover_g)
	{
		return FAIL;
	}

	LOCK_USER_DISCOVER;
	
	int index_drule;
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&user_discover_g->drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s, search druleid fail. druleid:%ld, hostid:%ld", __func__, druleid, hostid);
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[index_drule];
	for(int j = 0; j < drule->sessions.values_num; j ++)
	{
		zbx_user_discover_session_t *session = (zbx_user_discover_session_t *)drule->sessions.values[j];
		char *hostid_s = (char *)zbx_malloc(NULL, 22);
		zbx_snprintf(hostid_s, sizeof(hostid_s), ZBX_FS_UI64, hostid);
		zbx_vector_ptr_append(&session->hostids, hostid_s);
		zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s, success. session:%s, hostid:%d", __func__, session->session, hostid);
	}
	
	UNLOCK_USER_DISCOVER;
	return SUCCEED;
}

// 添加告警
int user_discover_add_alarm(zbx_uint64_t druleid, const char *ip, const int port)
{
	if (NULL == user_discover_g)
	{
		return FAIL;
	}
	LOCK_USER_DISCOVER;
	int index_drule;
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&user_discover_g->drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	zbx_user_discover_drule_t *dr = (zbx_user_discover_drule_t *)user_discover_g->drules.values[index_drule];

	zbx_user_discover_alarm_t *alarm = NULL;
	alarm = (zbx_user_discover_alarm_t *)zbx_malloc(NULL, sizeof(zbx_user_discover_alarm_t));
	memset(alarm, 0, sizeof(zbx_user_discover_alarm_t));
	zbx_strlcpy_utf8(alarm->ip, ip, ZBX_INTERFACE_IP_LEN_MAX);
	alarm->port = port;
	zbx_vector_ptr_append(&dr->alarms, alarm);
	UNLOCK_USER_DISCOVER;
	return SUCCEED;
}

/*zhul content*/
void discovery_rules_discoverer_thread_init()
{
	
	zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s",__func__);
	struct json_queue* thread_arg = (struct json_queue*)zbx_malloc(NULL, sizeof(struct json_queue));
	if (NULL == thread_arg) {
		zabbix_log(LOG_LEVEL_ERR, "#ZOPS#Failed to allocate memory for thread_arg");
	}

	if(-1 == (msgid = msgget(MSG_KEY, 0666 | IPC_CREAT)))
	{
		zabbix_log(LOG_LEVEL_WARNING, 
			"#ZOPS#%s, msgqueue creat fail! msgid=%d, errmsg=%s", 
			__func__, msgid, strerror(errno));
	}


	thread_arg->type = DCR_MSG_TYPE;
	pthread_t drd_thread; // 接收线程
	if (0 != pthread_create(&drd_thread, NULL, discovery_rules_discoverer_thread_function, thread_arg)) 
	{
		// # 未定义错误信息
		zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#thread_init#Failed to create msg_queue_thread !!!");
	}
}


void* discovery_rules_discoverer_thread_function(void* arg) 
{
	if (NULL == arg) 
	{
		zabbix_log(LOG_LEVEL_ERR, "#ZOPS#Thread argument is NULL");
		pthread_exit(NULL);
	}
	int count = 1;
	struct json_queue* recv_msg = (struct json_queue*)arg;
	struct zbx_json_parse	jp;
	char value[BUFSIZ] = "";
	while (ZBX_IS_RUNNING() && count <= 5)
	{
		// 读取消息
		if (-1 == msgrcv(msgid, (void *)recv_msg, BUFSIZ, DCR_MSG_TYPE, 0))
		{
			int old_msgid = msgid;
            zbx_sleep(count * 5);
			// 碰到过消息队列失败情况,这里增加重试机制。如果重试3次都没有创建队列，则退出线程。
			if(-1 == (msgid = msgget(MSG_KEY, 0666 | IPC_CREAT))){
				count ++;
			}else{
				count = 0;
			}
			zabbix_log(LOG_LEVEL_ERR, "#ZOPS#discovery_rules. Failed to receive message from queue,o_msgid=%d,msgid=%d",
				old_msgid, msgid);
			continue;
        }
		else
		{
			// 解析 json 数据 request 字段
			zbx_rtrim(recv_msg->content, " \r\n");	// 删除末尾字符 空格 回车 换行
			if (SUCCEED != zbx_json_open(recv_msg->content, &jp))
			{
				continue;
			}
			else if (SUCCEED != zbx_json_value_by_name(&jp, ZBX_PROTO_TAG_REQUEST, value, sizeof(value), NULL))
			{
				continue;
			}
			else
			{
				discovery_rules_select(value, recv_msg->recv_type, &jp);
			}
		}

	}
	zbx_json_free(&jp);
	free(arg);
    pthread_exit(NULL);
}

/*********************************************
 * Function_Name:discovery_rules_select
 *
 * Decscription: 根据 request 进行对应操作
 *
 * Parameter :
 * 	@ request_value			请求值
 *  @ jp					请求报文指针

 *
 * Return : 
 * 
************************************************/
void discovery_rules_select(const char* request_value,int recv_type, const struct zbx_json_parse *jp)
{
	
	char *response = NULL;
	char session_value[MAX_STRING_LEN];

	// 提取 session
	if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), NULL))
	{
		response = create_fail_json(request_value, "", DISCOVERY_RESULT_NO_SESSION, "NO session");
	}
	// 比较 request 值 进行对应操作
	else if (SUCCEED == zbx_strcmp_null(request_value, DISCOVERY_CMD_ACTIVITE)) 
	{
		zbx_vector_ptr_t druleids;
		zbx_vector_ptr_create(&druleids);  // 创建向量

		// 提取 druleids
		if (SUCCEED != parse_rules_activate(jp, &druleids))
		{
			response = create_fail_json(request_value, session_value, DISCOVERY_RESULT_NO_DRULEID, "No druleids");
		}
		// 启动 user_discover_create
		else if(SUCCEED == user_discover_create(session_value, &druleids))
		{
			response = create_activate_or_stop_json(DISCOVERY_CMD_ACTIVITE, session_value, jp);
		}
		else
		{
			response = create_fail_json(request_value, session_value, DISCOVERY_RESULT_CREATE_FAIL, "discover_create fail");
		}

 		// 在完成后销毁向量,必须在zbx_vector_uint64_create后调用，否则会crash
		zbx_vector_uint64_destroy(&druleids); 
	} 
	else if (SUCCEED == zbx_strcmp_null(request_value, DISCOVERY_CMD_PROGRESS))
	{
		// 调用扫描进度查询
		response = user_discover_progress(session_value, jp);
	} 
	else if (SUCCEED == zbx_strcmp_null(request_value, DISCOVERY_CMD_STOP))
	{
		// 停止user_discover_stop()
		if(SUCCEED != user_discover_stop(session_value))
		{
			response = create_fail_json(request_value, session_value, DISCOVERY_RESULT_STOP_FAIL ,"discover_stop fail");
		}
		else
		{
			response = create_activate_or_stop_json(DISCOVERY_CMD_STOP, session_value, jp);
		}
	} 
	else if (SUCCEED == zbx_strcmp_null(request_value, DISCOVERY_CMD_SINGLE_SCAN))
	{
		if(DISCOVERY_RESULT_SUCCESS == discover_single_scan(recv_type, session_value, jp, &response))
		{
			// 成功了，已经由单设备扫描线程发送返回应答，这里不要返回
			response = NULL;
		}
	}
	else
	{
		// 未识别
	}
	
	discover_response_replay(recv_type, response);
	zbx_free(response);
}

int query_druleid_progress(const char * session, zbx_uint64_t druleid, 
	int *out_progress, int *out_remain_time, char **out_hostids)
{
	// 计算进度
	int progress = 0, remain_time = 0;
	int need_remove_druleid = 0;
	int index_drule,index_session;
	zbx_user_discover_session_t *dsession = NULL;

	LOCK_USER_DISCOVER;
	if (NULL == user_discover_g || druleid == 0)
	{
		UNLOCK_USER_DISCOVER;
		return DISCOVERY_RESULT_QUERY_FAIL;
	}
	// 查用户某个druleid进度
	if (FAIL != (index_drule = zbx_vector_ptr_bsearch(&user_discover_g->drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)user_discover_g->drules.values[index_drule];
		
		if (drule->ip_all_num > 0)
		{

			if (drule->ip_discovered_num >= drule->ip_all_num)
			{
				progress = 100;
				need_remove_druleid = 1;
			}
			else
			{
				int remaining_ips = drule->ip_all_num - drule->ip_discovered_num; // 计算剩余的IP数量
				remain_time = remaining_ips * USER_DISCOVER_IP_INTERVAL_TIME;									// 剩余时间 = 剩余IP数量 * 3秒
				progress = (double)(drule->ip_discovered_num / (double)drule->ip_all_num) * 100;
				if (FAIL != (index_session = zbx_vector_ptr_bsearch(&drule->sessions, session, ZBX_DEFAULT_STR_COMPARE_FUNC)))
				{
					time_t now = time(NULL);
					int alltime = drule->ip_all_num * USER_DISCOVER_IP_INTERVAL_TIME;
					int timeout = drule->ip_all_num * USER_DISCOVER_IP_TIME_OUT;
					dsession = (zbx_user_discover_session_t *)drule->sessions.values[index_session];
					dsession->query_number ++;

					if (now >= dsession->sbegin_time + timeout)  //session超时，则移除session
					{
						__zbx_user_discover_session_free(&drule->sessions, index_session);

						// 该ruldid下没有任何任务，就从队列中移除ruldid
						if(drule->sessions.values_num == 0)
						{
							need_remove_druleid = 1;
						}
						progress = 100;
						remain_time = 0;
					}
					else if (progress > dsession->progress) // 当前进度比缓存的进度更多，用新的进度
					{
						dsession->progress = progress;
					}
					else if (progress <= dsession->progress && dsession->progress < 99) // 当前进度没有任何进展，则每次查询时候，把进度加1
					{
						//前端每2秒查询一次，每次过去时间为2秒，每次查询进度为 消耗时间除以总时间。
						int t_progress = ((double)(dsession->query_number * USER_DISCOVER_QUERY_INTERVAL_TIME) / (double)alltime) * 100;
						if(t_progress > progress && t_progress < 99)
							dsession->progress = t_progress;
						else
							dsession->progress ++;

						progress = dsession->progress;
						remain_time = ((double)(100-progress)/(double)100) * alltime;
					}
					else // 上次进度为99情况下，但是实际扫描进度没有那么多情况下，继续用99进度 
					{ 
						progress = dsession->progress;
					}
					
				}else
				{
					UNLOCK_USER_DISCOVER;
					return DISCOVERY_RESULT_NO_SESSION;

				}
			}

			// 返回扫描出来的设备hostid，格式为 hostid1,hostid2.....
			char hostids[5120] = {""};
			if (FAIL != (index_session = zbx_vector_ptr_bsearch(&drule->sessions, session, ZBX_DEFAULT_STR_COMPARE_FUNC)))
			{
				dsession = (zbx_user_discover_session_t *)drule->sessions.values[index_session];
				//zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s, get hostids. hostids_num:%d", __func__, dsession->hostids.values_num);
			
				for(int k = dsession->hostids.values_num - 1; k >= 0; k --)
				{
					char *str_hostid = (char *)dsession->hostids.values[k]; 
					strcat(hostids, str_hostid);
					if(k > 0)
						strcat(hostids, ",");
					zbx_free(str_hostid);
					zbx_vector_ptr_remove(&dsession->hostids, k);
				}
			}
			*out_hostids = zbx_strdup(NULL,hostids);
			zabbix_log(LOG_LEVEL_INFORMATION, "#ZOPS#%s, get hostids success. session:%s, hostids:%s", __func__, dsession->session, hostids);
		}
		else
		{
			progress = 100;
			need_remove_druleid = 1;
		}

		zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s status=%d,all_num=%d,discovered_num=%d,progress=%d,remain_time=%d,need_remove=%d", __func__, 
				drule->status, drule->ip_all_num,drule->ip_discovered_num, progress,remain_time,need_remove_druleid);

		// 如果100%了或者超时 就移除该ruleid的任务 如果没有下一个任务了就清理所有任务
		if (drule->ip_discovered_num >= drule->ip_all_num || need_remove_druleid)
		{
			__zbx_user_discover_session_clean_from_drule(index_drule, drule, session);
		}

	}
	else
	{
		UNLOCK_USER_DISCOVER;
		return DISCOVERY_RESULT_NO_DRULEID;
	}
	*out_progress = progress;
	*out_remain_time = remain_time;
	UNLOCK_USER_DISCOVER;
	return SUCCEED;
}

/*********************************************
 * Function_Name:create_progress_json
 *
 * Decscription: 创建进度回复报文
 *
 * Parameter :
 * 	@ session_value`		响应 session 值
 *  @ jp					请求报文指针
 * 	@ pdrule		扫描进度 结构体
 *
 * Return : 
 *  result	 				json 回复报文字符串
************************************************/
char* create_progress_json(const char* session_value, const struct zbx_json_parse *jp) 
{
    struct zbx_json j;
    struct zbx_json_parse data_jp;
    char druleid_str[MAX_STRING_LEN];
	const char *p = NULL;

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	// 添加response键值
	zbx_json_addstring(&j, "response", DISCOVERY_CMD_PROGRESS, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&j, "session", session_value, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&j, "result", DISCOVERY_RESULT_SUCCESS);

	// 开始"data"数组
	zbx_json_addarray(&j, "data");
	if (SUCCEED == zbx_json_brackets_by_name(jp, "params", &data_jp))
	{
		while (NULL != (p = zbx_json_next(&data_jp, p)))
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				// 从当前对象中提取druleid的值
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "druleid", druleid_str, sizeof(druleid_str), NULL))
				{
					int ret = 0;
					int progress = 0;
					int remain_time = 0;
					char *hostids = NULL;

					zbx_uint64_t druleid = 0;
					zbx_lrtrim(druleid_str, ZBX_WHITESPACE);
					zbx_is_uint64(druleid_str, &druleid);
					 
					zbx_json_addobject(&j, NULL);
					zbx_json_addint64(&j, "druleid", druleid);// 是否选择使用 user_discover中的值?
						
					ret = query_druleid_progress(session_value, druleid, &progress, &remain_time, &hostids);

					zbx_json_addint64(&j, "result", ret);  
					zbx_json_addint64(&j, "progress", progress);
					zbx_json_addint64(&j, "remain_time", remain_time);
					zbx_json_addstring(&j, "hostids", hostids, ZBX_JSON_TYPE_STRING);
					zbx_json_close(&j);
				}
			}
		}
	}	
    zbx_json_close(&j);
    char *json = strdup(j.buffer);
    zbx_json_free(&j);
    return json;
}

/*********************************************
 * Function_Name:create_activate_json
 *
 * Decscription: 创建启动扫描回复报文
 *
 * Parameter :
 * 	@ session_value			响应 session 值
 *  @ jp					请求报文指针
 *
 * Return : 
 *  result	 				json 回复报文字符串
************************************************/
char* create_activate_or_stop_json(const char *response, const char *session_value, const struct zbx_json_parse *jp)
{
    struct zbx_json j;
    struct zbx_json_parse data_jp;
    char druleid_str[MAX_STRING_LEN];
	const char *p = NULL;

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	zbx_json_addstring(&j, "response", response, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&j, "session", session_value, ZBX_JSON_TYPE_STRING);
	
	zbx_json_addint64(&j, "result", DISCOVERY_RESULT_SUCCESS);
	// 开始"data"数组
	zbx_json_addarray(&j, "data");
	if (SUCCEED == zbx_json_brackets_by_name(jp, "params", &data_jp))
	{
		while (NULL != (p = zbx_json_next(&data_jp, p)))
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				// 从当前对象中提取druleid的值
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "druleid", druleid_str, sizeof(druleid_str), NULL))
				{
					zbx_json_addobject(&j, NULL);
					zbx_json_addstring(&j, "druleid", druleid_str, ZBX_JSON_TYPE_STRING);
					zbx_json_addint64(&j, "result", DISCOVERY_RESULT_SUCCESS);
				}
			}
		}
	}
    zbx_json_close(&j);
    char *json = strdup(j.buffer);
    zbx_json_free(&j);
    return json;
}
 
/*********************************************
 * Function_Name:create_fail_json
 *
 * Decscription: 创建 错误响应报文
 *
 * Parameter :
 * 	@ failresion			错误原因
 *
 * Return : 
 *  result	 				json 错误报文字符串
************************************************/
char* create_fail_json(const char* response, const char* session, int result, const char* failreason)
{
	struct zbx_json j;
    struct zbx_json_parse data_jp;
	const char *p = NULL;

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	zbx_json_addstring(&j, "response", response, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&j, "session", session, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&j, "result", result);
	zbx_json_addstring(&j, "retmsg", failreason, ZBX_JSON_TYPE_STRING);

	zbx_json_close(&j);
    char *json = strdup(j.buffer);
    zbx_json_free(&j);
    return json;
}

/*********************************************
 *
 * Decscription: 提取规则
 *
 * Parameter :
 *  @ jp					请求报文指针
 *	@ druleids				存放规则
 * Return : 
 *  SUCCEED					提取成功 存入 druleids
 *	FAIL					提取失败
************************************************/
int parse_rules_activate(const struct zbx_json_parse *jp, zbx_vector_ptr_t *drules)
{
    struct zbx_json_parse data_jp, obj_j;
    char tstr[MAX_STRING_LEN];
    zbx_uint64_t druleid_value;
    const char *p = NULL;

	if (SUCCEED != zbx_json_brackets_by_name(jp, "params", &data_jp))
	{
		return FAIL;
	}
	while (NULL != (p = zbx_json_next(&data_jp, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
		{
			zbx_user_discover_drule_t *dr = (zbx_user_discover_drule_t *)zbx_malloc(NULL, sizeof(zbx_user_discover_drule_t));
			memset(dr, 0, sizeof(zbx_user_discover_drule_t));
			// 从当前对象中提取druleid的值
			if (SUCCEED == zbx_json_value_by_name(&obj_j, "druleid", tstr, sizeof(tstr), NULL))
			{
				ZBX_STR2UINT64(druleid_value, tstr);  // 将字符串转换为uint64_t
				dr->druleid = druleid_value;
			}

			memset(&tstr, 0, sizeof(tstr));
			// 从当前对象中提取check_type的值
			if (SUCCEED == zbx_json_value_by_name(&obj_j, "checktype", tstr, sizeof(tstr), NULL))
			{
				dr->check_type = zbx_atoi(tstr);
			}

			if(dr->druleid > 0)
				zbx_vector_ptr_append(drules, dr);  // 将druleid添加到向量中
			else
				zbx_free(dr);
		}
	}

    return SUCCEED;
}

void discover_response_replay(int recv_type, const char* response)
{
	if(NULL == response) return;
	
	int result = 0;
	struct json_queue  resp;
	resp.type = recv_type; // 99
	resp.recv_type = recv_type;
	zbx_strscpy(resp.content, response);
	int send_size = sizeof(resp.recv_type) + strlen(resp.content) + 1;
	
	if(-1 == (result = msgsnd(msgid, (void *)&resp, send_size, 0)))
	{
		zabbix_log(LOG_LEVEL_ERR, "#ZOPS#discocerer Failed to send message, response=%s",response);
	}
	// zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#discocerer send message. msgid=%d,result=%d,json=%s",msgid, result, response);
}
/*zhul adds content**end**/
#endif



