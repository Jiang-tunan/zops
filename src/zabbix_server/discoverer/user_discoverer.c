#ifndef ZABBIX_USER_DISCOVERER_C
#define ZABBIX_USER_DISCOVERER_C

#include "user_discoverer.h"
#include "discoverer_single.h"
#include "discoverer_vmware.h"
#include "discoverer_nutanix.h"
#include "zbxmutexs.h"
#include "zbxip.h"
#include "zbxserver.h"

zbx_mutex_t		user_discover_lock = ZBX_MUTEX_NULL;
zbx_user_discover_drules_t	g_user_discover;

extern int g_running_program_type;


void __zbx_user_discover_drule_free(zbx_user_discover_drule_t *ptr)
{
	// 注释这2行session释放代码，是因为session同时存放在old_sessions队列中，由old_sessions队列释放。
	// zbx_vector_ptr_clear_ext(&ptr->sessions, zbx_ptr_free);
	// zbx_vector_ptr_destroy(&ptr->sessions);
	ptr->status = ZBX_USER_DISCOVER_STATUS_FREE;
}
 

void __zbx_user_discover_session_free(zbx_vector_ptr_t *v_session, int index)
{
	if(NULL == v_session)  return;

	int now = time(NULL);
	zbx_user_discover_session_t *session = (zbx_user_discover_session_t *)v_session->values[index];
	zbx_vector_ptr_remove(v_session, index);
	if (now >= session->end_time)
	{
		session->progress = 0;
		zbx_vector_ptr_clear_ext(&session->all_hostids, zbx_ptr_free);
		zbx_vector_ptr_destroy(&session->all_hostids);
		zbx_vector_ptr_destroy(&session->hostids);
		int old_index = zbx_vector_ptr_bsearch(&g_user_discover.old_sessions, session->session, ZBX_DEFAULT_STR_COMPARE_FUNC);
		if(FAIL != old_index){
			zbx_vector_ptr_remove(&g_user_discover.old_sessions, old_index);
		}
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s clear old session, session=%s, old_index=%d", 
				__func__, session->session, old_index);
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s clear session, session=%s, now=%d, end_time=%d", 
				__func__, session->session, now, session->end_time);
}

//只负责按session清理任务  
int __zbx_user_discover_session_timout()
{
	int now = time(NULL);
	zbx_user_discover_session_t *session = NULL;
	for(int i=0; i<g_user_discover.drules.values_num; i++)
	{
		zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[i];
		for(int j = 0; j < drule->sessions.values_num; j ++)
		{
			int timeout = abs(drule->ip_all_num - drule->ip_discovered_num) * USER_DISCOVER_IP_TIME_OUT + USER_DISCOVER_EXTRA_TIME_OUT;
			session = (zbx_user_discover_session_t *)drule->sessions.values[j];
			if (now >= (session->sbegin_time + timeout)){
				zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s ruleid=%d,session=%s, now=%d, sbegin_time=%d,timeout=%d", 
					__func__, drule->druleid, session->session,now, session->sbegin_time,timeout);
				__zbx_user_discover_session_clean_from_drule(i, drule, session->session);
			}
		}
	}

	for(int i=(g_user_discover.old_sessions.values_num-1); i>=0; i--)
	{
		session = (zbx_user_discover_session_t *)g_user_discover.old_sessions.values[i];
		if (now >= session->end_time){
			zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s clear old session, session=%s, now=%d, end_time=%d", 
				__func__, session->session, now, session->end_time);
			zbx_vector_ptr_clear_ext(&session->all_hostids, zbx_ptr_free);
			zbx_vector_ptr_destroy(&session->all_hostids);
			zbx_vector_ptr_destroy(&session->hostids);
			zbx_vector_ptr_remove(&g_user_discover.old_sessions, i);
		}
	}

	return 0;
}



//只负责按session清理任务 返回:是否还有下一个任务
int __zbx_user_discover_session_clean_from_drule(int index, zbx_user_discover_drule_t *drule, const char *session)
{ 
	zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s ruleid=%d,session=%s,session_num=%d", 
		__func__, drule->druleid, session,drule->sessions.values_num);

	int index_session = zbx_vector_ptr_bsearch(&drule->sessions, session, ZBX_DEFAULT_STR_COMPARE_FUNC);
	if(FAIL != index_session){
		__zbx_user_discover_session_free(&drule->sessions,index_session);
	}

	if (drule->sessions.values_num == 0)
	{
		__zbx_user_discover_drule_free(drule);
		zbx_vector_ptr_remove(&g_user_discover.drules, index);
		g_user_discover.need_scan_druleid_num --;
	}
	return SUCCEED;
}

/****
 * 清理所有session相关的扫描任务
 * 返回: SUCCEED:成功  FAIL: 没有此seesion
 */
int __zbx_user_discover_session_clean(const char *session)
{
	int result = FAIL;
	for(int i=0; i<g_user_discover.drules.values_num; i++)
	{
		zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[i];
		
		if(SUCCEED == __zbx_user_discover_session_clean_from_drule(i, drule, session)){
			result = SUCCEED;
		}
	}

	return result;
}


void free_dhosts(zbx_user_discover_drule_t *dr)
{
	if(NULL == dr) return;
	zbx_free(dr->proxy_session.p_hostids);
	zbx_free(dr->proxy_session.p_all_hostids); 
}


//清理全部 用户扫描数据，进程退出时调用
void zbx_user_discover_g_free()
{
	LOCK_USER_DISCOVER;
	zbx_vector_ptr_clear_ext(&g_user_discover.drules, (zbx_mem_free_func_t)__zbx_user_discover_drule_free);
	zbx_vector_ptr_clear(&g_user_discover.drules);
	g_user_discover.druleid = 0;
	g_user_discover.need_scan_druleid_num = 0;
	zbx_vector_ptr_destroy(&g_user_discover.drules);
	UNLOCK_USER_DISCOVER;
}

static int	dc_compare_discover_session(const void *d1, const void *d2)
{
	const zbx_user_discover_session_t	*ptr1 = *((const zbx_user_discover_session_t * const *)d1);
	const char *session = *((const char * const *)d2);
	if(NULL == ptr1->session ||  NULL == session)
		return -1;
	//zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#%s uuid1=%s, uuid2=%s",  __func__, ptr1->session, session);
	return strcmp(ptr1->session, session);
}


//用户扫描任务创建，这里服务端程序和代理程序都会执行
int	user_discover_create(int proxyhostid, const char *session, const struct zbx_json_parse *jp)
{
	char			*sql = NULL;
	size_t			sql_alloc = 0, sql_offset = 0;
	DB_RESULT		result = NULL;
	DB_ROW			row = NULL;
	zbx_db_info_t	db;
	int             ret = DISCOVERY_RESULT_CREATE_FAIL, ipnumber=0, need_scan_druleid_num=0, is_session_create = 0;
	int             try_count=0, max_try_count=1, end_time=0;
	int index_drule, index_session;
	zbx_user_discover_drule_t *old_dr = NULL, *dr = NULL;
	zbx_user_discover_session_t *t_session = NULL;

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s begin proxyhostid=%d",__func__, proxyhostid);
		
	ret = parse_rules_activate(jp, &dr);
	// 提取 druleids
	if (SUCCEED != ret)  goto out;
 
	zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, "select druleid, iprange from drules where druleid='%llu'", dr->druleid);
	
	if(SUCCEED == get_db_select_result(sql, &db)){
		row = db.row;
		result =  db.result;
	}
	
	while (NULL != row)
	{
		zbx_iprange_t iprange;
		if (SUCCEED == zbx_iprange_parse(&iprange, row[1]))
		{
			ipnumber = zbx_iprange_volume(&iprange);
			break;
		}else{
			zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s ruleid:%s: wrong format of IP range:%s",__func__, row[0], row[1]);
		}
		row = zbx_db_fetch(result); 
	}

	if (ipnumber <= 0){
		ret = DISCOVERY_RESULT_CREATE_FAIL;
		goto out; 
	}
	
	LOCK_USER_DISCOVER;
	// 首先检测整个user_discover_g队列 session是否超时；

	__zbx_user_discover_session_timout();
	end_time = time(NULL) + ipnumber * USER_DISCOVER_IP_TIME_OUT + USER_DISCOVER_EXTRA_TIME_OUT + USER_DISCOVER_SESSION_REMOVE_TIME;
 
	if (FAIL != (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &(dr->druleid), ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s druleid:[%d] is in tasks",__func__, dr->druleid);
		old_dr = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
		if (FAIL != (index_session = zbx_vector_ptr_search(&old_dr->sessions, session, dc_compare_discover_session)))
		{
			t_session = (zbx_user_discover_session_t *)old_dr->sessions.values[index_session];
		}
	} 

	is_session_create = 0;
	if(NULL == t_session)
	{
		is_session_create = 1;
		t_session = (zbx_user_discover_session_t *)zbx_malloc(NULL, sizeof(zbx_user_discover_session_t));
		memset(t_session, 0, sizeof(zbx_user_discover_session_t));
		t_session->sbegin_time = time(NULL);
		t_session->end_time = end_time;
		zbx_strscpy(t_session->session,  session);
		zbx_vector_str_create(&t_session->hostids);
		zbx_vector_str_create(&t_session->all_hostids);
		zbx_vector_ptr_append(&g_user_discover.old_sessions, t_session);
	}

	ret = SUCCEED;
	if(NULL != old_dr)
	{
		if(DISCOVERY_RESULT_SUCCESS != old_dr->result || dr->check_type != old_dr->check_type)
		{
			// 旧的dr规则失败的或者check_type不对，则创建新的规则
			__zbx_user_discover_drule_free(old_dr);
			zbx_vector_ptr_remove(&g_user_discover.drules, index_drule);
			g_user_discover.need_scan_druleid_num --;
		}else{ // 用旧的扫描规则
			if(is_session_create)
				zbx_vector_ptr_append(&old_dr->sessions, t_session);
			goto out;
		}
	}
	
	//首次创建任务
	dr->status = ZBX_USER_DISCOVER_STATUS_CREATE;
	dr->result = DISCOVERY_RESULT_SUCCESS;
	
	// VMWare扫描，这个逻辑比较特殊，先把ip地址多少设置为160
	if(SVC_VMWARE  == dr->check_type){
		dr->ip_all_num= 160;  
	}else if(SVC_NUTANIX  == dr->check_type){
		dr->ip_all_num= 161;  
	}else{
		dr->ip_all_num = ipnumber;
	}

	zbx_vector_ptr_create(&dr->sessions);
	zbx_vector_ptr_append(&dr->sessions, t_session);

	zbx_vector_ptr_append(&g_user_discover.drules, dr);
	
	// if(ZBX_PROGRAM_TYPE_PROXY == g_running_program_type){
	// 	dr->proxy_session = t_session;
	// }
	// 需要扫描的规则增加了1个
	g_user_discover.need_scan_druleid_num ++; 

	if(!(proxyhostid > 0 && ZBX_PROGRAM_TYPE_SERVER == g_running_program_type)){
		init_discovery_hosts(1);
	}
	// 通知discover进程立刻处理
	notify_discover_thread();
	
	
out: 
	UNLOCK_USER_DISCOVER;
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s result=%d, type=%d, druleid=%d, ipnumber=%d,need_scan_druleid_num=%d,try_count=%d",
		__func__, ret, dr->check_type, dr->druleid, ipnumber, g_user_discover.need_scan_druleid_num, try_count);
	
	zbx_free(sql);
	zbx_db_free_result(result);
	return ret;
}

//用户扫描任务停止
int	user_discover_stop(const char *session)
{
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s session:[%s]", __func__, session);

	LOCK_USER_DISCOVER;
	
	int result = DISCOVERY_RESULT_SUCCESS;
	//清理该用户的扫描数据
	__zbx_user_discover_session_clean(session);
	UNLOCK_USER_DISCOVER;
	return result;
}

//用户扫描进度
char* user_discover_progress(int from_proxy, const char * session, const struct zbx_json_parse *jp)
{
	return create_progress_json(from_proxy, session, jp);
}
 
//扫描完一个ip 更新数据 ret:是否开始下一个ip段的扫描
int user_discover_next_ip(zbx_uint64_t druleid)
{
	int next_ip = FAIL;  
	
	// zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s druleid=%llu",  __func__, druleid);

	LOCK_USER_DISCOVER;
	
	int index_drule;
	//规则扫描到半被停止了 下一个规则已经在停止的时候确定了
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "%s Can't find ruleid. druleid=%llu", __func__, druleid);
		goto out;
	}

	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
	
	// 代理进程中WMWare,Nutanix等扫描 不能根据ip_discovered_num判断，要根据status判断
	if(ZBX_USER_DISCOVER_STATUS_FINISH == drule->status){
		next_ip = FAIL;
		goto out;
	}

	drule->ip_discovered_num++;
	if(drule->ip_discovered_num >= drule->ip_all_num)
	{
		drule->ip_discovered_num = drule->ip_all_num;
		drule->status = ZBX_USER_DISCOVER_STATUS_FINISH;
	}else{
		next_ip = SUCCEED;
	}

	for(int j = 0; j < drule->sessions.values_num; j ++)
	{
		zbx_user_discover_session_t *session = (zbx_user_discover_session_t *)drule->sessions.values[j];
		session->sbegin_time = time(NULL);
	}
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s druleid:[%llu] status:[%d],discovered_num=%d,all_num=%d,next_ip=%d,check_type=%d", 
		__func__, druleid, drule->status, drule->ip_discovered_num, drule->ip_all_num, next_ip, drule->check_type);

out:
	// 必须在更新sbegin_time后再检测session是否超时；
	__zbx_user_discover_session_timout();
	UNLOCK_USER_DISCOVER;

	return next_ip;
}

//扫描完一个druleid 更新数据 返回下一个需要扫描的druleid
int user_discover_next_druleid(zbx_uint64_t *druleid)
{
	LOCK_USER_DISCOVER;
	int next = FAIL;  //是否有下一条规则是否需要扫描, FAIL:没有，SUCCEED：有
	if (g_user_discover.need_scan_druleid_num > 0  && g_user_discover.drules.values_num)
	{
		for(int i=0; i<g_user_discover.drules.values_num; i++)
		{
			zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[i];
			if(drule->status == ZBX_USER_DISCOVER_STATUS_CREATE)
			{
				drule->status = ZBX_USER_DISCOVER_STATUS_RUN;
				*druleid = drule->druleid;
				g_user_discover.druleid = drule->druleid;
				next = SUCCEED;
				zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s druleid_num:[%d],druleid=%llu,next=%d", __func__, 
					g_user_discover.need_scan_druleid_num, *druleid, next);
				break;
			}
		}
	}

	UNLOCK_USER_DISCOVER;
	return next;
}

// VMWare扫出来的ip数不固定，这增加扫描ip数
int discovery_add_total_ip_num(zbx_uint64_t druleid, int type, int ip_num)
{

	LOCK_USER_DISCOVER;
	int index_drule;
	if ( FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX# %s, search druleid fail. druleid:%d", __func__, druleid);
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}
	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
	switch (type)
	{
	case DEVICE_TYPE_HV:
		drule->hv_num = ip_num;
		break;
	case DEVICE_TYPE_VM:
		drule->vm_num = ip_num;
		break;
	default:
		break;
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, druleid=%d, type=%d, ip_num=%d, hv_num=%d, vm_num=%d", 
		__func__, druleid, type, ip_num, drule->hv_num, drule->vm_num);

	UNLOCK_USER_DISCOVER;
	return SUCCEED;
}

// VMWare、Nutanix扫描的next ip
int discovered_next_ip(zbx_uint64_t druleid, int type, int ip_num)
{	
	LOCK_USER_DISCOVER;
	int index_drule;
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, search druleid fail. druleid:%d", __func__, druleid);
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	int now_count = 0;
	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];

	switch (type)
	{
	case DEVICE_TYPE_HV:
		if(ip_num <= 1 && drule->hv_count < drule->hv_num){
			int last_count = (int)(((float)drule->hv_count/(float)drule->hv_num)*50);
			drule->hv_count += ip_num;
			now_count = (int)(((float)drule->hv_count/(float)drule->hv_num)*50);
			drule->ip_discovered_num += now_count - last_count;
		}
		else if(ip_num >= drule->hv_num){
			now_count = ip_num;
			drule->ip_discovered_num = 60;
		}
		
		break;
	case DEVICE_TYPE_VM:
		if(ip_num <= 1 && drule->vm_count < drule->vm_num){
			int last_count = (int)(((float)drule->vm_count/(float)drule->vm_num)*100);
			drule->vm_count += ip_num;
			now_count = (int)(((float)drule->vm_count/(float)drule->vm_num)*100);
			drule->ip_discovered_num += now_count - last_count;
		}else if(ip_num >= drule->vm_num){
			now_count = ip_num;
			drule->ip_discovered_num = 160;
		}
		break;
	default: 
		now_count = ip_num;
		drule->ip_discovered_num += now_count;
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
	UNLOCK_USER_DISCOVER;

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, druleid=%d, type=%d, ip_num=%d, all_num=%d, discovered_num=%d", 
		__func__, druleid, type, ip_num, drule->ip_all_num, drule->ip_discovered_num);
	
	return SUCCEED;
}


// 添加已经扫描出来的hostid
int user_discover_add_hostid(zbx_uint64_t druleid, zbx_uint64_t hostid)
{
	LOCK_USER_DISCOVER;
	int ret = FAIL;
	int index_drule;
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, search druleid fail. druleid:%ld, hostid:%ld", __func__, druleid, hostid);
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}

	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
	for(int j = 0; j < drule->sessions.values_num; j ++)
	{
		zbx_user_discover_session_t *session = (zbx_user_discover_session_t *)drule->sessions.values[j];
		char *hostid_s = (char *)zbx_malloc(NULL, 22);
		zbx_snprintf(hostid_s, sizeof(hostid_s), ZBX_FS_UI64, hostid);
		zbx_vector_str_append(&session->hostids, hostid_s);
		zbx_vector_str_append(&session->all_hostids, hostid_s);
		ret = SUCCEED;
		//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, success. session:%s, hostid:%d", __func__, session->session, hostid);
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, ret=%d, druleid=%d, hostid:%d", __func__, ret, druleid, hostid);
	UNLOCK_USER_DISCOVER;
	return SUCCEED;
}

// 添加扫描的结果
int user_discover_add_result(zbx_uint64_t druleid, int result)
{
	if (0 == druleid)
		return DISCOVERY_RESULT_FAIL;

	int ret = DISCOVERY_RESULT_FAIL, index_drule, index_session;
	zbx_user_discover_drule_t *drule;
	zbx_user_discover_session_t *dsession;

	LOCK_USER_DISCOVER;
	// 查用户某个druleid进度
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		ret = DISCOVERY_RESULT_NO_DRULEID;
		goto out;
	}
	drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
	drule->result = result;
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, ret=%d, result=%d, druleid=%d, ", __func__, ret, result, druleid);
out:
	UNLOCK_USER_DISCOVER;
	return ret;
}


void update_hostmacro_data(int hostmacroid, int hostid, char *macro, char *value, char *description)
{
	char *value_esc = zbx_get_db_escape_string(value);

	if (hostmacroid <= 0)
	{
		hostmacroid = zbx_db_get_maxid("hostmacro");
		zbx_db_execute("insert into hostmacro (hostmacroid,hostid,macro,value,description,type,automatic)"
				" values (" ZBX_FS_UI64 "," ZBX_FS_UI64 ",'%s','%s','%s', 0, 1)",
				hostmacroid, hostid, macro, value_esc, description);
	}
	else
	{
		zbx_db_execute("update hostmacro set hostid="ZBX_FS_UI64",macro='%s',value='%s',description='%s'"
		" where hostmacroid="ZBX_FS_UI64,
		 hostid, macro, value_esc, description, hostmacroid);
	}
	zbx_free(value_esc);
	
}

void update_hostmacro_int_data(int hostmacroid, int hostid, char *macro, int ivalue, char *description)
{
	char value[128] = {0};
	zbx_snprintf(value,sizeof(value),"%d",ivalue);
	update_hostmacro_data(hostmacroid, hostid, macro, value, description);
}

/*zhul content*/
void discovery_rules_discoverer_thread_init()
{
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s",__func__);
	struct json_queue* thread_arg = (struct json_queue*)zbx_malloc(NULL, sizeof(struct json_queue));
	if (NULL == thread_arg) {
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#Failed to allocate memory for thread_arg");
	}

	if(-1 == (msgid = msgget(MSG_KEY, 0666 | IPC_CREAT)))
	{
		zabbix_log(LOG_LEVEL_WARNING, 
			"#TOGNIX#%s, msgqueue creat fail! msgid=%d, errmsg=%s", 
			__func__, msgid, strerror(errno));
	}


	thread_arg->type = DCR_MSG_TYPE;
	pthread_t drd_thread; // 接收线程
	if (0 != pthread_create(&drd_thread, NULL, discovery_rules_discoverer_thread_function, thread_arg)) 
	{
		// # 未定义错误信息
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#thread_init#Failed to create msg_queue_thread !!!");
	}
}


void* discovery_rules_discoverer_thread_function(void* arg) 
{
	if (NULL == arg) 
	{
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#Thread argument is NULL");
		pthread_exit(NULL);
	}
	int count = 1;
	struct json_queue* recv_msg = (struct json_queue*)arg;
	struct zbx_json_parse	jp;
	char cmd[BUFSIZ] = "";
	while (ZBX_IS_RUNNING() && count <= 5)
	{
		// 读取消息
		if (-1 == msgrcv(msgid, (void *)recv_msg, QUEUE_STR_LEN, DCR_MSG_TYPE, 0))
		{
			int old_msgid = msgid;
            zbx_sleep(count * 5);
			// 碰到过消息队列失败情况,这里增加重试机制。如果重试3次都没有创建队列，则退出线程。
			if(-1 == (msgid = msgget(MSG_KEY, 0666 | IPC_CREAT))){
				count ++;
			}else{
				count = 0;
			}
			zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#discovery_rules. Failed to receive message from queue,o_msgid=%d,msgid=%d",
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
			else if (SUCCEED == zbx_json_value_by_name(&jp, ZBX_PROTO_TAG_REQUEST, cmd, sizeof(cmd), NULL))
			{
				discovery_rules_select(cmd, recv_msg->recv_type, &jp, recv_msg->content);
			}
		}

	}
	free(arg);
    pthread_exit(NULL);
} 
 

/*********************************************
 * Function_Name:discovery_rules_select
 *
 * Decscription: 根据 request 进行对应操作
 *
 * Parameter :
 * 	@ cmd			请求值
 *  @ jp					请求报文指针

 *
 * Return : 
 * 
************************************************/
void discovery_rules_select(const char* cmd,int recv_type, const struct zbx_json_parse *jp, char *request)
{
	int ret, proxy_hostid = 0;
	char *response = NULL;
	char session_value[256], tstr[256]={0};

		
	// 提取 session
	if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), NULL))
	{
		response = create_fail_json(cmd, "", DISCOVERY_RESULT_NO_SESSION, "NO session");
	}

	// 提取 proxyhostid
	if (SUCCEED == zbx_json_value_by_name(jp, "proxyhostid", tstr, sizeof(tstr), NULL))
	{
		proxy_hostid = zbx_atoi(tstr);
	}

	// 比较 request 值 进行对应操作
	if (SUCCEED == zbx_strcmp_null(cmd, DISCOVERY_CMD_ACTIVITE)) 
	{
		ret = user_discover_create(proxy_hostid, session_value, jp);
		response = create_activate_or_stop_json(ret, DISCOVERY_CMD_ACTIVITE, session_value, jp);
	} 
	else if (SUCCEED == zbx_strcmp_null(cmd, DISCOVERY_CMD_PROGRESS))
	{
		// 调用扫描进度查询
		response = user_discover_progress(0, session_value, jp);
	} 
	else if (SUCCEED == zbx_strcmp_null(cmd, DISCOVERY_CMD_STOP))
	{
		// 停止user_discover_stop()
		ret = user_discover_stop(session_value);
		response = create_activate_or_stop_json(ret, DISCOVERY_CMD_STOP, session_value, jp);
	} 
	else if (SUCCEED == zbx_strcmp_null(cmd, DISCOVERY_CMD_SINGLE_SCAN))
	{
		if(DISCOVERY_RESULT_SUCCESS == discover_single_scan(recv_type, session_value, jp, request, &response))
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

int query_druleid_progress(const char * session, zbx_uint64_t druleid, int fullsync, 
	int *out_progress, int *out_remain_time, char **out_hostids, int *proxy_discover_finish)
{
	// 计算进度
	int progress = 0, remain_time, ret = DISCOVERY_RESULT_SUCCESS;
	int need_remove_druleid = 0;
	int index_drule = FAIL,index_session = FAIL;
	zbx_user_discover_drule_t *drule = NULL;
	zbx_user_discover_session_t *dsession = NULL;

	if (druleid == 0)
		return DISCOVERY_RESULT_QUERY_FAIL;
	
	LOCK_USER_DISCOVER;
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ruleid=%d,fullsync=%d,session=%s",
			__func__, druleid, fullsync, session);


	// 查用户某个druleid进度
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		// 代理程序因为无法控制查询顺序，所以即使查询不到也返回成功
		if(ZBX_PROGRAM_TYPE_PROXY == g_running_program_type)
			ret = DISCOVERY_RESULT_SUCCESS;
		else
			ret = DISCOVERY_RESULT_NO_DRULEID;
		goto out;
	}
	drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
	
	if (FAIL == (index_session = zbx_vector_ptr_bsearch(&drule->sessions, session, ZBX_DEFAULT_STR_COMPARE_FUNC)))
	{
		if(ZBX_PROGRAM_TYPE_PROXY == g_running_program_type)
			ret = DISCOVERY_RESULT_SUCCESS;
		else
			ret = DISCOVERY_RESULT_NO_SESSION;
		goto out;
	}
	dsession = (zbx_user_discover_session_t *)drule->sessions.values[index_session];
	
	int remaining_ips = drule->ip_all_num - drule->ip_discovered_num; // 计算剩余的IP数量
	remain_time = remaining_ips * USER_DISCOVER_IP_INTERVAL_TIME;	 // 剩余时间 = 剩余IP数量 * 3秒
	progress = (double)(drule->ip_discovered_num / (double)drule->ip_all_num) * 100;

	time_t now = time(NULL);
	int alltime = drule->ip_all_num * USER_DISCOVER_IP_INTERVAL_TIME;
	int timeout = remaining_ips * USER_DISCOVER_IP_TIME_OUT + USER_DISCOVER_EXTRA_TIME_OUT;
	
	dsession->query_number ++;

	if(DISCOVERY_RESULT_SUCCESS !=  drule->result){
		ret = drule->result;
		progress = 100;
		remain_time = 0;
		need_remove_druleid = 1;
	}
	else if (drule->ip_discovered_num >= drule->ip_all_num)
	{
		progress = 100;
		remain_time = 0;
		need_remove_druleid = 1;
	}
	else if (now >= dsession->sbegin_time + timeout)  //session超时，则移除session
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
	else if(ZBX_PROGRAM_TYPE_PROXY == g_running_program_type && drule->proxy_discover_finish) 
	{
		// do nothing
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

	if(fullsync){
		vector_to_str(&dsession->all_hostids, out_hostids, ",");
	}else{
		vector_to_str(&dsession->hostids, out_hostids, ",");
	}
	
	for(int k = dsession->hostids.values_num - 1; k >= 0; k --)
	{
		zbx_vector_ptr_remove(&dsession->hostids, k);
	}

	if(ZBX_PROGRAM_TYPE_PROXY == g_running_program_type && drule->proxy_discover_finish) {
		// 代理程序只是处理部分数据，代理到这里就结束了，后续由服务端处理剩余进度
		*proxy_discover_finish = drule->proxy_discover_finish;
		__zbx_user_discover_session_free(&drule->sessions, index_session);
		// 该ruldid下没有任何任务，就从队列中移除ruldid
		if(drule->sessions.values_num == 0)
		{
			need_remove_druleid = 1;
		}
	}
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ruleid=%d,status=%d,fullsync=%d,all_num=%d,discovered_num=%d,progress=%d,remain_time=%d,need_remove=%d, proxy_discover_finish=%d, hostids=%s",
			__func__, drule->druleid, drule->status, fullsync, drule->ip_all_num, drule->ip_discovered_num, progress,remain_time,need_remove_druleid, *proxy_discover_finish, *out_hostids);

	// 如果100%了或者超时 就移除该ruleid的任务 如果没有下一个任务了就清理所有任务
	if (drule->ip_discovered_num >= drule->ip_all_num || need_remove_druleid)
	{
		__zbx_user_discover_session_clean_from_drule(index_drule, drule, session);
	}

out:
	// 没有拿到session进度，可能已经超时过期了，如果是fullsync，则从old_sessions拿
	if(fullsync && DISCOVERY_RESULT_SUCCESS != ret)
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s find from old_sessions. session=%s, old_session_num=%d",
					__func__,  session,  g_user_discover.old_sessions.values_num);
		if (FAIL != (index_session = zbx_vector_ptr_search(&g_user_discover.old_sessions, session, dc_compare_discover_session)))
		{
			dsession = (zbx_user_discover_session_t *)g_user_discover.old_sessions.values[index_session];
			progress = 100;
			remain_time = 0;
			vector_to_str(&dsession->all_hostids, out_hostids, ",");
			ret = DISCOVERY_RESULT_SUCCESS;
			zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s find old_sessions success. session=%s, all_hostid_num=%d",
					__func__,  dsession->session,  dsession->all_hostids.values_num);
		}
		else{
			ret = DISCOVERY_RESULT_NO_SESSION;
		}
	} 

	*out_progress = progress;
	*out_remain_time = remain_time;
	UNLOCK_USER_DISCOVER;
	return ret;
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
char* create_progress_json(int from_proxy, const char* session_value, const struct zbx_json_parse *jp) 
{
    struct zbx_json j;
    struct zbx_json_parse data_jp;
    char druleid_str[128], fullsync_str[128];
	const char *p = NULL;
	int fullsync = 0;

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN*2);
	// 添加response键值
	zbx_json_addstring(&j, "response", DISCOVERY_CMD_PROGRESS, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&j, "session", session_value, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&j, "result", DISCOVERY_RESULT_SUCCESS);

	// 开始"data"数组
	zbx_json_addarray(&j, "data");
	if (SUCCEED == zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &data_jp))
	{
		while (NULL != (p = zbx_json_next(&data_jp, p)))
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				fullsync = 0;
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "fullsync", fullsync_str, sizeof(fullsync_str), NULL))
				{
					fullsync = zbx_atoi(fullsync_str);
				}
				// 从当前对象中提取druleid的值
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "druleid", druleid_str, sizeof(druleid_str), NULL))
				{
					int ret = 0, progress = 0,remain_time = 0, proxy_discover_finish = 0;
					char *hostids = NULL;

					zbx_uint64_t druleid = 0;
					zbx_lrtrim(druleid_str, ZBX_WHITESPACE);
					zbx_is_uint64(druleid_str, &druleid);
					 
					zbx_json_addobject(&j, NULL);
					zbx_json_addint64(&j, "druleid", druleid);// 是否选择使用 user_discover中的值?
					
					if(from_proxy){
						ret = server_query_proxy_druleid_progress(session_value, druleid, fullsync, &progress, &remain_time, &hostids);
					}else{
						ret = query_druleid_progress(session_value, druleid, fullsync, &progress, &remain_time, &hostids, &proxy_discover_finish);
					}
					zbx_json_addint64(&j, "result", ret);  
					zbx_json_addint64(&j, "progress", progress);
					zbx_json_addint64(&j, "remain_time", remain_time);
					if(proxy_discover_finish > 0){
						zbx_json_addint64(&j, "proxy_discover_finish", proxy_discover_finish);
					}
					zbx_json_addstring(&j, "hostids", hostids, ZBX_JSON_TYPE_STRING);
					zbx_json_close(&j);
					zbx_free(hostids);
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
char* create_activate_or_stop_json(int result, const char *cmd, const char *session_value, const struct zbx_json_parse *jp)
{
    struct zbx_json j;
    struct zbx_json_parse data_jp;
    char druleid_str[MAX_STRING_LEN];
	const char *p = NULL;

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	zbx_json_addstring(&j, "response", cmd, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&j, "session", session_value, ZBX_JSON_TYPE_STRING);
	
	zbx_json_addint64(&j, "result", result);
	// 开始"data"数组
	zbx_json_addarray(&j, "data");
	if (SUCCEED == zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &data_jp))
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
					zbx_json_addint64(&j, "result", result);
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
int parse_rules_activate(const struct zbx_json_parse *jp, zbx_user_discover_drule_t **out_dr)
{
    struct zbx_json_parse data_jp, obj_j;
    char tstr[128];
    zbx_uint64_t druleid_value;
    const char *p = NULL;
	int ret = DISCOVERY_RESULT_CREATE_FAIL;
	zbx_user_discover_drule_t *dr = NULL;
	
	if (SUCCEED != zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &data_jp))
	{
		return DISCOVERY_RESULT_JSON_PARSE_FAIL;
	}

	while (NULL != (p = zbx_json_next(&data_jp, p)))
	{
		if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
		{
			dr = (zbx_user_discover_drule_t *)zbx_malloc(NULL, sizeof(zbx_user_discover_drule_t));
			memset(dr, 0, sizeof(zbx_user_discover_drule_t));

			memset(&tstr, 0, sizeof(tstr));
			// 从当前对象中提取druleid的值
			if (SUCCEED == zbx_json_value_by_name(&obj_j, "druleid", tstr, sizeof(tstr), NULL))
			{
				ZBX_STR2UINT64(druleid_value, tstr);  // 将字符串转换为uint64_t
				dr->druleid = druleid_value;
			}

			dr->check_type = -1;
			memset(&tstr, 0, sizeof(tstr));
			// 从当前对象中提取check_type的值
			if (SUCCEED == zbx_json_value_by_name(&obj_j, "checktype", tstr, sizeof(tstr), NULL))
			{
				dr->check_type = zbx_atoi(tstr);
			}

			if(dr->druleid > 0 && dr->check_type >= 0){
				*out_dr = dr;
				ret = SUCCEED;
			}else{
				if(dr->druleid == 0)  ret = DISCOVERY_RESULT_NO_DRULEID;
				else  ret = DISCOVERY_RESULT_CREATE_FAIL;
				zbx_free(dr);
			}
			break;
		}
	}
    return ret;
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
		zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s send message fail, msgid=%d, recv_type=%d, send_size=%d, response=%s",
			__func__, msgid, recv_type, send_size, response);
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s result=%d,msgid=%d,recv_type=%d,send_size=%d,resp=%s",
		__func__, result, msgid, recv_type, send_size, print_content(response));
}
/*zhul adds content**end**/




int get_proxy_dhosts(zbx_uint64_t druleid,char *session, zbx_user_discover_drule_t *dr)
{
	DB_RESULT		result;
	DB_ROW			row;
	int ret = DISCOVERY_RESULT_FAIL, k = 0;

	if(NULL == dr || 0 == druleid) return DISCOVERY_RESULT_NO_DRULEID;

	memset(dr, 0, sizeof(zbx_user_discover_drule_t));
	dr->druleid = druleid;
	if(NULL != session){
		result = zbx_db_select("select ip_all_num, ip_discovered_num, proxy_discover_finish, check_type,vm_count, hv_count, " \
				" vm_num, hv_num, status, query_number, progress, begintime, hostids, all_hostids " \ 
				" from proxy_dhosts where druleid=%llu and session='%s'", druleid, session);
	}else{
		result = zbx_db_select("select ip_all_num, ip_discovered_num, proxy_discover_finish, check_type,vm_count, hv_count, " \
				" vm_num, hv_num, status, query_number, progress, begintime, hostids, all_hostids " \ 
				" from proxy_dhosts where druleid=%llu order by id desc", druleid);
	}

	while (NULL != (row = zbx_db_fetch(result)))
	{
		k = 0;
		dr->ip_all_num = zbx_atoi(row[k++]);
		dr->ip_discovered_num = zbx_atoi(row[k++]);
		dr->proxy_discover_finish = zbx_atoi(row[k++]);
		dr->check_type = zbx_atoi(row[k++]);
		dr->vm_count = zbx_atoi(row[k++]);
		dr->hv_count = zbx_atoi(row[k++]);
		dr->vm_num = zbx_atoi(row[k++]);
		dr->hv_num = zbx_atoi(row[k++]);
		dr->status = zbx_atoi(row[k++]);
		dr->proxy_session.query_number = zbx_atoi(row[k++]);
		dr->proxy_session.progress = zbx_atoi(row[k++]);
		dr->proxy_session.sbegin_time = zbx_atoi(row[k++]);
		dr->proxy_session.p_hostids = zbx_strdup(NULL, row[k++]);
		dr->proxy_session.p_all_hostids = zbx_strdup(NULL, row[k++]);
		ret = SUCCEED;
        break;
	}
	zbx_db_free_result(result);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ruleid=%llu,ip_all_num=%d,ip_discovered_num=%d,proxy_discover_finish=%d,vm_count=%d,hv_count=%d," \
				"vm_num=%d,hv_num=%d,status=%d,query_number=%d, progress=%d,hostids=%s,all_hostsid=%s",
				__func__, dr->druleid, dr->ip_all_num,dr->ip_discovered_num,dr->proxy_discover_finish,dr->vm_count,dr->hv_count,
				dr->vm_num,dr->hv_num,dr->status,dr->proxy_session.query_number,dr->proxy_session.progress,dr->proxy_session.p_hostids,dr->proxy_session.p_all_hostids);

	return ret;
}

// 服务端创建代理的扫描任务
int	server_user_discover_create_proxy(int proxyhostid, const char *session, const struct zbx_json_parse *jp)
{
    char			*sql = NULL;
	size_t			sql_alloc = 0, sql_offset = 0;
	DB_RESULT		result;
	DB_ROW			row;
	int             ret = DISCOVERY_RESULT_SUCCESS, dbret = -1, ip_all_num=0, druleid = 0;
	
	zbx_user_discover_drule_t *dr = NULL;
	
	// 获得drule
	ret = parse_rules_activate(jp, &dr);
	
	if (SUCCEED != ret)  goto out;
    
    // 删除超时的扫描
    zbx_db_execute("delete from proxy_dhosts where endtime<%d", time(NULL));

	zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, "select id,druleid,session,hostids,begintime" \ 
        " from proxy_dhosts where druleid=%llu and session='%s' ", \
         dr->druleid, session);
	result = zbx_db_select(sql);
	while (NULL != (row = zbx_db_fetch(result)))
	{
		// 已经创建，就不要创建了，直接跳出
		zbx_db_free_result(result);
        goto out;
	}
	zbx_db_free_result(result);
 
	result = zbx_db_select("select druleid, iprange from drules where druleid=%llu", dr->druleid);
	while (NULL != (row = zbx_db_fetch(result)))
	{
		zbx_iprange_t iprange;
		if (SUCCEED != zbx_iprange_parse(&iprange, row[1]))
		{
			zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#%s ruleid:%s: wrong format of IP range:%s",__func__, row[0], row[1]);
			continue;
		}
		ip_all_num = zbx_iprange_volume(&iprange);
	}
	zbx_db_free_result(result);
	dr->ip_all_num = ip_all_num;
	// VMWare扫描，这个逻辑比较特殊，先把ip地址多少设置为160
	if(SVC_VMWARE  == dr->check_type){
		dr->ip_all_num= 160;  
	}else if(SVC_NUTANIX  == dr->check_type){
		dr->ip_all_num= 161;  
	}
	dr->status = ZBX_USER_DISCOVER_STATUS_CREATE;
    int begintime = time(NULL);
    int endtime =  begintime + ip_all_num*USER_DISCOVER_IP_TIME_OUT + USER_DISCOVER_EXTRA_TIME_OUT + USER_DISCOVER_SESSION_REMOVE_TIME;
    druleid = dr->druleid;
	dbret = zbx_db_execute("INSERT INTO proxy_dhosts (druleid, session, ip_all_num, ip_discovered_num, proxy_discover_finish, check_type," \
				" vm_count, hv_count, vm_num, hv_num, hostids, all_hostids, status, begintime, endtime) " \
                  " VALUES (%llu, '%s', %d,  %d, %d, %d, " \
				  " %d, %d, %d, %d, '%s', '%s', %d, %d, %d) ",
        		dr->druleid, session, dr->ip_all_num, dr->ip_discovered_num, dr->proxy_discover_finish, dr->check_type,
				dr->vm_count,dr->hv_count,dr->vm_num,dr->hv_num,"","",dr->status, begintime, endtime);
	if(dbret > 0 ) ret = DISCOVERY_RESULT_SUCCESS;
	else ret = DISCOVERY_RESULT_CREATE_FAIL;
	
out:
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, ret=%d, dbret=%d, proxyhostid=%d, session=%s, druleid=%d", 
		__func__, ret, dbret, proxyhostid, session, druleid);
	
	return ret;
}

int server_user_discover_add_proxy_hostid(zbx_uint64_t druleid, zbx_uint64_t hostid)
{
	int ret;
	char hostid_s[32] = {""};
	zbx_snprintf(hostid_s, sizeof(hostid_s), "%llu,", hostid);
	ret = zbx_db_execute("update proxy_dhosts set all_hostids=concat(all_hostids,'%s'),hostids=concat(hostids,'%s') WHERE druleid=%llu", \
                    hostid_s,hostid_s, druleid);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, ret=%d, druleid=%d, hostid:%d", __func__, ret, druleid, hostid);
	return SUCCEED;
}


// 服务端处理代理 VMWare扫出来的ip数不固定，这增加扫描ip数
int server_discovery_proxy_add_total_ip_num(zbx_uint64_t druleid, int type, int ip_num)
{ 
	int ret = FAIL;
	switch (type)
	{
	case DEVICE_TYPE_HV:
		ret = zbx_db_execute("update proxy_dhosts set hv_num=%d WHERE druleid=%llu", \
                    ip_num, druleid);
		break;
	case DEVICE_TYPE_VM:
		ret = zbx_db_execute("update proxy_dhosts set vm_num=%d WHERE druleid=%llu", \
                    ip_num, druleid);
		break;
	default:
		break;
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, ret=%d,druleid=%d, type=%d, ip_num=%d", 
		__func__, ret,druleid, type, ip_num);
 
	return ret;
}

// 服务端处理代理 VMWare、Nutanix扫描的next ip
int server_discovered_proxy_next_ip(zbx_uint64_t druleid, int type, int ip_num)
{
	int ret=FAIL, k = 0, now_count = 0;
	zbx_user_discover_drule_t dr;

	if(SUCCEED != (ret = get_proxy_dhosts(druleid,NULL, &dr)))
		return FAIL;

	switch (type)
	{
	case DEVICE_TYPE_HV:
		if(ip_num <= 1 && dr.hv_count < dr.hv_num){
			int last_count = (int)(((float)dr.hv_count/(float)dr.hv_num)*50);
			dr.hv_count += ip_num;
			now_count = (int)(((float)dr.hv_count/(float)dr.hv_num)*50);
			dr.ip_discovered_num += now_count - last_count;
		}
		else if(ip_num >= dr.hv_num){
			now_count = ip_num;
			dr.ip_discovered_num = 60;
		}
		break;
	case DEVICE_TYPE_VM:
		if(ip_num <= 1 && dr.vm_count < dr.vm_num){
			int last_count = (int)(((float)dr.vm_count/(float)dr.vm_num)*100);
			dr.vm_count += ip_num;
			now_count = (int)(((float)dr.vm_count/(float)dr.vm_num)*100);
			dr.ip_discovered_num += now_count - last_count;
		}else if(ip_num >= dr.vm_num){
			now_count = ip_num;
			dr.ip_discovered_num = 160;
		}
		break;
	default: 
		now_count = ip_num;
		dr.ip_discovered_num += now_count;

		// if(161 == dr.ip_all_num && 161 <= dr.ip_discovered_num){
		// 	dr.status = ZBX_USER_DISCOVER_STATUS_FINISH;
		// }
		break;
	} 
	dr.status = ZBX_USER_DISCOVER_STATUS_RUN;
	// if(dr.ip_discovered_num >= dr.ip_all_num)
	// {
	// 	dr.status = ZBX_USER_DISCOVER_STATUS_FINISH;
	// }

	int begintime = time(NULL);

	ret = zbx_db_execute("update proxy_dhosts set ip_discovered_num=%d,hv_count=%d,vm_count=%d,status=%d,begintime=%d WHERE druleid=%llu", \
                    dr.ip_discovered_num,dr.hv_count,dr.vm_count,dr.status, begintime, druleid);
	
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, ret=%d, druleid=%d, type=%d, ip_num=%d, all_num=%d, discovered_num=%d", 
		__func__, ret, druleid, type, ip_num, dr.ip_all_num, dr.ip_discovered_num);
	free_dhosts(&dr);
	return ret;
}

// 服务端处理代理服务器返回的已经完成的进度数据
int server_discovery_proxy_progress_finish(char *proxy_resp, char **session)
{
	struct zbx_json_parse jp, data_jp, obj_j;
    char tstr[128];
	const char *p = NULL;
	size_t session_alloc=0;
	int ret = FAIL, proxy_discover_finish = 0, progress = 0, druleid = 0, ip_discovered_num = 0;
	if (SUCCEED != zbx_json_open(proxy_resp, &jp)){
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, json open fail, proxy_resp=%s",  __func__, proxy_resp);
		return ret;
	}

	zbx_json_value_by_name_dyn(&jp, ZBX_PROTO_TAG_SESSION, session, &session_alloc, NULL);

	if (SUCCEED == zbx_json_brackets_by_name(&jp, ZBX_PROTO_TAG_DATA, &data_jp))
	{
		while (NULL != (p = zbx_json_next(&data_jp, p)))
		{
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "druleid", tstr, sizeof(tstr), NULL))
				{
					druleid = zbx_atoi(tstr);
				}

				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "proxy_discover_finish", tstr, sizeof(tstr), NULL))
				{
					proxy_discover_finish = zbx_atoi(tstr);
				}

				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "progress", tstr, sizeof(tstr), NULL))
				{
					progress = zbx_atoi(tstr);
				}
			}
		}
	}

	if(0 < proxy_discover_finish && 0 < druleid && NULL != *session){
		
		// 只有在代理扫描完成后，才更新数据库
		ret = zbx_db_execute("update proxy_dhosts set ip_discovered_num=10,proxy_discover_finish=%d,progress=%d " \
				" WHERE druleid=%llu and session='%s' and ip_discovered_num < 10",  
				proxy_discover_finish, progress, druleid, *session);
		if(ret <= 0){
			ret = zbx_db_execute("update proxy_dhosts set proxy_discover_finish=%d,progress=%d " \
				" WHERE druleid=%llu and session='%s'",  
				proxy_discover_finish, progress, druleid, *session);
		}
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, ret=%d,druleid=%d, ip_discovered_num=%d, proxy_discover_finish=%d, progress=%d", 
		__func__, ret,druleid, ip_discovered_num, proxy_discover_finish, progress);
		
	}else{
		ret = SUCCEED;
	}
	
	return ret;
}

int is_proxy_discover_finish(char *session, struct zbx_json_parse *jp, zbx_uint64_t *druleid,  int *fullsync)
{	
	DB_RESULT		result;
	DB_ROW			row;
	int proxy_discover_finish = 0;

	struct zbx_json_parse data_jp, obj_j;
    char tstr[128];
	const char *p = NULL;

	if (SUCCEED == zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &data_jp))
	{
		while (NULL != (p = zbx_json_next(&data_jp, p)))
		{
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				*fullsync = 0;
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "fullsync", tstr, sizeof(tstr), NULL))
				{
					*fullsync = zbx_atoi(tstr);
				}
				
				memset(tstr, 0, sizeof(tstr));
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "druleid", tstr, sizeof(tstr), NULL))
				{
					*druleid = zbx_atoi(tstr);
					break;
				}
			}
		}
	}

	if(0 == *druleid) return 0;

	result = zbx_db_select("select proxy_discover_finish from proxy_dhosts where druleid=%llu and session='%s'", 
		*druleid, session);
	while (NULL != (row = zbx_db_fetch(result)))
	{
		proxy_discover_finish = zbx_atoi(row[0]);
        break;
	}
	zbx_db_free_result(result);
	return proxy_discover_finish;
}

// 服务端查询代理扫描进度，在代理端已经获取到对应数据，然后服务端处理数据
int server_query_proxy_druleid_progress(const char * session, zbx_uint64_t druleid, int fullsync, 
	int *out_progress, int *out_remain_time, char **out_hostids)
{
	// 计算进度
	int progress = 0, remain_time, ret = DISCOVERY_RESULT_SUCCESS, dbret;
	int need_remove_druleid = 0;
	int index_drule = FAIL,index_session = FAIL;
	zbx_user_discover_drule_t dr; 
	 
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ruleid=%d,fullsync=%d,session=%s",
			__func__, druleid, fullsync, session);
	
	if(SUCCEED != (ret = get_proxy_dhosts(druleid, session, &dr)))
		return ret;
	
	int remaining_ips = dr.ip_all_num - dr.ip_discovered_num; // 计算剩余的IP数量
	remain_time = remaining_ips * USER_DISCOVER_IP_INTERVAL_TIME;	 // 剩余时间 = 剩余IP数量 * 3秒
	progress = (double)(dr.ip_discovered_num / (double)dr.ip_all_num) * 100;

	time_t now = time(NULL);
	int alltime = dr.ip_all_num * USER_DISCOVER_IP_INTERVAL_TIME;
	int timeout = remaining_ips * USER_DISCOVER_IP_TIME_OUT + USER_DISCOVER_EXTRA_TIME_OUT;
	 
	int query_number = ++dr.proxy_session.query_number;

	if (dr.ip_discovered_num >= dr.ip_all_num)
	{
		progress = 100;
		remain_time = 0;
		need_remove_druleid = 1;
	}
	else if (now >= dr.proxy_session.sbegin_time + timeout)  //session超时，则移除session
	{ 
		progress = 100;
		remain_time = 0;
	}
	else if (progress > dr.proxy_session.progress) // 当前进度比缓存的进度更多，用新的进度
	{
		dr.proxy_session.progress = progress;
	}
	else if (progress <= dr.proxy_session.progress && dr.proxy_session.progress < 99) // 当前进度没有任何进展，则每次查询时候，把进度加1
	{
		//前端每2秒查询一次，每次过去时间为2秒，每次查询进度为 消耗时间除以总时间。
		int t_progress = ((double)(query_number * USER_DISCOVER_QUERY_INTERVAL_TIME) / (double)alltime) * 100;
		if(t_progress > progress && t_progress < 99)
			dr.proxy_session.progress = t_progress;
		else
			dr.proxy_session.progress ++;

		progress = dr.proxy_session.progress;
		remain_time = ((double)(100-progress)/(double)100) * alltime;
	}
	else // 上次进度为99情况下，但是实际扫描进度没有那么多情况下，继续用99进度 
	{ 
		progress = dr.proxy_session.progress;
	}

	if(fullsync){
		*out_hostids = zbx_strdup(NULL, dr.proxy_session.p_all_hostids);
	}else{
		*out_hostids = zbx_strdup(NULL, dr.proxy_session.p_hostids);
	}
	
	dbret = zbx_db_execute("update proxy_dhosts set progress=%d,query_number=%d,hostids='' " \
					" WHERE druleid=%llu and session='%s' and hostids='%s'", \
                     progress, query_number, druleid, session, *out_hostids);
	if(dbret <= 0) {
		dbret = zbx_db_execute("update proxy_dhosts set progress=%d,query_number=%d " \
					" WHERE druleid=%llu and session='%s'", \
                     progress, query_number, druleid, session);
	}
	
	// status没有在ZBX_USER_DISCOVER_STATUS_FINISH说明还没有真正入库绑定模板，这个时候，先把进度调为99，让前端继续调用
	if(ZBX_USER_DISCOVER_STATUS_FINISH != dr.status && progress == 100){
		progress = 99;
	}
	if(dbret > 0) ret = DISCOVERY_RESULT_SUCCESS;
	else ret = DISCOVERY_RESULT_NO_SESSION;

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ret=%d,dbret=%d,ruleid=%d,status=%d,fullsync=%d,all_num=%d,discovered_num=%d,query_number=%d,progress=%d,remain_time=%d,need_remove=%d, hostids=%s",
			__func__, ret,dbret,dr.druleid, dr.status, fullsync, dr.ip_all_num, dr.ip_discovered_num,query_number, progress,remain_time,need_remove_druleid, *out_hostids);
    
	// // 如果100%了或者超时 就移除该ruleid的任务 如果没有下一个任务了就清理所有任务
	// if (dr.ip_discovered_num >= dr.ip_all_num || need_remove_druleid)
	// {
	// 	__zbx_user_discover_session_clean_from_drule(index_drule, drule, session);
	// }

out:
	*out_progress = progress;
	*out_remain_time = remain_time;
	free_dhosts(&dr);
	UNLOCK_USER_DISCOVER;
	return ret;
}

// 服务端处理代理程序真正结束（所有的host已经绑定了模板）
int server_discover_proxy_finished(zbx_uint64_t druleid, char *session)
{
	int ret = FAIL,dbret = -1;
	char		*sql = NULL;
	size_t		sql_alloc = 0, sql_offset = 0;	

	if(0 == druleid) return ret;

	zbx_vector_str_t	v_sessions; 
	zbx_vector_str_create(&v_sessions); 

	zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset,
				"update proxy_dhosts set status=%d WHERE druleid=%llu and ip_all_num <= ip_discovered_num  ",
				ZBX_USER_DISCOVER_STATUS_FINISH, druleid);
	if(NULL != session && strlen(session) > 0){
		zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset," and ");
		
		str_to_vector(&v_sessions,session, ",");
		zbx_db_add_str_condition_alloc(&sql, &sql_alloc, &sql_offset, "session",
					(const char **)v_sessions.values, v_sessions.values_num); 
	}
	
	if(0 < druleid){
		dbret = zbx_db_execute(sql);
		if(dbret > 0) ret = SUCCEED;
	}

	zbx_free(sql);
	zbx_vector_str_clear(&v_sessions);
	zbx_vector_str_destroy(&v_sessions);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s  dbret=%d, druleid=%d, sesions=%s", 
		__func__, dbret, druleid, session);
		
	return ret;
}

// 代理端处理代码，在代理端扫描结束后，设置标识
int proxy_discover_finished(zbx_uint64_t druleid)
{	
	LOCK_USER_DISCOVER;
	int index_drule;
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, search druleid fail. druleid:%d", __func__, druleid);
		UNLOCK_USER_DISCOVER;
		return FAIL;
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, success. druleid=%d", __func__, druleid);
	zbx_user_discover_drule_t *drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
	drule->proxy_discover_finish = 1;
	drule->status = ZBX_USER_DISCOVER_STATUS_FINISH;
	UNLOCK_USER_DISCOVER;
	
	return SUCCEED;
}

int proxy_get_sessions(zbx_uint64_t druleid, char **sessions)
{
	int ret = FAIL;
	size_t sessions_alloc = 0, sessions_offset = 0;
	zbx_user_discover_drule_t *drule = NULL;
	zbx_user_discover_session_t *session = NULL;

	LOCK_USER_DISCOVER;
	
	int index_drule;
	//规则扫描到半被停止了 下一个规则已经在停止的时候确定了
	if (FAIL == (index_drule = zbx_vector_ptr_bsearch(&g_user_discover.drules, &druleid, ZBX_DEFAULT_UINT64_PTR_COMPARE_FUNC)))
	{
		zabbix_log(LOG_LEVEL_DEBUG, "%s Can't find ruleid. druleid=%llu", __func__, druleid);
		goto out;
	}

	drule = (zbx_user_discover_drule_t *)g_user_discover.drules.values[index_drule];
	for(int j = 0; j < drule->sessions.values_num; j ++)
	{
		session = (zbx_user_discover_session_t *)drule->sessions.values[j];
		zbx_snprintf_alloc(sessions, &sessions_alloc, &sessions_offset, "%s,",
					session->session);
		ret = SUCCEED;
	}
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s druleid=%llu,sessions=%s", __func__, druleid, *sessions);
		
	 
out: 
	UNLOCK_USER_DISCOVER;
	return ret;
}

#endif



