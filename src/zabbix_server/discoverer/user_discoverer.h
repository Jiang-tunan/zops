#ifndef ZABBIX_USER_DISCOVERER_H
#define ZABBIX_USER_DISCOVERER_H

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>
#include "zbxmutexs.h"
#include "zbxdbhigh.h"
#include "zbxthreads.h"
#include "zbxnix.h"
#include "zbxdiscovery.h"
#include "discoverer_comm.h"

#define LOCK_USER_DISCOVER		zbx_mutex_lock(user_discover_lock)
#define UNLOCK_USER_DISCOVER	zbx_mutex_unlock(user_discover_lock)

#define DCR_MSG_TYPE				100		// discover 发送消息类型
#define MSG_KEY						(key_t)0416


#define DISCOVERY_CMD_ACTIVITE		"discovery_rules_activate"
#define DISCOVERY_CMD_PROGRESS		"discovery_rules_progress"
#define DISCOVERY_CMD_STOP			"discovery_rules_stop"
#define DISCOVERY_CMD_SINGLE_SCAN	"discovery_rules_single_scan"

#define DISCOVERY_RESULT_SUCCESS  					0       //成功，通用类型。
#define DISCOVERY_RESULT_FAIL						1000    //失败，通用类型。当不需要非常详细区分那种失败时候用
#define DISCOVERY_RESULT_NO_SESSION					1001    //请求没有session 参数，或者没有发现此session在扫描
#define DISCOVERY_RESULT_NO_DRULEID					1002    //请求没有ruleid 参数，或者没有发现此ruleid在扫描
#define DISCOVERY_RESULT_CREATE_FAIL				1003    //创建扫描规则失败
#define DISCOVERY_RESULT_QUERY_FAIL					1004    //查询扫描结果失败
#define DISCOVERY_RESULT_STOP_FAIL					1005    //停止扫描结果失败
#define DISCOVERY_RESULT_JSON_PARSE_FAIL			1006    //解析json失败
#define DISCOVERY_RESULT_SCAN_FAIL					1007    //单设备扫描失败
#define DISCOVERY_RESULT_CREDENTIAL_FAIL    		1008    //凭证错误
#define DISCOVERY_RESULT_DUPLICATE_FAIL				1009    //软件重复添加错误
#define DISCOVERY_RESULT_PORXY_CONN_FAIL			1010    //连接代理失败
#define DISCOVERY_RESULT_PORXY_NO_EXIST				1011    //不是代理服务器
#define DISCOVERY_RESULT_PORXY_NO_MATCH_MODE		1012    //代理服务器模式配置和服务器配置的不匹配
#define DISCOVERY_RESULT_PORXY_NO_MATCH_HOSTNAME	1013    //代理服务器名称配置和服务器配置的不匹配
#define DISCOVERY_RESULT_PORXY_OVER_NODES			1014    //代理服务器超过许可允许数量
#define DISCOVERY_RESULT_PORXY_SCAN_FAIL			1015    //代理服务器扫描设备/软件失败


#define USER_DISCOVER_IP_INTERVAL_TIME 		3     //用户扫描每个IP估算间隔时间,单位秒
#define USER_DISCOVER_IP_TIME_OUT   		6     //用户扫描每个IP过期时间,单位秒
#define USER_DISCOVER_QUERY_INTERVAL_TIME   2     //前端每次查询进度间隔时间,单位秒
#define USER_DISCOVER_EXTRA_TIME_OUT   		10    //用户扫描额外的过期时间,单位秒
#define USER_DISCOVER_SESSION_REMOVE_TIME	3600  //用户扫描old_session过期时间,单位秒

extern int msgid;


typedef enum
{
	ZBX_USER_DISCOVER_STATUS_FREE=0,      //用户扫码任务是释放状态
	ZBX_USER_DISCOVER_STATUS_CREATE,      //用户扫描任务被创建
	ZBX_USER_DISCOVER_STATUS_RUN,         //用户扫描任务正在进行
	ZBX_USER_DISCOVER_STATUS_FINISH       //扫描完成 扫描完成后等待读取数据
}
zbx_user_discover_status_t;


//超时
typedef struct
{
	char                         session[128];           			//session
	int                          sbegin_time;                       //完成时间
	int                          end_time;                       	//seesion最终删除时间
	int                          query_number;						//查询次数，做进度条用
	int                          progress;							//当前的进度0-100的值
	zbx_vector_str_t             hostids;                           //扫描出来的hostid列表，保存对象为字符串(char *)
	zbx_vector_str_t             all_hostids;                       //扫描出来的hostid列表，一直保存，给前端恢复页面用
	char*			             p_hostids;                         //从数据库读出的 扫描出来的hostid列表，
	char*			             p_all_hostids;                     //从数据库读出的 扫描出来的hostid列表，一直保存，给前端恢复页面用
}
zbx_user_discover_session_t;

//单个扫描规则 最小单位
typedef struct
{
	zbx_uint64_t                 druleid;                           //id
	int                          ip_all_num;                        //总ip数
	int                          ip_discovered_num;                 //已经扫完的ip数
	zbx_vector_ptr_t             sessions;                          //有哪些用户添加了这个规则,
                                                                    //保存对象为 zbx_user_discover_session_t
	zbx_user_discover_status_t   status;                            //扫描状态
	int                          check_type;						//扫描类型
	int                          vm_count;							// 虚拟机扫描出来的数量
	int                          hv_count;							// 服务器扫描出来的数量
	int                          vm_num;							// 虚拟机总数
	int                          hv_num;							// 服务器总数
	int							 proxy_discover_finish;				// 代理端扫描部分已经结束，代理只是完成了进度的一部分，需要服务端继续处理
	zbx_user_discover_session_t  proxy_session;						// 代理session对象
	
	int							 result;							//扫描结果
}
zbx_user_discover_drule_t;

//所有扫描 锁这个数据
typedef struct
{
	zbx_vector_ptr_t             drules;                            //所有扫描规则，包括已经完成的,zbx_user_discover_drule_t
	zbx_uint64_t                 druleid;                           //扫描到了哪一个规则
	int                          need_scan_druleid_num;				//需要扫描规则id的数量，<=0表示没有，>0表示有
	zbx_vector_ptr_t             old_sessions; 						//旧的session，当进度为100或超时后，把当前的session保存到此，供前端恢复页面用
}
zbx_user_discover_drules_t;


int	user_discover_create(int proxyhostid, const char *session, const struct zbx_json_parse *jp);
char* user_discover_progress(int proxy_hostid, const char * session, const struct zbx_json_parse *jp);
int	user_discover_stop(const char *session);

// int user_discover_gen_ip(const char *ipnext);
int user_discover_next_ip(zbx_uint64_t druleid);
int user_discover_next_druleid(zbx_uint64_t *druleid);
void zbx_user_discover_g_free();
void __zbx_user_discover_clean();

/*zhul*/
void discovery_rules_discoverer_thread_init();
void* discovery_rules_discoverer_thread_function(void* arg);
void discovery_rules_select(const char* request_value, int socket, const struct zbx_json_parse *jp, char *request);
char* create_progress_json(int proxy_hostid, const char* session_value, const struct zbx_json_parse *jp);
char* create_activate_or_stop_json(int result, const char *cmd, const char *session_value, const struct zbx_json_parse *jp);
char* create_fail_json(const char* response, const char* session, int result, const char* failreason);
int extract_druleids(const struct zbx_json_parse *jp, zbx_vector_uint64_t *druleids);
void discover_response_replay(int socket, const char* response);

int discovery_add_total_ip_num(zbx_uint64_t druleid, int type, int ip_num);
int discovered_next_ip(zbx_uint64_t druleid, int type, int ip_num);

void update_hostmacro_data(int hostmacroid, int hostid, char *macro, char *value, char *description);
void update_hostmacro_int_data(int hostmacroid, int hostid, char *macro, int ivalue, char *description);
char* user_discover_progress(int from_proxy, const char * session, const struct zbx_json_parse *jp);
int user_discover_add_result(zbx_uint64_t druleid, int result);

int	server_user_discover_create_proxy(int proxyhostid, const char *session, const struct zbx_json_parse *jp);
int server_discovery_proxy_add_total_ip_num(zbx_uint64_t druleid, int type, int ip_num);
int server_user_discover_add_proxy_hostid(zbx_uint64_t druleid, zbx_uint64_t hostid);
int server_discovered_proxy_next_ip(zbx_uint64_t druleid, int type, int ip_num);
int server_query_proxy_druleid_progress(const char * session, zbx_uint64_t druleid, int fullsync, 
	int *out_progress, int *out_remain_time, char **out_hostids);
int server_discover_proxy_finished(zbx_uint64_t druleid, char *session);
int server_discovery_proxy_progress_finish(char *proxy_resp, char **session);

int is_proxy_discover_finish(char *session, struct zbx_json_parse *jp, zbx_uint64_t *druleid,  int *fullsync);

int proxy_discover_finished(zbx_uint64_t druleid);
int proxy_get_sessions(zbx_uint64_t druleid, char **sessions);

#endif
