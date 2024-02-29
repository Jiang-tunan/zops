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

#define LOCK_USER_DISCOVER		zbx_mutex_lock(user_discover_lock)
#define UNLOCK_USER_DISCOVER	zbx_mutex_unlock(user_discover_lock)

#define DCR_MSG_TYPE				100		// discover 发送消息类型
#define MSG_KEY						(key_t)0416


#define DISCOVERY_CMD_ACTIVITE		"discovery_rules_activate"
#define DISCOVERY_CMD_PROGRESS		"discovery_rules_progress"
#define DISCOVERY_CMD_STOP			"discovery_rules_stop"
#define DISCOVERY_CMD_SINGLE_SCAN	"discovery_rules_single_scan"

#define DISCOVERY_RESULT_SUCCESS  			0       //成功
#define DISCOVERY_RESULT_NO_SESSION			1001    //请求没有session 参数，或者没有发现此session在扫描
#define DISCOVERY_RESULT_NO_DRULEID			1002    //请求没有ruleid 参数，或者没有发现此ruleid在扫描
#define DISCOVERY_RESULT_CREATE_FAIL		1003    //创建扫描规则失败
#define DISCOVERY_RESULT_QUERY_FAIL			1004    //查询扫描结果失败
#define DISCOVERY_RESULT_STOP_FAIL			1005    //停止扫描结果失败
#define DISCOVERY_RESULT_JSON_PARSE_FAIL	1006    //解析json失败
#define DISCOVERY_RESULT_SCAN_FAIL			1007    //单设备扫描失败
#define DISCOVERY_RESULT_CREDENTIAL_FAIL    1008    //凭证错误


#define USER_DISCOVER_IP_INTERVAL_TIME 		3     //用户扫描每个IP估算间隔时间,单位秒
#define USER_DISCOVER_IP_TIME_OUT   		6     //用户扫描每个IP过期时间,单位秒
#define USER_DISCOVER_QUERY_INTERVAL_TIME   2     //前端每次查询进度间隔时间,单位秒


extern int msgid;

// 消息队列结构体
struct json_queue
{
    long int type;						// 消息类型
	int recv_type;						// trapper 进程接收的消息类型
    char content[BUFSIZ];				// 信息存储
};

typedef enum
{
	ZBX_USER_DISCOVER_STATUS_FREE=0,      //用户扫码任务是释放状态
	ZBX_USER_DISCOVER_STATUS_CREATE,      //用户扫描任务被创建
	ZBX_USER_DISCOVER_STATUS_RUN,         //用户扫描任务正在进行
	ZBX_USER_DISCOVER_STATUS_FINISH       //扫描完成 扫描完成后等待读取数据
}
zbx_user_discover_status_t;

typedef struct
{
	char                         ip[ZBX_INTERFACE_IP_LEN_MAX];      //ip
	int                          port;                              //端口
}
zbx_user_discover_alarm_t;


//超时
typedef struct
{
	char                         session[MAX_STRING_LEN];           //session
	int                          sbegin_time;                       //完成时间
	int                          query_number;						//查询次数，做进度条用
	int                          progress;							//当前的进度0-100的值
	zbx_vector_ptr_t             hostids;                           //扫描出来的hostid列表，保存对象为字符串(char *)
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
	zbx_vector_ptr_t             alarms;                            //没有mac地址的告警
	zbx_user_discover_status_t   status;                            //扫描状态
	int                          check_type;						//扫描类型
	int                          vm_count;
	int                          hv_count;
	int                          vm_num;
	int                          hv_num;							
}
zbx_user_discover_drule_t;

//所有扫描 锁这个数据
typedef struct
{
	zbx_vector_ptr_t             drules;                            //所有扫描规则，包括已经完成的,zbx_user_discover_drule_t
	zbx_uint64_t                 druleid;                           //扫描到了哪一个规则
	int                          need_scan_druleid_num;				//需要扫描规则id的数量，<=0表示没有，>0表示有
}
zbx_user_discover_drules_t;

int	user_discover_create(const char *session, zbx_vector_ptr_t *druleids);
char* user_discover_progress(const char * session, const struct zbx_json_parse *jp);
int	user_discover_stop(const char *session);

// int user_discover_gen_ip(const char *ipnext);
void user_discover_next_ip(zbx_uint64_t druleid, int *next_drule);
int user_discover_next_druleid(zbx_uint64_t *druleid);
int user_discover_add_alarm(zbx_uint64_t druleid, const char *ip, const int port);
void zbx_user_discover_g_free();
void __zbx_user_discover_clean();

/*zhul*/
void discovery_rules_discoverer_thread_init();
void* discovery_rules_discoverer_thread_function(void* arg);
void discovery_rules_select(const char* request_value, int socket, const struct zbx_json_parse *jp);
char* create_progress_json(const char* session_value, const struct zbx_json_parse *jp);
char* create_activate_or_stop_json(const char *response, const char *session_value, const struct zbx_json_parse *jp);
char* create_fail_json(const char* response, const char* session, int result, const char* failreason);
int extract_druleids(const struct zbx_json_parse *jp, zbx_vector_uint64_t *druleids);
void discover_response_replay(int socket, const char* response);

int vmware_add_ip_num(zbx_uint64_t druleid, int type, int ip_num);
int vmware_add_discovered_ip_num(zbx_uint64_t druleid, int type, int ip_num);
#endif
