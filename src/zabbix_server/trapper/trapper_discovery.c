#ifndef TRAPPER_DISCOVERY_C
#define TRAPPER_DISCOVERY_C

#include "zbxdbwrap.h"
#include "trapper_discovery.h"
#include "zbx_rtc_constants.h"
#include "../../libs/zbxcacheconfig/dbconfig.h"
#include "../discoverer/user_discoverer.h"
#include "../discoverer/discoverer_comm.h"
#include "zbxip.h"
#include "../../libs/zbxcomms/comms.h"
#include "../../libs/zbxrtc/rtc.h"

zbx_vector_ptr_t global_sock_queue;
int create_queue_flag = FALSE;
static int is_initialized = 0;
int msgid = -1;
static int G_TPR_MSG_TYPE = 200;		// trapper 消息类型
static int G_DCR_MSG_TYPE = 100;		// discover 消息类型

extern int	CONFIG_TRAPPER_TIMEOUT;
extern char	*CONFIG_SOURCE_IP;
extern unsigned char	program_type;
extern char	*CONFIG_HOSTNAME;
extern int g_running_program_type;

void discovery_rules_trapper_thread_init(int server_num)
{
    int ret = FAIL;
    pthread_t drt_thread; // 接收线程

    if (!is_initialized)
    {
        
        // 执行初始化操作
        G_TPR_MSG_TYPE = G_TPR_MSG_TYPE + server_num;
        if(-1 == (msgid =  msgget(MSG_KEY, 0666 | IPC_CREAT)))
        { 
            zabbix_log(LOG_LEVEL_WARNING, 
                "#TOGNIX#%s, msgqueue creat fail! msgid=%d, errmsg=%s", 
                __func__, msgid, strerror(errno));
        }

        zbx_vector_ptr_create(&global_sock_queue);

        // 创建 接收response 线程
        ret = pthread_create(&drt_thread, NULL, discovery_rules_trapper_thread_function, NULL);
        zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s  ret=%d,msgid=%d,recv_type=%d", __func__, ret, msgid, G_TPR_MSG_TYPE);

        is_initialized = 1; // 标记为已初始化
    }
}

int tognix_tcp_send(zbx_socket_t *s, const char *data, size_t len, int timeout)
{

    int result = zbx_tcp_send_bytes_to(s, data, len, timeout);
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX# send response: socket=%d, send_result=%d, message=%s",
             s->socket, result, print_content(data));
    return result;
}

/*********************************************
 * 设备发现状态[discovery_rules_progress> <discovery_rules_activate> <discovery_rules_stop]处理
 *
 * Parameter :
 * 	@ sock				客户端连接 sock
 *  @ input_json		客户端发起请求内容
 * 	@ ts				时间戳
 *
 * Return : 
 *  SUCCEED 			0 处理成功	
 *	FAIL				-1 处理失败	
************************************************/
int discovery_rules_state(int from_proxy, zbx_socket_t *sock, char *input_json, int config_timeout, zbx_ipc_async_socket_t *rtc)
{
    struct json_queue send_js;
    char session_value[128] = {""}, cmd[128] = {""}; 

    struct zbx_json_parse	jp;
   
    if (SUCCEED != zbx_json_open(input_json, &jp))
        return FAIL;

    if (SUCCEED != zbx_json_value_by_name(&jp, ZBX_PROTO_TAG_REQUEST, cmd, sizeof(cmd), NULL))
        return FAIL;
    if (SUCCEED != zbx_json_value_by_name(&jp, ZBX_PROTO_TAG_SESSION, session_value, sizeof(session_value), NULL))
        return FAIL;

    // 代理端在被动模式下，如果是触发扫描/添加情况下，主动拉取服务端相关数据
    if(ZBX_PROGRAM_TYPE_PROXY == g_running_program_type)
    {
        if(0 == strcmp(cmd, DISCOVERY_RULES_ACTIVATE) ||
			0 == strcmp(cmd, DISCOVERY_RULES_SINGLE_SCAN))
        {
            zbx_rtc_notify_proxy_config_fullsync(config_timeout, rtc);
        }
    }

     // 创建一个sock_queue结构的实例
    struct sock_queue *new_item = (struct sock_queue *)malloc(sizeof(struct sock_queue));
    
    if(from_proxy){
        // 从代理发到服务端的请求，因为是线程处理，前面已经copy_zbx_socket了，所以这里直接使用
        new_item->sock = sock;
    }else{
        zbx_socket_t *resp_sock = (zbx_socket_t *)zbx_malloc(NULL, sizeof(zbx_socket_t));
        copy_zbx_socket(sock, resp_sock);
        // memcpy(resp_sock, sock, sizeof(sock));
        sock->socket = ZBX_SOCKET_ERROR;
        new_item->sock = resp_sock;
    }
   
    new_item->id = msgid; 
   
    new_item->config_timeout = config_timeout;
    zbx_strlcpy(new_item->session_value, session_value, sizeof(new_item->session_value));

    // 将该结构的实例添加到全局队列中
    zbx_vector_ptr_append(&global_sock_queue, new_item);

    // 将 json 数据发送到 discoverer 处理
    send_js.type = G_DCR_MSG_TYPE;
    send_js.recv_type = G_TPR_MSG_TYPE;
    zbx_strscpy(send_js.content, input_json); 
    int send_size = sizeof(send_js.recv_type) + strlen(send_js.content) + 1;
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX# recv request: socket=%d, recv_type=%d, send_size=%d, msg=%s", 
            new_item->sock->socket, send_js.recv_type, send_size, send_js.content);

    if (-1 == msgsnd(msgid, (void *)&send_js, send_size, IPC_NOWAIT))
    {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s()Failed to send string [msgid=%d size=%d type=%d]\n%s\n'%s'",
             __func__, msgid, send_size, send_js.type, send_js.content, strerror(errno));
        // zbx_tcp_send_to(sock, sendbuf.json_buf,tz); #未创建错误 json 数据
        return FAIL;        // 发送 json 失败 返回FAIL
    }
    // zbx_sleep(1);
    return SUCCEED;
}

void* discovery_rules_trapper_thread_function(void* arg) 
{
    struct json_queue r_msg;
    char session_value[MAX_STRING_LEN];
    int count = 1, result = 0;
    while(ZBX_IS_RUNNING() && count <= 5) 
    {
        memset(session_value, 0, sizeof(session_value));

        // 接收消息队列中的消息
        if (-1 == msgrcv(msgid, &r_msg, QUEUE_STR_LEN, G_TPR_MSG_TYPE, 0)) 
        {
            int old_msgid = msgid;
            zbx_sleep(count * 5);
			// 碰到过消息队列失败情况,这里增加重试机制。如果重试3次都没有创建队列，则退出线程。
			if(-1 == (msgid = msgget(MSG_KEY, 0666 | IPC_CREAT))){
				count ++;
			}else{
				count = 0;
			}
			zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#discovery_rules_trapper. Failed to receive message from queue,o_msgid=%d,msgid=%d",
				old_msgid, msgid);
			continue;
        }

    
        if (SUCCEED != extract_session_from_json(r_msg.content, session_value))
        {
            zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s()Failed to extract session from JSON", __func__);
            continue;
        }

        // zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s() before", __func__);
        // zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#Current queue size: %d", global_sock_queue.values_num);
        struct sock_queue *queue_item = NULL;
        int found = 0;

        // 遍历队列
        if (0 != global_sock_queue.values_num)
        { 
            //遍历队列查找数据
            for (int i = 0; i < global_sock_queue.values_num; i++)
            {
                queue_item = (struct sock_queue*)global_sock_queue.values[i];
                if (0 == strcmp(session_value, queue_item->session_value))
                {
                    found = 1;
                    // 从队列中删除数据
                    zbx_vector_ptr_remove(&global_sock_queue, i); 
                    break;
                }
            } 
        } 
        if (!found)
        {
            zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s()Session value not found in queue: %s", __func__, session_value);
            continue;
        }

        int result = tognix_tcp_send(queue_item->sock, r_msg.content, strlen(r_msg.content), queue_item->config_timeout);
        // 使用找到的元素进行回复
        if (SUCCEED != result)
        {
            zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#%s()Failed to send response to client", __func__);
        }

        zbx_tcp_close(queue_item->sock);
 
        zbx_free(queue_item);
    }

    pthread_exit(NULL);
}


int extract_session_from_json(const char *json_str, char *session) {
    struct zbx_json_parse jp;
    char *session_ptr = NULL;

    if (FAIL == zbx_json_open(json_str, &jp)) {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#Failed to parse JSON.");
        return FAIL; // 解析失败
    }

    session_ptr = zbx_json_pair_by_name(&jp, "session");
    if (session_ptr == NULL) {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#JSON does not contain a session key.");
        return FAIL; // 没有找到 session 键
    }

    if (NULL == zbx_json_decodevalue(session_ptr, session, MAX_STRING_LEN - 1, NULL)) {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#Failed to decode session value from JSON.");
        return FAIL; // 解码 session 值失败
    }

    return SUCCEED; // 成功提取 session
}

static char* build_comm_resp_json(int result, char *session, char *cmd)
{ 
	struct zbx_json	json;
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);

	zbx_json_addstring(&json, "response", cmd, ZBX_JSON_TYPE_STRING);
	zbx_json_addstring(&json, "session", session, ZBX_JSON_TYPE_STRING);
	zbx_json_addint64(&json, "result", result);
	zbx_json_addarray(&json, "data");
 	zbx_json_close(&json);
	char *sjson = strdup(json.buffer);
	zbx_json_free(&json);
	return sjson;
}

int discovery_comm_check_ip_connect(zbx_socket_t *sock, struct zbx_json_parse *jp, int config_timeout)
{ 
    struct zbx_json_parse jp_params;
    const char *p = NULL; 
    char tstr[256], *ip=NULL, *session=NULL;
	int ret = FAIL, port = 0;
    zbx_socket_t	dsock; 

    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(jp, "session", tstr, sizeof(tstr), NULL))
    {
        session = zbx_strdup(NULL, tstr);
    }

	if (SUCCEED != zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &jp_params))
	{
		return ret;
	}
	  
    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp_params, "ip", tstr, sizeof(tstr), NULL))
    {
        ip = zbx_strdup(NULL, tstr);
    }
    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp_params, "port", tstr, sizeof(tstr), NULL))
    {
        port = zbx_atoi(tstr);
    }

    if(NULL != ip && port > 0){
        ret = zbx_tcp_connect(&dsock, CONFIG_SOURCE_IP, ip, port, 2, ZBX_TCP_SEC_UNENCRYPTED, NULL, NULL);
        zbx_tcp_close(&dsock);
    }
    char *response = build_comm_resp_json(ret, session, COMMON_CHECK_IP_CONNECT);
    tognix_tcp_send(sock, response, strlen(response), config_timeout);

    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ip=%s,port=%d,result=%d",__func__, ip, port, ret);
    
    zbx_free(session);
    zbx_free(ip);
    zbx_free(response);
    return ret;
}


int discovery_comm_check_sendmail(zbx_socket_t *sock, struct zbx_json_parse *jp, int config_timeout)
{ 
    struct zbx_json_parse jp_params;
	int ret = DISCOVERY_RESULT_FAIL, mediatypeid=-1;
    DB_RESULT	result = NULL;
	DB_ROW		row;
    char *smtp_server=NULL,  *smtp_helo=NULL,  *smtp_email=NULL,  *mailto=NULL,  *inreplyto=NULL,  *mailsubject=NULL, *mailbody=NULL;
    char tstr[256], *session=NULL, *name=NULL, *username=NULL, *password=NULL, *response=NULL;
	unsigned char smtp_security=0, smtp_verify_peer=0, smtp_verify_host=0,smtp_authentication=0, content_type=0;
    int k = 0, timeout=6;
    size_t value_size = 0;
    unsigned short smtp_port=0;
    char error[MAX_STRING_LEN];

    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(jp, "session", tstr, sizeof(tstr), NULL)){
        session = zbx_strdup(NULL, tstr);
    }

	if (FAIL == zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &jp_params)){
		goto out;
	}
	  
    memset(&tstr, 0, sizeof(tstr));
    if (FAIL == zbx_json_value_by_name(&jp_params, "mediatypeid", tstr, sizeof(tstr), NULL))
        goto out;
    else
        mediatypeid = zbx_atoi(tstr);

    if (FAIL == zbx_json_value_by_name_dyn(&jp_params, "mailto", &mailto, &value_size, NULL))
        goto out;

    value_size = 0;
    if (FAIL == zbx_json_value_by_name_dyn(&jp_params, "mailsubject", &mailsubject, &value_size, NULL))
        goto out;
    
    value_size = 0;
    if (FAIL == zbx_json_value_by_name_dyn(&jp_params, "mailbody", &mailbody, &value_size, NULL))
        goto out;

    result = zbx_db_select("select name,smtp_server,smtp_helo,smtp_email,username,passwd," \
        "smtp_port,smtp_security,smtp_verify_peer,smtp_verify_host,smtp_authentication," \
        "content_type,timeout from media_type where mediatypeid=%d", mediatypeid);
    if (NULL != (row = zbx_db_fetch(result)))
    {
        k = 0;
        name = zbx_strdup(NULL,row[k++]);
        smtp_server = zbx_strdup(NULL,row[k++]);
        smtp_helo = zbx_strdup(NULL,row[k++]);
        smtp_email = zbx_strdup(NULL,row[k++]);
        username = zbx_strdup(NULL,row[k++]);
        password = zbx_strdup(NULL,row[k++]);
        smtp_port = zbx_atoi(row[k++]);
        ZBX_STR2UCHAR(smtp_security, row[k++]);
        ZBX_STR2UCHAR(smtp_verify_peer, row[k++]);
        ZBX_STR2UCHAR(smtp_verify_host, row[k++]);
        ZBX_STR2UCHAR(smtp_authentication, row[k++]);
        ZBX_STR2UCHAR(content_type, row[k++]);
    } else{
        goto out;
    }
    ret = send_email(smtp_server, smtp_port, smtp_helo, smtp_email,
		mailto, inreplyto, mailsubject, mailbody,
		smtp_security, smtp_verify_peer, smtp_verify_host,
		smtp_authentication, username, password,
		content_type, timeout, error, sizeof(error));

    if(SUCCEED != ret) ret = DISCOVERY_RESULT_FAIL;

out:
    zbx_db_free_result(result);
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s result=%d, mediatypeid=%d,name=%s,smtp_server=%s, smtp_port=%d,mailto=%s, mailsubject=%s, mailbody=%s,error=%s",
        __func__,ret, mediatypeid,name,smtp_server,smtp_port,mailto,mailsubject,mailbody,error);
    
    response = build_comm_resp_json(ret, session, COMMON_CHECK_SEND_MAIL);
    tognix_tcp_send(sock, response, strlen(response), config_timeout); 

    zbx_free(session);
    zbx_free(response);
    zbx_free(smtp_server);
    zbx_free(smtp_helo);
    zbx_free(smtp_email);
    zbx_free(mailto);
    zbx_free(inreplyto);
    zbx_free(mailsubject);
    zbx_free(mailbody);
    zbx_free(name);
    zbx_free(username);
    zbx_free(password);

    return ret;
}

// 代理程序处理服务器发过来的检测代理请求
int proxy_check_proxy_server(zbx_socket_t *sock, char *request, struct zbx_json_parse *jp, int config_timeout)
{ 
    struct zbx_json_parse jp_params;
    char tstr[256], *session=NULL, *hostname=NULL;
	int ret = DISCOVERY_RESULT_PORXY_NO_EXIST, proxymode = 0;
    DB_RESULT	result = NULL;
	DB_ROW		row;
    
    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(jp, "session", tstr, sizeof(tstr), NULL)){
        session = zbx_strdup(NULL, tstr);
    }

	if (SUCCEED != zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &jp_params)){
		return ret;
	}

    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp_params, "proxymode", tstr, sizeof(tstr), NULL)){
        proxymode = zbx_atoi(tstr);
    }
    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp_params, "hostname", tstr, sizeof(tstr), NULL)){
        hostname = zbx_strdup(NULL, tstr);
    }


    // 获得代理许可的数量
	int now_proxy_nodes = 0, allow_proxy_nodes = 0;
    allow_proxy_nodes = get_monitor_nodes("proxy");
    if(allow_proxy_nodes > 0)
    {
        result = zbx_db_select("select count(1) from hosts where  (status = %d or status = %d) and host <> '%s'",
        HOST_STATUS_PROXY_ACTIVE, HOST_STATUS_PROXY_PASSIVE, hostname);
        if (NULL != (row = zbx_db_fetch(result)))
        {
            // 当前数量新增加一个
            now_proxy_nodes = zbx_atoi(row[0]) + 1;
        } 
        zbx_db_free_result(result);
    }

    if(now_proxy_nodes > allow_proxy_nodes )
    {
        // 当前代理数量大于许可代理数量，则返回超过代理数的错误
        ret = DISCOVERY_RESULT_PORXY_OVER_NODES;
    }
    else if (0 != (program_type & ZBX_PROGRAM_TYPE_PROXY))
    {
        // 判断服务端的代理模式是否和本地代理模式一致，如果不一致，则返回错误
        if(  (program_type == ZBX_PROGRAM_TYPE_PROXY_PASSIVE && proxymode == 1)
          || (program_type == ZBX_PROGRAM_TYPE_PROXY_ACTIVE && proxymode == 0)){
           ret = SUCCEED;
        }else{
            ret = DISCOVERY_RESULT_PORXY_NO_MATCH_MODE;
        }
        
        // 判断服务端的代理名称是否和本地代理名称一致，如果不一致，则返回错误
        if(SUCCEED == ret && 0 != zbx_strcmp_null(CONFIG_HOSTNAME, hostname)){
            ret = DISCOVERY_RESULT_PORXY_NO_MATCH_HOSTNAME;
        }
    }
    else
    {
        ret = DISCOVERY_RESULT_PORXY_NO_EXIST;
    }

    char *response = build_comm_resp_json(ret, session, DISCOVERY_CHECK_PROXY_SERVER);
    tognix_tcp_send(sock, response, strlen(response), config_timeout);

    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s session=%s,program_type=%d,proxymode=%d,hostname=%s,result=%d",
        __func__, session,program_type, proxymode, CONFIG_HOSTNAME, ret);
    
    zbx_free(session);
    zbx_free(response);
    zbx_free(hostname);
    return ret;
}

// 检测代理服务器是否可用,添加代理服务器时执行
int discovery_check_proxy_server(zbx_socket_t *sock, char *request, struct zbx_json_parse *jp, int config_timeout)
{ 
    struct zbx_json_parse jp_params;
    const char *p = NULL; 
    char tstr[256], *ip=NULL, *session=NULL, *response=NULL;
	int ret = FAIL, port = 0, depth = 0;
    zbx_socket_t	dsock; 
    struct zbx_json json;	
    zbx_map_t dc_map;
	zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);

    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(jp, "session", tstr, sizeof(tstr), NULL)){
        session = zbx_strdup(NULL, tstr);
    }else{
         ret = DISCOVERY_RESULT_NO_SESSION;
		goto out;
    }

	if (SUCCEED != zbx_json_brackets_by_name(jp, ZBX_PROTO_TAG_PARAMS, &jp_params)){
        ret = DISCOVERY_RESULT_JSON_PARSE_FAIL;
		goto out;
	}
	  
    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp_params, "ip", tstr, sizeof(tstr), NULL)){
        ip = zbx_strdup(NULL, tstr);
    }
    memset(&tstr, 0, sizeof(tstr));
    if (SUCCEED == zbx_json_value_by_name(&jp_params, "port", tstr, sizeof(tstr), NULL)){
        port = zbx_atoi(tstr);
    }


    if(NULL != ip && port > 0){
        if(SUCCEED != zbx_tcp_connect(&dsock, CONFIG_SOURCE_IP, ip, port, 2, ZBX_TCP_SEC_UNENCRYPTED, NULL, NULL)){
            ret = DISCOVERY_RESULT_PORXY_CONN_FAIL;
            goto out;
        }
    }else{
        ret = DISCOVERY_RESULT_JSON_PARSE_FAIL;
		goto out;
    }
    
   
    dc_map.name = "request";
    dc_map.value = PROXY_CHECK_PROXY_SERVER;
	copy_original_json2(ZBX_JSON_TYPE_OBJECT, jp, &json, depth, &dc_map);
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ip=%s,port=%d,request=%s",__func__, ip, port, json.buffer);
    if (FAIL == (ret = zbx_tcp_send_ext(&dsock, json.buffer, strlen(json.buffer), 0, ZBX_TCP_PROTOCOL, 0))){
        ret = DISCOVERY_RESULT_PORXY_CONN_FAIL;
        goto out;
    }
    if (FAIL == (ret = zbx_tcp_recv(&dsock))){
        ret = DISCOVERY_RESULT_PORXY_NO_EXIST;
        goto out;
    }
    response = zbx_strdup(NULL, dsock.buffer);
    
out:
    if(response == NULL){
        response = build_comm_resp_json(ret, session, DISCOVERY_CHECK_PROXY_SERVER);
    }
    tognix_tcp_send(sock, response, strlen(response), config_timeout);

    zbx_json_free(&json);
    zbx_free(session);
    zbx_free(ip);
    zbx_free(response);
    zbx_tcp_close(&dsock);
    
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s ip=%s,port=%d,result=%d",__func__, ip, port, ret);
    return ret;
}


/*zhu adds content * 软件许可 */

/**
 * 发送 许可密钥 响应
*/
int send_productkey(zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout)
{
    char productkey[2 * SHA256_DIGEST_SIZE + 1];
    char session_value[128] = ""; 
    char resqust_value[128] = "";
    char *response = NULL;
    char *resqust = NULL;
    int result = DISCOVERY_RESULT_FAIL;

    // 提取 resqust char resqust_value[MAX_STRING_LEN] = "";
    if (SUCCEED != zbx_json_value_by_name(jp, ZBX_PROTO_TAG_REQUEST, resqust_value, sizeof(resqust_value), NULL))
    {
        result = DISCOVERY_RESULT_FAIL;
        response = create_license_fail(result, "Failed to ectract resqust value");
        goto out;
    }

    // 提取 session
    if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), NULL))
    {
        result = DISCOVERY_RESULT_NO_SESSION;
        response = create_license_fail(result, "Failed to ectract session value");
        goto out;
    }

    if (SUCCEED >= (result = create_productkey(productkey)))
    {
        result = DISCOVERY_RESULT_FAIL;
        response = create_license_fail(result, "Error creating product key.");
        goto out;
    }else{
        result = DISCOVERY_RESULT_SUCCESS;
    }

    response = create_productkey_json(SUCCEED, resqust_value, session_value, productkey);

out:
    // 发送响应
    if (SUCCEED != tognix_tcp_send(sock, response, strlen(response), config_timeout))
    {
        zabbix_log(LOG_LEVEL_ERR, "The send_productkey function encountered an error while sending the JSON response.");
    }
    
	zbx_free(response);
    return result;
}

/**
 * 发送 许可校验 响应
*/
int send_license_verify(zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout)
{
    char session_value[MAX_STRING_LEN] = "";
    char resqust_value[MAX_STRING_LEN] = "";
    char *response = NULL;
    struct service monitor_services[MAX_STRING_LEN];
    struct service function_services[MAX_STRING_LEN];
    short monitor_size = 0, func_size = 0;
    int result = DISCOVERY_RESULT_FAIL, nodes;
    long lic_expired = 0;

    // 提取 resqust 
    if (SUCCEED != zbx_json_value_by_name(jp, ZBX_PROTO_TAG_REQUEST, resqust_value, sizeof(resqust_value), NULL))
    {
        result = DISCOVERY_RESULT_FAIL;
        response = create_license_fail(result, "Failed to ectract resqust value");
        goto out;
    }
    // 提取 session
    if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), 	NULL))
    {
        result = DISCOVERY_RESULT_NO_SESSION;
        response = create_license_fail(result, "Failed to ectract session value");
        goto out;
    }

    // 提取 monitor 和 function 数组
    if (FAIL == extract_monitor_and_function(jp, &nodes, monitor_services, function_services, &monitor_size, &func_size))
    {
        result = DISCOVERY_RESULT_FAIL;
        response = create_license_fail(result, "Failed to extract monitor and function data.");
        goto out;
    }
    
    // 调用 verify_license 函数
    result = verify_license(nodes, &lic_expired, monitor_size, monitor_services, func_size, function_services);

    // 调试信息
    zabbix_log(LOG_LEVEL_DEBUG, "monitor_size:%d, func_size:%d",monitor_size, func_size);
    for (int i = 0; i < monitor_size; i++)
        zabbix_log(LOG_LEVEL_DEBUG, "monitor_services->func:%s  allow:%d  ", monitor_services[i].func, monitor_services[i].allow);
    for (int i = 0; i < func_size; i++)
        zabbix_log(LOG_LEVEL_DEBUG, "function_services->func:%s  allow:%d  ", function_services[i].func, function_services[i].allow);
    zabbix_log(LOG_LEVEL_DEBUG, "lic_expired:%ld  ", lic_expired);

    if (result != LICENSE_SUCCESS)
    {
        result = DISCOVERY_RESULT_FAIL;
        if(LICENSE_OVER_NODES == result)
        {
            response = create_license_fail(result, "Number of nodes exceeded.");
        }
        else if(LICENSE_EXPIRED == result)
        {
            response = create_license_fail(result, "License expiration.");
        }
        else
        {
            response = create_license_fail(result, "License verification failed.");
        }
        goto out;
    }else{
        result = DISCOVERY_RESULT_SUCCESS;
    }

    response = create_license_verify_json(resqust_value, session_value, monitor_services, function_services, monitor_size, func_size, lic_expired);

out:
    // 发送响应
    if (SUCCEED != tognix_tcp_send(sock, response, strlen(response), config_timeout))
    {
        zabbix_log(LOG_LEVEL_ERR, "The `send_license_verify` function encountered an error while sending the JSON response.");
    }

	zbx_free(response);
    return SUCCEED;
}

/**
 * 发送 许可查询 响应
*/
int send_license_query(zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout)
{
    char session_value[MAX_STRING_LEN] = "";
    char resqust_value[MAX_STRING_LEN] = "";
    char *response = NULL;
    struct app_license *lic = NULL;
    int result = DISCOVERY_RESULT_FAIL;
    // 提取 resqust 
    if (SUCCEED != zbx_json_value_by_name(jp, ZBX_PROTO_TAG_REQUEST, resqust_value, sizeof(resqust_value), NULL))
    {
        result = DISCOVERY_RESULT_FAIL;
        response = create_license_fail(result, "Failed to ectract resqust value");
        goto out;
    }
    // 提取 session
    if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), NULL))
    {
        result = DISCOVERY_RESULT_NO_SESSION;
        response = create_license_fail(result, "Failed to ectract session value");
        goto out;
    }

    // 调用 query_license 函数
    if (FAIL == query_license(&lic))
    {
        result = DISCOVERY_RESULT_FAIL;
        response = create_license_fail(result, "Failed to query license.");
        goto out;
    }
    result = DISCOVERY_RESULT_SUCCESS;
    response = create_license_query_json(resqust_value, session_value, lic);
out:
    // 发送响应
    if (SUCCEED != tognix_tcp_send(sock, response, strlen(response), config_timeout))
    {
        zabbix_log(LOG_LEVEL_ERR, "The `send_license_query` function encountered an error while sending the JSON response.");
    }

    zbx_free(response);
    zbx_free(lic);
    return result;
}

/**
 * 构建 获得产品密钥 响应
*/
char* create_productkey_json(const int result, const char* resqust, const char* session, const char* productkey)
{
    struct zbx_json j;
    char *response_json = NULL;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addstring(&j, "response", resqust, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "session", session, ZBX_JSON_TYPE_STRING);
    zbx_json_addint64(&j, "result", result);
    zbx_json_addstring(&j, "retmsg", "", ZBX_JSON_TYPE_STRING);
    
    
    zbx_json_addobject(&j, "data");
    zbx_json_addstring(&j, "productkey", productkey, ZBX_JSON_TYPE_STRING);
    zbx_json_close(&j);

    response_json = strdup(j.buffer);
    zbx_json_free(&j);

    return response_json;
}

/**
 * 构建 许可校验 查询响应
*/
char* create_license_verify_json(const char * resqust, const char* session, struct service *monitor_services, struct service *function_services,
                                const short monitor_size, const short func_size, const long lic_expired)
{
    struct zbx_json j;
    char *response_json = NULL;
    int i;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addstring(&j, "response", resqust, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "session", session, ZBX_JSON_TYPE_STRING);
    zbx_json_addint64(&j, "result", SUCCEED);
    zbx_json_addstring(&j, "retmsg", "", ZBX_JSON_TYPE_STRING);

    zbx_json_addobject(&j, "data");
    zbx_json_addint64(&j, "lic_expired", lic_expired);
    zbx_json_addarray(&j, "monitor");
    for (i = 0; i < monitor_size; i++)
    {
        zabbix_log(LOG_LEVEL_DEBUG,"json monitor for %d", i);
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "func", monitor_services[i].func, ZBX_JSON_TYPE_STRING);
        zbx_json_addint64(&j, "allow", monitor_services[i].allow);
        zbx_json_close(&j);
    }
    zbx_json_close(&j);

    zbx_json_addarray(&j, "function");
    for (i = 0; i < func_size; i++)
    {
        zabbix_log(LOG_LEVEL_DEBUG,"json function for %d", i);
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "func", function_services[i].func, ZBX_JSON_TYPE_STRING);
        zbx_json_addint64(&j, "allow", function_services[i].allow);
        zbx_json_close(&j);
    }
    zbx_json_close(&j);

    zbx_json_close(&j);

    response_json = strdup(j.buffer);
    zbx_json_free(&j);

    return response_json;
}

/**
 * 构建 产品许可 查询响应
 */
char* create_license_query_json(const char* resqust, const char* session, struct app_license *lic)
{
    struct zbx_json j;
    char *response_json = NULL;
    int i;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addstring(&j, "response", resqust, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "session", session, ZBX_JSON_TYPE_STRING);
    zbx_json_addint64(&j, "result", SUCCEED);
    zbx_json_addstring(&j, "retmsg", "", ZBX_JSON_TYPE_STRING);

    zbx_json_addobject(&j, "data");

    zbx_json_addstring(&j, "company", lic->company, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "version", lic->version, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "lic_begin", lic->lic_begin, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "lic_expired", lic->lic_expired, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "productkey", lic->productkey, ZBX_JSON_TYPE_STRING);
    zbx_json_addint64(&j, "nodes", lic->nodes);

    zbx_json_addarray(&j, "monitor");
    for (i = 0; i < lic->monitor_size; i++)
    {
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "func", lic->monitor[i].func, ZBX_JSON_TYPE_STRING);
        zbx_json_addint64(&j, "nodes", lic->monitor[i].nodes);
        zbx_json_close(&j);
    }
    zbx_json_close(&j);

    zbx_json_addarray(&j, "function");
    for (i = 0; i < lic->func_size; i++)
    {
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "func", lic->func[i].func, ZBX_JSON_TYPE_STRING);
        zbx_json_addint64(&j, "allow", lic->func[i].allow);
        zbx_json_close(&j);
    }
    zbx_json_close(&j);

    zbx_json_close(&j);

    response_json = strdup(j.buffer);
    zbx_json_free(&j);

    return response_json;
}

/**
 * 构建 查询报错 响应
*/
char* create_license_fail(const int result, const char *retmsg)
{
    struct zbx_json j;
    char *response_json = NULL;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addint64(&j, "result", result);
    zbx_json_addstring(&j, "retmsg", retmsg, ZBX_JSON_TYPE_STRING);

    response_json = strdup(j.buffer);
    zbx_json_free(&j);

    return response_json;
}

/**
 * 提取 monitor and function
 */
int extract_monitor_and_function(const struct zbx_json_parse *jp, int *nodes, struct service *monitor_services, struct service *function_services, short *monitor_size, short *func_size)
{
    struct zbx_json_parse jp_params, jp_monitor, jp_function;
    char *p = NULL;
    int index;
    char nodes_str[MAX_STRING_LEN], monitor_nodes_str[MAX_STRING_LEN];

    // 获取 params 对象
    if (SUCCEED != zbx_json_brackets_by_name(jp, "params", &jp_params))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to fetch params object.");
        return FAIL;
    }

    // 从 params 对象中提取 nodes
    if (SUCCEED != zbx_json_value_by_name(&jp_params, "nodes", nodes_str, sizeof(nodes_str), NULL))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to fetch node number.");
        return FAIL;
    }
    *nodes = atoi(nodes_str);
	 
    // 从 params 对象中提取 monitor
    if (SUCCEED != zbx_json_brackets_by_name(&jp_params, "monitor", &jp_monitor))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to fetch monitor object.");
        return FAIL;
    }
    index = 0;
    while (NULL != (p = (char *)zbx_json_next(&jp_monitor, p)))
    {
        struct zbx_json_parse jp_sub;
        if (SUCCEED != zbx_json_brackets_open(p, &jp_sub))
        {
            zabbix_log(LOG_LEVEL_ERR, "Failed to open JSON object while processing %s. JSON fragment: %s", 
               (jp == &jp_monitor) ? "monitor" : "function", p);
            return FAIL;
        }
        if (SUCCEED != zbx_json_value_by_name(&jp_sub, "func", monitor_services[index].func, sizeof(monitor_services[index].func), NULL))
        {
            zabbix_log(LOG_LEVEL_ERR, "Failed to extract 'func' from monitor object.");
            return FAIL;
        }
        if (SUCCEED != zbx_json_value_by_name(&jp_sub, "nodes", monitor_nodes_str, sizeof(monitor_nodes_str), NULL))
        {
            zabbix_log(LOG_LEVEL_ERR, "Failed to extract 'nodes' from monitor object.");
            return FAIL;
        }
        monitor_services[index].nodes = atoi(monitor_nodes_str);
        index++;
    }
    *monitor_size = index;

    // 从 params 对象中提取 function
    if (SUCCEED != zbx_json_brackets_by_name(&jp_params, "function", &jp_function))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to fetch function object.");
        return FAIL;
    }
    p = NULL;  // 重置指针
    index = 0; // 重置索引
    while (NULL != (p = (char *)zbx_json_next(&jp_function, p)))
    {
        struct zbx_json_parse jp_sub;
        if (SUCCEED != zbx_json_brackets_open(p, &jp_sub))
        {
            zabbix_log(LOG_LEVEL_ERR, "Failed to open JSON object while processing %s. JSON fragment: %s", 
               (jp == &jp_monitor) ? "monitor" : "function", p);
            return FAIL;
        }
        if (SUCCEED != zbx_json_value_by_name(&jp_sub, "func", function_services[index].func, sizeof(function_services[index].func), NULL))
        {
            zabbix_log(LOG_LEVEL_ERR, "Failed to extract 'func' from function object.");
            return FAIL;
        }
        index++;
    }
    *func_size = index;

    return SUCCEED;
}

/**
 * 发送 许可查询 响应
*/
int license_hander(char *cmd, zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout)
{
    int ret = FAIL;
    if (0 == strcmp(cmd, LICENSE_GET_PRODUCTKEY))
    {
       ret = send_productkey(sock, jp, config_timeout);
    }		
    else if (0 == strcmp(cmd, LICENSE_VERIFY))
    {
        ret = send_license_verify(sock, jp, config_timeout);
    }
    else if (0 == strcmp(cmd, LICENSE_QUERY))
    {
        ret = send_license_query(sock, jp, config_timeout);
    }
    return ret;
}

/*zhu adds content * 软件许可 **end*/
#endif
