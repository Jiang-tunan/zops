#ifndef TRAPPER_DISCOVERY_C
#define TRAPPER_DISCOVERY_C

#include "trapper_discovery.h"

zbx_vector_ptr_t global_sock_queue;
int create_queue_flag = FALSE;
static int is_initialized = 0;
int msgid = -1;
static int G_TPR_MSG_TYPE = 200;		// trapper 消息类型
static int G_DCR_MSG_TYPE = 100;		// discover 消息类型


/*********************************************************
 * FunctionName:discovery_rules_trapper_thread_init
 *
 * Decscription:
 *
 * Parameter :
 *
 * Return : 
 * 
***********************************************************/
void discovery_rules_trapper_thread_init(int server_num)
{
    pthread_t drt_thread; // 接收线程

    if (!is_initialized)
    {
        
        // 执行初始化操作
        G_TPR_MSG_TYPE = G_TPR_MSG_TYPE + server_num;
        if(-1 == (msgid =  msgget(MSG_KEY, 0666 | IPC_CREAT)))
        { 
            zabbix_log(LOG_LEVEL_WARNING, 
                "#ZOPS#%s, msgqueue creat fail! msgid=%d, errmsg=%s", 
                __func__, msgid, strerror(errno));
        }

        
        zbx_vector_ptr_create(&global_sock_queue);

        zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s()sock_queue_init, msgid=%d,recv_type=%d", __func__, msgid, G_TPR_MSG_TYPE);

        // 创建 接收response 线程
        if (0 != pthread_create(&drt_thread, NULL, discovery_rules_trapper_thread_function, NULL)) 
        {
            zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s()Failed to create read message queue thread!", __func__);
        }
        else
        {
            zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s()Successfully to create read message queue thread!", __func__);
        }

        is_initialized = 1; // 标记为已初始化
    }
}

int zops_tcp_send(zbx_socket_t *s, const char *data, size_t len, int timeout)
{

    int result = zbx_tcp_send_bytes_to(s, data, len, timeout);
    zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS# send response: socket=%d, send_result=%d, message=%s",
             s->socket, result, data);
    return result;
}

/*********************************************
 * Function_Name:discovery_rules_state
 *
 * Decscription:设备发现状态[discovery_rules_progress> <discovery_rules_activate> <discovery_rules_stop]处理
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
int discovery_rules_state(zbx_socket_t *sock, char *input_json, int config_timeout)
{
    struct json_queue send_js;
    char session_value[MAX_STRING_LEN] = ""; 

    // 从JSON中提取session值
    if (SUCCEED != extract_session_from_json(input_json, session_value)) 
    {
        zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s()Failed to extract session from JSON.", __func__);
        return FAIL;
    }
     
	zbx_socket_t *resp_sock = NULL;
    resp_sock = zbx_malloc(resp_sock, sizeof(zbx_socket_t));
	memcpy(resp_sock, sock, sizeof(zbx_socket_t));
	sock->socket = -1;   

    // 创建一个sock_queue结构的实例
    struct sock_queue *new_item = (struct sock_queue *)malloc(sizeof(struct sock_queue));
    new_item->id = msgid; 
    new_item->sock = resp_sock;
    new_item->config_timeout = config_timeout;
    zbx_strlcpy(new_item->session_value, session_value, sizeof(new_item->session_value));

    // 将该结构的实例添加到全局队列中
    zbx_vector_ptr_append(&global_sock_queue, new_item);
 
    // sock_queue_print();
    // zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#%s() Current queue size: %d", __func__, global_sock_queue.values_num);


    // 将 json 数据发送到 discoverer 处理
    send_js.type = G_DCR_MSG_TYPE;
    send_js.recv_type = G_TPR_MSG_TYPE;
    zbx_strscpy(send_js.content, input_json); 
    int send_size = sizeof(send_js.recv_type) + strlen(send_js.content) + 1;
    zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS# recv request: socket=%d, recv_type=%d, send_size=%d, msg=%s", 
            resp_sock->socket, send_js.recv_type, send_size, send_js.content);

    if (-1 == msgsnd(msgid, (void *)&send_js, send_size, IPC_NOWAIT))
    {
        zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s()Failed to send string [msgid=%d size=%d type=%d]\n%s\n'%s'",
             __func__, msgid, send_size, send_js.type, send_js.content, strerror(errno));
        // zbx_tcp_send_to(sock, sendbuf.json_buf,tz); #未创建错误 json 数据
        return FAIL;        // 发送 json 失败 返回FAIL
    }
    zbx_sleep(1);
    return SUCCEED;
}

/*********************************************************
 * FunctionName:discovery_rules_trapper_thread_function
 *
 * Decscription:
 *
 * Parameter :
 * 	@ arg
 *
 * Return : 
 * 
***********************************************************/
void* discovery_rules_trapper_thread_function(void* arg) 
{
    struct json_queue r_msg;
    char session_value[MAX_STRING_LEN];
    int count = 1, result = 0;
    while(ZBX_IS_RUNNING() && count <= 5) 
    {
        memset(session_value, 0, sizeof(session_value));

        // 接收消息队列中的消息
        if (-1 == msgrcv(msgid, &r_msg, BUFSIZ, G_TPR_MSG_TYPE, 0)) 
        {
            int old_msgid = msgid;
            zbx_sleep(count * 5);
			// 碰到过消息队列失败情况,这里增加重试机制。如果重试3次都没有创建队列，则退出线程。
			if(-1 == (msgid = msgget(MSG_KEY, 0666 | IPC_CREAT))){
				count ++;
			}else{
				count = 0;
			}
			zabbix_log(LOG_LEVEL_ERR, "#ZOPS#discovery_rules_trapper. Failed to receive message from queue,o_msgid=%d,msgid=%d",
				old_msgid, msgid);
			continue;
        }

    
        if (SUCCEED != extract_session_from_json(r_msg.content, session_value))
        {
            zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s()Failed to extract session from JSON", __func__);
            continue;
        }

        // zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s() before", __func__);
        // zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#Current queue size: %d", global_sock_queue.values_num);
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
            zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s()Session value not found in queue: %s", __func__, session_value);
            continue;
        }

        int result = zops_tcp_send(queue_item->sock, r_msg.content, strlen(r_msg.content), queue_item->config_timeout);
        // 使用找到的元素进行回复
        if (SUCCEED != result)
        {
            zabbix_log(LOG_LEVEL_ERR, "#ZOPS#%s()Failed to send response to client", __func__);
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
        zabbix_log(LOG_LEVEL_ERR, "#ZOPS#Failed to parse JSON.");
        return FAIL; // 解析失败
    }

    session_ptr = zbx_json_pair_by_name(&jp, "session");
    if (session_ptr == NULL) {
        zabbix_log(LOG_LEVEL_ERR, "#ZOPS#JSON does not contain a session key.");
        return FAIL; // 没有找到 session 键
    }

    if (FAIL == zbx_json_decodevalue(session_ptr, session, MAX_STRING_LEN - 1, NULL)) {
        zabbix_log(LOG_LEVEL_ERR, "#ZOPS#Failed to decode session value from JSON.");
        return FAIL; // 解码 session 值失败
    }

    return SUCCEED; // 成功提取 session
}

/*zhu adds content * 软件许可 */

/**
 * 发送 许可密钥 响应
*/
int send_productkey(zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout)
{
    char productkey[2 * SHA256_DIGEST_SIZE + 1];
    char session_value[MAX_STRING_LEN] = ""; 
    char resqust_value[MAX_STRING_LEN] = "";
    char *response = NULL;
    char *resqust = NULL;
    int result = FAIL;

    // 提取 resqust char resqust_value[MAX_STRING_LEN] = "";
    if (SUCCEED != zbx_json_value_by_name(jp, ZBX_PROTO_TAG_REQUEST, resqust_value, sizeof(resqust_value), NULL))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to ectract resqust value.");
        response = create_license_fail(FAIL, "Failed to ectract resqust value");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }

    // 提取 session
    if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), NULL))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to ectract session value.");
        response = create_license_fail(FAIL, "Failed to ectract session value");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }

    if (SUCCEED >= (result = create_productkey(productkey)))
    {
        zabbix_log(LOG_LEVEL_ERR, "Error creating product key. #error code=%d#", result);
        response = create_license_fail(result, "Error creating product key.");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }

    response = create_productkey_json(SUCCEED, resqust_value, session_value, productkey);

    // 发送响应
    if (SUCCEED != zops_tcp_send(sock, response, strlen(response), config_timeout))
    {
        zabbix_log(LOG_LEVEL_ERR, "The send_productkey function encountered an error while sending the JSON response.");
        zbx_free(response);
        return FAIL;
    }
	zbx_free(response);
    return SUCCEED;
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
    int result, nodes;
    long lic_expired = 0;

    // 提取 resqust 
    if (SUCCEED != zbx_json_value_by_name(jp, ZBX_PROTO_TAG_REQUEST, resqust_value, sizeof(resqust_value), NULL))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to ectract resqust value.");
        response = create_license_fail(FAIL, "Failed to ectract resqust value");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }
    // 提取 session
    if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), 	NULL))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to ectract session value.");
        response = create_license_fail(FAIL, "Failed to ectract session value");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }

    // 提取 monitor 和 function 数组
    if (FAIL == extract_monitor_and_function(jp, &nodes, monitor_services, function_services, &monitor_size, &func_size))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to extract monitor and function data.");
        response = create_license_fail(FAIL, "Failed to extract monitor and function data.");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
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
        zabbix_log(LOG_LEVEL_DEBUG, "License verification failed.#error code=%d#", result);
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
        
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }

    response = create_license_verify_json(resqust_value, session_value, monitor_services, function_services, monitor_size, func_size, lic_expired);

    // 发送响应
    if (SUCCEED != zops_tcp_send(sock, response, strlen(response), config_timeout))
    {
        zabbix_log(LOG_LEVEL_ERR, "The `send_license_verify` function encountered an error while sending the JSON response.");
        zbx_free(response);
        return FAIL;
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

    // 提取 resqust 
    if (SUCCEED != zbx_json_value_by_name(jp, ZBX_PROTO_TAG_REQUEST, resqust_value, sizeof(resqust_value), NULL))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to ectract resqust value.");
        response = create_license_fail(FAIL, "Failed to ectract resqust value");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }
    // 提取 session
    if (SUCCEED != zbx_json_value_by_name(jp, "session", session_value, sizeof(session_value), NULL))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to ectract session value.");
        response = create_license_fail(FAIL, "Failed to ectract session value");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        return FAIL;
    }

    // 调用 query_license 函数
    if (FAIL == query_license(&lic))
    {
        zabbix_log(LOG_LEVEL_ERR, "Failed to query license.");
        response = create_license_fail(FAIL, "Failed to query license.");
        zops_tcp_send(sock, response, strlen(response), config_timeout);
        zbx_free(response);
        zbx_free(lic);
        return FAIL;
    }

    response = create_license_query_json(resqust_value, session_value, lic);

    // 发送响应
    if (SUCCEED != zops_tcp_send(sock, response, strlen(response), config_timeout))
    {
        zabbix_log(LOG_LEVEL_ERR, "The `send_license_query` function encountered an error while sending the JSON response.");
        zbx_free(response);
        zbx_free(lic);
        return FAIL;
    }

    zbx_free(response);
    zbx_free(lic);
    return SUCCEED;
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

/*zhu adds content * 软件许可 **end*/
#endif
