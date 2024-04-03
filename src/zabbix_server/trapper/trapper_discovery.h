#ifndef TRAPPER_DISCOVERY_H
#define TRAPPER_DISCOVERY_H

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>
#include "zbxthreads.h"
#include "zbxcomms.h"
#include "zbxvault.h"
#include "zbxtime.h"
#include "zbxstr.h"
#include "license.h"
#include "zbxdiscovery.h"

#define FALSE     0
#define TRUE   	  1
#define MSG_KEY				(key_t)0416

#define SHA256_DIGEST_SIZE 32 

struct sock_queue
{  
	int id;								// 所属消息队列标识
	zbx_socket_t *sock; 
	int config_timeout;
	char session_value[MAX_STRING_LEN];
};

typedef struct {
	zbx_uint64_t proxyhostid;
	char *cmd;
	char *session;
	const char *request;
	zbx_socket_t *sock;
	int config_timeout;
	const zbx_config_vault_t *config_vault;
}proxy_thread_arg;

/*zhu content * 端口扫描 */
void discovery_rules_trapper_thread_init(int server_num);
void discovery_rules_trapper_thread_cleanup();
int discovery_rules_state(zbx_socket_t *sock, char *input_json, int config_timeout);
void* discovery_rules_trapper_thread_function(void* arg);
int extract_session_from_json(const char *json_str, char *session);

/*zhu content * 软件许可 */
int send_productkey(zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout);
int send_license_verify(zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout);
int send_license_query(zbx_socket_t *sock, const struct zbx_json_parse *jp, int config_timeout);

char* create_productkey_json(const int result,const char* resqust, const char* session, const char* productkey);
char* create_license_verify_json(const char* resqust, const char* session, struct service *monitor_services, struct service *function_services,
                                const short monitor_size, const short func_size, const long lic_expired);
char* create_license_query_json(const char* resqust, const char* session, struct app_license *lic);
char* create_license_fail(const int result, const char *retmsg);

int extract_monitor_and_function(const struct zbx_json_parse *jp, int *nodes, struct service *monitor_services, struct service *function_services, short *monitor_size, short *func_size);

int tognix_tcp_send(zbx_socket_t *s, const char *data, size_t len, int timeout);
#endif
