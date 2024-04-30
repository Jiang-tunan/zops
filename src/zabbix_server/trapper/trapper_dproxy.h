#ifndef TRAPPER_DPROXY_H
#define TRAPPER_DPROXY_H

#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <pthread.h>

#include "zbxversion.h"
#include "zbxvault.h"
#include "zbxtime.h"
#include "zbxthreads.h"
#include "zbxstr.h"
#include "zbxserver.h"
#include "zbxself.h"
#include "zbxrtc.h"
#include "zbxnum.h"
#include "zbxnix.h"
#include "zbxip.h"
#include "zbxdbwrap.h"
#include "zbxdbhigh.h"
#include "zbxcrypto.h"
#include "zbxcompress.h"
#include "zbxcommshigh.h" 
#include "zbxcomms.h"
#include "zbx_rtc_constants.h"
#include "zbx_host_constants.h"
#include "trapper_request.h"
#include "trapper_discovery.h"

#include "log.h"
#include "license.h"

#include "../trapper/proxydata.h"
#include "../proxyconfigread/proxyconfig_read.h"
#include "../discoverer/user_discoverer.h"
#include "../discoverer/discoverer_comm.h"
#include "../../libs/zbxcacheconfig/dbconfig.h"

#define MAX_SEND_PROXY_DATA_TIMES       3   // 发送代理数据重试次数

#define MAX_SEND_PROXY_SLEEP_TIME       3   // 重试间隔时间

int	dc_proxy_send_configuration(ZBX_DC_PROXY *proxy, const zbx_config_vault_t *config_vault, int isfullsync);
int	dc_get_data_from_proxy(ZBX_DC_PROXY *proxy, const char *request, int config_timeout, 
		char **data, zbx_timespec_t *ts);
int discovery_rules_proxy(char *cmd, char *session, int proxyhostid, zbx_socket_t *sock, const char *request, 
    int config_timeout, zbx_ipc_async_socket_t *rtc);
#endif
