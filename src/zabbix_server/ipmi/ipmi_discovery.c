#ifndef  __IPMI_DISCOVERY__C
#define  __IPMI_DISCOVERY__C

#include "ipmi_discovery.h"
#include "log.h"
#include <stddef.h>

void get_ipmi_value_by_ip(char *addr, const unsigned short port)
{
    zbx_uint64_t	itemid;
    signed char authtype = 2;      // auth类型
    unsigned char privilege = 4;   // 管理者权限
    char *username = "ADMIN";      // 用户名
    char *password = "ADMIN";      // 密码
    char *sensor = "FAN1";         // 传感器
    char *value = NULL;            // 用于存储读取到的IPMI值的变量
    int result;
    if (!IS_IPMI_INIT) 
    {
        zbx_init_ipmi_handler();
        IS_IPMI_INIT = TRUE;
    }

    result = get_ipmi_lanc_value(0, addr, port, authtype, privilege, username, password, &value);
    // result = get_value_ipmi(0, addr, port, authtype, privilege, username, password, sensor, &value);
    if (result == 0) {  // 如果函数调用成功
        zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s()Value: %s result: %d", __func__, value, result);
        free(value);  // 释放动态分配的内存
    } else {
        zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s()Failed to get IPMI value. %s result: %d", __func__, value, result);
    }
}

#endif

