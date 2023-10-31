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

    if (!IS_IPMI_INIT) 
    {
        zbx_init_ipmi_handler();
        IS_IPMI_INIT = TRUE;
    }
    int result = get_value_ipmi(0, addr, port, authtype, privilege, username, password, sensor, &value);
    // int result = get_discovery_ipmi(itemid, addr, port, authtype, privilege, username, password, &value);

    if (result == 0) {  // 如果函数调用成功
        zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s()Value: %s result: %d", __func__, value, result);
        free(value);  // 释放动态分配的内存
    } else {
        zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s()Failed to get IPMI value. %s result: %d", __func__, value, result);
    }
}

// void log_ipmi_mac_address()
// {
//     char *addr = "192.168.30.44";
//     unsigned short port = 623;
//     signed char authtype = 2;
//     unsigned char privilege = 4;
//     char *username = "ADMIN";
//     char *password = "ADMIN";
//     zbx_ipmi_host_t *h;

//     // 初始化IPMI连接
//     if (NULL == os_hnd) {
//         zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI handler is not initialised.");
//         return;
//     }
//     h = zbx_init_ipmi_host(addr, port, authtype, privilege, username, password);
//     if (h == NULL) {
//         zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#Failed to initialize IPMI host.");
//         return;
//     }
//     if (0 == h->domain_up) {
//         zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI connection failed. Error: %s", NULL != h->err ? h->err : "Unknown error");
//         return;
//     }
//     // 获取MAC地址
//     ipmi_lan_config_t *lanc;
//     unsigned char mac_addr[6];
//     unsigned int mac_addr_len = sizeof(mac_addr);
//     ipmi_lanparm_t *lanparm; //初始化
//     int result = lanparm_config_get(ipmi_lanparm_t *lanparm, void *cb_data);
//     if (result == 0) {
//         zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
//                    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
//     } else {
//         zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#Failed to get IPMI MAC Address.");
//     }
// }


#endif
