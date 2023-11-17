#ifndef  __IPMI_DISCOVERY__H__
#define  __IPMI_DISCOVERY__H__


#include <stddef.h>
#include "ipmi_poller.h"
#include "ipmi_manager.h"
#include "zbxcommon.h"
#include "log.h"

#include "zbxnix.h"   
#include "zbxself.h"
#include "zbxipcservice.h"
#include "ipmi_protocol.h"
#include "checks_ipmi.h"
#include "zbxtime.h"
#include "zbxcacheconfig.h"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

/*option*/
#define IPMI_VALUE_OPTION_ALL		1  /*获取所有值*/
#define IPMI_VALUE_OPTION_SDRS		2   // 传感器
#define IPMI_VALUE_OPTION_FRUS		3   // 设备类型 序列号
#define IPMI_VALUE_OPTION_LAN		4   // 网络配置
#define IPMI_VALUE_OPTION_DISCOVERY	5   // 扫描
// 资产扫描定义
/*ipmi_name*/
#define PRODUCT_MANUFACTURER    "Product Manufacturer"  // 制造商
#define PRODUCT_PART_NUMBER     "Product Part Number"   // 主机型号
#define PRODUCT_SERIAL          "Product Serial"        // 主机序列号
#define BOARD_PART_NUMBER       "Board Part Number"     // 主板型号
#define BOARE_SERIAL            "Board Serial"          // 主板序列号
#define MAC_ADDRESSS            "MAC Address"           // mac地址
#define 
typedef enum
{
	MAC_ADDER = 0,

}
ipmitool_values_option_t;

typedef struct
{
    int option;
    char *addr;
    unsigned short port;
    signed char authtype;
    unsigned char privilege;
    char *username;
    char *password;
    char *value;
    char *product_manu_value;
    char *productpart_value;
    char *product_serial_value;
    char *boardpart_value;
    char *board_serial_value;
    char *mac_address_value;
    char *user_text;
    
    char *json;
    int value_num;
}
ipmitool_option_t;

int ipmitool_parsing_key(char *trimmed_key, char **tokens, int *token_len);
void extract_value_after_colon(char *original_value);
int ipmitool_control(const DC_ITEM *item, ipmitool_option_t *ioption);
int get_ipmitool_discovery_value(char *command, char **tokens, int token_len, ipmitool_option_t *ioption);
int get_ipmitool_value_by_name(char* ipmitoolcmd, const char* name, ipmitool_option_t *ioption);
int run_ipmitool_cmd(char* cmd, char **output);
void create_ipmitool_value_response(ipmitool_option_t *ioption);
#endif /*__IPMI_DISCOVERY__H__*/
