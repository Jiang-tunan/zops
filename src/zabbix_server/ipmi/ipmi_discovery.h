#ifndef  __IPMI_DISCOVERY__H__
#define  __IPMI_DISCOVERY__H__


#include <stddef.h>
#include <regex.h>
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

#define STR_LINE_LEN            1024

#define FRU_DEVICE_DESCRIPTION  "FRU Device Description"//组件描述

// 主板信息
#define BOARD_MFG_DATA          "Board Mfg Date"        // 主板制造日期
#define BOARD_MFG               "Board Mfg"             // 主板制造商
#define BOARD_PRODUCT           "Board Product"         // 主板名称
#define BOARD_SERIAL            "Board Serial"          // 主板序列号
#define BOARD_PART_NUMBER       "Board Part Number"     // 主板部件号
#define BOARD_EXTRA             "Board Extra"           // 主板扩展字段

// 机箱信息
#define CHASSSIS_TYPE           "Chassis Type"          // 机箱类型
#define CHSASSIS_PART_NUMBER    "Chassis Part Number"   // 机箱部件号
#define CHASSIS_SERIAL          "Chassis Serial"        // 机箱序列号
#define CHASSIS_EXTRA           "Chassis Extra"         // 机箱扩展字段

// 组件描述字段
#define PRODUCT_MANUFACTURER    "Product Manufacturer"  // 制造商
#define PRODUCT_NAME            "Product Name"          // 产品名称
#define PRODUCT_PART_NUMBER     "Product Part Number"   // 产品部件号
#define PRODUCT_VERSION         "Product Version"       // 产品版本
#define PRODUCT_SERIAL          "Product Serial"        // 产品序列号
#define PRODUCT_ASSET_TAG       "Product Asset Tag"     // 产品资产标签
#define PRODUCT_EXTRA           "Product Extra"         // 产品扩展字段

#define MAC_ADDRESSS            "MAC Address"           // mac地址

typedef enum
{
	IPMI_VALUE_OPTION_ALL = 0,
    IPMI_VALUE_OPTION_SDRS,
    IPMI_VALUE_OPTION_FRUS,
    IPMI_VALUE_OPTION_LAN,
    IPMI_VALUE_OPTION_DISCOVERY
}
ipmitool_option;


// FRU设备类型
enum {
    FRU_UNKNOWN,            // 0 未知
    FRU_CPU,                // 1 cpu
    FRU_MEMORY,             // 2 memory
    FRU_DISK,               // 3 disk 
    FRU_NETWORK,            // 4 network
    FRU_BIOS,               // 5 bios
    FRU_PSU,                // 6 psu
    FRU_PCI_E_SLOT,         // 不好分
    FRU_BUILTIN             // 
};


typedef struct ipmi_item_info
{
    // 共有
    char *mf;
    char *name;
    char *model;
    char *serial;
    char *version;

    // 机箱
    char *chassis;
    char *chassis_serial;

    // 主板
    char *boardpart_value;
    char *board_serial_value;

    // 磁盘 内存
    char *capacity;

    // 网络
    char *port_num;
    char *netspeed;

    // 电源
    char *max_power;

}
ipmi_item_info_t;

typedef struct ipmi_product_info
{
    zbx_vector_ptr_t builtin_fru;           // 不可更换组件
    zbx_vector_ptr_t cpus;                  //cpu信息
    zbx_vector_ptr_t memory;                //内存信息
    zbx_vector_ptr_t disks;                 //磁盘信息
    zbx_vector_ptr_t networks;              //网卡信息
    zbx_vector_ptr_t bios;                  //bios信息
    zbx_vector_ptr_t psus;                  //电源信息
}
ipmi_product_info_t;

typedef struct
{
    int option;

    // 凭证
    char *addr;
    unsigned short port;
    signed char authtype;
    unsigned char privilege;
    char *username;
    char *password;

    // 值
    char *mac_address_value;
    ipmi_product_info_t *i_pro;

    char *json;
}
ipmitool_option_t;

int ipmitool_parsing_key(char *trimmed_key, char **tokens, int *token_len);
char* extract_value_after_colon(const char *original_value);
int ipmitool_control(const DC_ITEM *item, ipmitool_option_t *ioption);
int get_ipmitool_value_by_name(char* ipmitoolcmd, const char* name, ipmitool_option_t *ioption);
int get_ipmi_inventory_value(ipmitool_option_t *ioption, const char* ip,int port, const char *ipmi_username, const char *ipmi_password);
int run_ipmitool_cmd(char* cmd, ipmitool_option_t *ioption);
void create_ipmitool_value_response(ipmitool_option_t *ioption);

int parse_fru_fields(int fru_type, const char *line, ipmi_item_info_t *item);

char *extract_json_field(const char *json_str, const char *field_name);
int extract_memory_capacity(const char *str, char **capacity);
int extract_speed(const char *str, char **speed);
int extract_port_count(const char *str, char **port);

void init_ipmitool_option(ipmitool_option_t **option);
void free_ipmitool_option(ipmitool_option_t *option);

#endif /*__IPMI_DISCOVERY__H__*/
