#ifndef  __IPMI_DISCOVERY__C
#define  __IPMI_DISCOVERY__C

#include "ipmi_discovery.h"
#include "log.h"
#include <stddef.h>

// 服务器制造商不同 对应的 id 也不同
typedef struct 
{
    uint16_t builtin_fru_device_id ;

    // 惠普服务器
    uint16_t hp_bmc_controller_id;
    uint16_t hp_bios_id; 
    uint16_t hp_sas_ctrl_id;
    uint16_t hp_cpu_id[2];
    uint16_t hp_psu_id[2];
    uint16_t hp_ethernet_adptr[2];              
    // 其它服务器
}
services_fru_id_s;

services_fru_id_s services_fru_id = {
    .builtin_fru_device_id = 0,       // 不可更换组件 服务器描述 id
    .hp_bmc_controller_id = 238,      // 惠普 BMC 控制器
    .hp_bios_id = 239,                // 惠普 bios
    .hp_sas_ctrl_id = 6,              // 惠普 存储
    .hp_cpu_id = {16, 17},            // 惠普 cpu 单元
    .hp_psu_id = {144, 145},          // 惠普 电源 单元
    .hp_ethernet_adptr = {4, 5}       // 惠普 网络设备
    // 其它服务器
};


/* 解析 ipmi discovery key */
int ipmitool_parsing_key(char *trimmed_key, char **tokens, int *token_len) 
{
    if (trimmed_key == NULL || tokens == NULL || token_len == NULL || *token_len <= 0) 
        return FAIL;
    if (strncmp(trimmed_key, "discovery[", 10) == 0) 
    {
        char *start = trimmed_key + 10;

        char *end = strrchr(start, ']');
        if (end != NULL) 
            *end = '\0'; 

        int result = zbx_split(start, "|", tokens, token_len);
        return result;
    } 
    else 
    {
        // 如果 tkey 不是以 "discovery[" 开始的，返回 FAIL
        return FAIL;
    }
}

/* 根据 ioptipn->optin 对 ipmitool 进行操作 */
int ipmitool_control(const DC_ITEM *item, ipmitool_option_t *ioption)
{
    ioption->addr = strdup(item->interface.addr);
    ioption->port = item->interface.port;
    ioption->authtype = item->host.ipmi_authtype;
    ioption->privilege = item->host.ipmi_privilege;
    ioption->username = strdup(item->host.ipmi_username);
    ioption->password = strdup(item->host.ipmi_password);

    char command[MAX_STRING_LEN];

    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#IPMI %s() addr:%s port:%hu authtype:%d privilege:%d username:%s ",
                                __func__, ioption->addr, ioption->port, ioption->authtype, ioption->privilege, ioption->username);
    /* 构建 ipmitool 认证命令 */
    zbx_snprintf(command, sizeof(command), "ipmitool -I lanplus -H %s -p %u -U %s -P %s",
                                            ioption->addr, ioption->port, ioption->username, ioption->password);
    switch (ioption->option)
    {
        case IPMI_VALUE_OPTION_ALL:
        {
            
        }
        break;
        case IPMI_VALUE_OPTION_FRUS:
        {
            // 重新构建 ipmitool 命令
        }
        break;
        case IPMI_VALUE_OPTION_SDRS:
        {
            
        }
        break;
        case IPMI_VALUE_OPTION_LAN:
        {
            
        }
        break;
        case IPMI_VALUE_OPTION_DISCOVERY:
        {
            int token_len = 20; 
            char *tokens[20] = {0};
            char *trimmed_key = strdup(item->key);
            char cmd[MAX_STRING_LEN];

            if (SUCCEED != ipmitool_parsing_key(trimmed_key, tokens, &token_len)) 
            {
                // 处理失败
                zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() Failed to parse key.", __func__);
                return FAIL;
            }

            // 获取 mac 地址
            get_ipmitool_value_by_name(command, MAC_ADDRESSS, ioption);
            create_ipmitool_value_response(ioption);

            zbx_free(trimmed_key);
        }
        
            break;
        default:
            break;
    }
    return SUCCEED;
}


/* 根据名称获取值*/
int get_ipmitool_value_by_name(char* ipmitoolcmd, const char* name, ipmitool_option_t *ioption)
{
    char cmd[MAX_STRING_LEN];

    // zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#IPMI %s() name =[%s]", __func__, name);
    if(strcmp(name, CHASSSIS_TYPE) == SUCCEED)
    {
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Chassis Type\"", ipmitoolcmd);  
        FILE *fp;
        char line[STR_LINE_LEN];
        fp = popen(cmd, "r");
        if (fp == NULL)
            return FAIL;

        if(fgets(line, sizeof(line), fp) != NULL) 
            //ioption->chassis = extract_value_after_colon(line);
        
        pclose(fp);

    }
    else if(strcmp(name, CHASSIS_SERIAL) == SUCCEED)
    {
        
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Chassis Serial\"", ipmitoolcmd);
        FILE *fp;
        char line[STR_LINE_LEN];
        fp = popen(cmd, "r");
        if (fp == NULL)
            return FAIL;

        if(fgets(line, sizeof(line), fp) != NULL) 
            //ioption->chassis_serial = extract_value_after_colon(line);

        pclose(fp);
    }
    else if (strcmp(name, BOARD_PRODUCT) == SUCCEED)
    {
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Board Product\"", ipmitoolcmd);
        FILE *fp;
        char line[STR_LINE_LEN];
        fp = popen(cmd, "r");
        if (fp == NULL)
            return FAIL;

        if(fgets(line, sizeof(line), fp) != NULL)
            //ioption->boardpart_value = extract_value_after_colon(line);
        
        pclose(fp);
    }
    else if (strcmp(name, BOARD_SERIAL) == SUCCEED)
    {
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Board Serial\"", ipmitoolcmd);
        FILE *fp;
        char line[STR_LINE_LEN];
        fp = popen(cmd, "r");
        if (fp == NULL)
            return FAIL;

        if(fgets(line, sizeof(line), fp) != NULL) 
           // ioption->board_serial_value = extract_value_after_colon(line);
        pclose(fp);
    }
    else if (strcmp(name, MAC_ADDRESSS) == SUCCEED)
    {
        zbx_snprintf(cmd, sizeof(cmd), "%s lan print | grep \"MAC Address\"", ipmitoolcmd);
        
        FILE *fp;
        char line[STR_LINE_LEN];
        fp = popen(cmd, "r");
        if (fp == NULL)
            return FAIL;

        if(fgets(line, sizeof(line), fp) != NULL) 
            ioption->mac_address_value = extract_value_after_colon(line);
        
        pclose(fp);

    } 
    else 
    {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() unknow name=[%s]", __func__, name);
        return FAIL;
    }
    return SUCCEED; // 成功
}


void create_ipmitool_value_response(ipmitool_option_t *ioption)
{
    struct zbx_json j;
    // 初始化 JSON 对象
    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);

    //凭证
    zbx_json_addstring(&j, "ipmi_username", ioption->username, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "ipmi_password", ioption->password, ZBX_JSON_TYPE_STRING);
    zbx_json_addint64(&j, "ipmi_privilege", ioption->privilege);
    zbx_json_addint64(&j, "ipmi_authtype", ioption->authtype);
    zbx_json_addstring(&j, ZBX_DSERVICE_KEY_IFPHYSADDRESS, ioption->mac_address_value, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, ZBX_DSERVICE_KEY_SYSNAME, ioption->addr, ZBX_JSON_TYPE_STRING);

    // 系统硬件信息
    if(ioption->i_pro->builtin_fru.values_num > 0)
    {
        ipmi_item_info_t *builtin = (ipmi_item_info_t *)ioption->i_pro->builtin_fru.values[0];
        // 机箱信息
        zbx_json_addstring(&j, "chassis", builtin->chassis, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "chassis_serial", builtin->chassis_serial, ZBX_JSON_TYPE_STRING);

        // 主板信息
        zbx_json_addstring(&j, "board", builtin->boardpart_value, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "board_serial", builtin->board_serial_value, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, ZBX_DSERVICE_KEY_SYSDESC, builtin->mf, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM, builtin->serial, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME, builtin->model, ZBX_JSON_TYPE_STRING);
    }

    // 封装CPU信息
    if (ioption->i_pro->cpus.values_num > 0)
    {
        ipmi_item_info_t *cpu = (ipmi_item_info_t *)ioption->i_pro->cpus.values[0];
        zbx_json_addobject(&j, "cpu");
        zbx_json_addint64(&j, "cpu_num", ioption->i_pro->cpus.values_num);
        zbx_json_addstring(&j, "mf", cpu->mf, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "name", cpu->name, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&j);
    }

    // 封装内存信息
    if (ioption->i_pro->memory.values_num > 0)
    {
        int ret;
        zbx_json_addobject(&j, "memory");

        zbx_json_addstring(&j, "capacity", "", ZBX_JSON_TYPE_STRING);
        zbx_json_addarray(&j, "memory");

        for (int i = 0; i < ioption->i_pro->memory.values_num; i++)
        {
            ipmi_item_info_t *memory = (ipmi_item_info_t *)ioption->i_pro->memory.values[i];

            if(NULL == memory->serial) continue;
            if(NULL != memory->model)
                ret = extract_memory_capacity(memory->model, &memory->capacity);

            struct zbx_json j_memory;
            zbx_json_init(&j_memory, ZBX_JSON_STAT_BUF_LEN);
            zbx_json_addstring(&j_memory, "mf", memory->mf, ZBX_JSON_TYPE_STRING);
            zbx_json_addstring(&j_memory, "model", memory->model, ZBX_JSON_TYPE_STRING);
            zbx_json_addstring(&j_memory, "serial", memory->serial, ZBX_JSON_TYPE_STRING);
            zbx_json_addstring(&j_memory, "capacity", memory->capacity, ZBX_JSON_TYPE_STRING);
            zbx_json_addraw(&j, NULL, j_memory.buffer);
            zbx_json_free(&j_memory);
        }
        zbx_json_close(&j);
        zbx_json_close(&j);
    }

    // 封装磁盘信息
    if (ioption->i_pro->disks.values_num > 0)
    {
        zbx_json_addobject(&j, "disk");

        zbx_json_addstring(&j, "capacity", "", ZBX_JSON_TYPE_STRING);
        zbx_json_addarray(&j, "disk");
        for (int i = 0; i < ioption->i_pro->disks.values_num; i++)
        {
            ipmi_item_info_t *disk = (ipmi_item_info_t *)ioption->i_pro->disks.values[i];
            struct zbx_json j_disk;
            zbx_json_init(&j_disk, ZBX_JSON_STAT_BUF_LEN);
            zbx_json_addstring(&j_disk, "name", disk->name, ZBX_JSON_TYPE_STRING);
            zbx_json_addstring(&j_disk, "model", disk->model, ZBX_JSON_TYPE_STRING);
            zbx_json_addstring(&j_disk, "serial", disk->serial, ZBX_JSON_TYPE_STRING);
            zbx_json_addstring(&j_disk, "capacity", disk->capacity, ZBX_JSON_TYPE_STRING);
            zbx_json_addraw(&j, NULL, j_disk.buffer);
            zbx_json_free(&j_disk);
        }
        zbx_json_close(&j);
        zbx_json_close(&j);
    }

    // 封装网络信息
    if (ioption->i_pro->networks.values_num > 0)
    {
        char *port_num_str = NULL;
        int port_num = 0;
        int ethernet_num = 0;
        zbx_json_addobject(&j, "network");
        zbx_json_addstring(&j, "port_num", "", ZBX_JSON_TYPE_STRING);
        zbx_json_addint64(&j, "ethernet_num", ioption->i_pro->networks.values_num);
        zbx_json_addarray(&j, "ethernet");
        for (int i = 0; i < ioption->i_pro->networks.values_num; i++)
        {
            int ret;
            ipmi_item_info_t *network = (ipmi_item_info_t *)ioption->i_pro->networks.values[i];

            if(SUCCEED  == strcmp(network->name, "Empty"))  continue;

            if(NULL != network->name)
            {
                ret = extract_speed(network->name, &network->netspeed);
                ret = extract_port_count(network->name, &network->port_num);
            }

            struct zbx_json j_network;
            zbx_json_init(&j_network, ZBX_JSON_STAT_BUF_LEN);
            zbx_json_addstring(&j_network, "name", network->name, ZBX_JSON_TYPE_STRING);
            zbx_json_addstring(&j_network, "netspeed", network->netspeed, ZBX_JSON_TYPE_STRING);
            zbx_json_addraw(&j, NULL, j_network.buffer);
            zbx_json_free(&j_network);
        }
        zbx_json_close(&j);
        zbx_json_close(&j);
    }

    // 封装 bios 信息
    if (ioption->i_pro->bios.values_num > 0)
    {
        ipmi_item_info_t *bios = (ipmi_item_info_t *)ioption->i_pro->bios.values[0];
        zbx_json_addobject(&j, "bios");
        zbx_json_addstring(&j, "mf", bios->mf, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "model", bios->name, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "version", bios->version, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&j);
    }
 
    // 封装 电源 信息
    if (ioption->i_pro->psus.values_num > 0)
    {
        ipmi_item_info_t *psu = (ipmi_item_info_t *)ioption->i_pro->psus.values[0];
        zbx_json_addobject(&j, "psu");
        zbx_json_addint64(&j, "psu_num", ioption->i_pro->psus.values_num);
        zbx_json_addstring(&j, "mf", psu->mf, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "model", psu->name, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "version", psu->version, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "serial", psu->serial, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "max_power", psu->max_power, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&j);
    }
    size_t buffer_size = strlen(j.buffer) + 3;
    char *formatted_json = (char *)malloc(buffer_size);
    if (formatted_json != NULL)
    {
        zbx_snprintf(formatted_json, buffer_size, "[%s]", j.buffer);
        ioption->json = strdup(formatted_json);
        free(formatted_json);
    }
    zbx_json_free(&j);
}

char* extract_value_after_colon(const char *original_value) {
    if (original_value == NULL) {
        return NULL;
    }

    const char *value_with_colon = strchr(original_value, ':');
    if (value_with_colon == NULL) {
        return NULL;
    }

    value_with_colon++;
    while (isspace((unsigned char)*value_with_colon)) {
        value_with_colon++;
    }

    const char *end = value_with_colon + strlen(value_with_colon);
    while (end > value_with_colon && isspace((unsigned char)*(end - 1))) {
        end--;
    }
    size_t length = end - value_with_colon;

    char *trimmed_value = malloc(length + 1);
    if (trimmed_value == NULL) {
        return NULL;
    }

    memcpy(trimmed_value, value_with_colon, length);
    trimmed_value[length] = '\0';

    return trimmed_value;
}

void bind_template_to_host(uint64_t hostid)
{
    DB_RESULT result;
    DB_ROW row;
    char sql[MAX_STRING_LEN];
    uint64_t template_hostid = 0;
    uint64_t max_hosttemplateid = 0;
    uint64_t max_hostgroupid = 0;
    int status;
    zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() hostid=%d",__func__, hostid);
    // 查询 "Chassis by IPMI" 的 hostid 和 status
    zbx_snprintf(sql, sizeof(sql), "SELECT hostid, status FROM hosts WHERE host='Chassis by IPMI'");
    result = zbx_db_select(sql);
    if (NULL != (row = zbx_db_fetch(result)))
    {
        ZBX_STR2UINT64(template_hostid, row[0]);
        status = atoi(row[1]);

        if (3 != status)
        {
            zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s()Template 'Chassis by IPMI' is not in the correct status",__func__);
            zbx_db_free_result(result);
            return;
        }
    }
    zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() status=%d template_hostid= %d",__func__, status, template_hostid);
    zbx_db_free_result(result);

    if (0 == template_hostid)
    {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s()Template 'Chassis by IPMI' not found",__func__);
        return;
    }

    // 检查 hosts_templates 表
    zbx_snprintf(sql, sizeof(sql), "SELECT 1 FROM hosts_templates WHERE hostid=" ZBX_FS_UI64, hostid);
    result = zbx_db_select(sql);
    if (NULL != (row = zbx_db_fetch(result)))
    {
        // 更新
        zbx_snprintf(sql, sizeof(sql), "UPDATE hosts_templates SET templateid=" ZBX_FS_UI64 " WHERE hostid=" ZBX_FS_UI64, template_hostid, hostid);
    }
    else
    {
        // 插入
        max_hosttemplateid = zbx_db_get_maxid("hosts_templates");
        zbx_snprintf(sql, sizeof(sql), "INSERT INTO hosts_templates (hosttemplateid, hostid, templateid) VALUES (" ZBX_FS_UI64 "," ZBX_FS_UI64 "," ZBX_FS_UI64 ")", max_hosttemplateid, hostid, template_hostid);
    }
    zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() max_hosttemplateid = %d",__func__, max_hosttemplateid);
    zbx_db_free_result(result);
    zbx_db_execute(sql);

    // 检查 hosts_groups 表
    zbx_snprintf(sql, sizeof(sql), "SELECT 1 FROM hosts_groups WHERE hostid=" ZBX_FS_UI64, hostid);
    result = zbx_db_select(sql);
    if (NULL != (row = zbx_db_fetch(result)))
    {
        // 更新
        zbx_snprintf(sql, sizeof(sql), "UPDATE hosts_groups SET groupid=3 WHERE hostid=" ZBX_FS_UI64, hostid);
    }
    else
    {
        // 插入
        max_hostgroupid = zbx_db_get_maxid("hosts_groups");
        zbx_snprintf(sql, sizeof(sql), "INSERT INTO hosts_groups (hostgroupid, hostid, groupid) VALUES (" ZBX_FS_UI64 ", " ZBX_FS_UI64 ", 3)", max_hostgroupid, hostid);
    }
    zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() max_hostgroupid = %d",__func__, max_hostgroupid);
    zbx_db_free_result(result);
    zbx_db_execute(sql);
}


void process_fru_description(char *description) {
    // 使用正则表达式匹配大类，例如：CPU, BIOS, MEMORY等
  
}

int parse_fru_fields(int fru_type, const char *line, ipmi_item_info_t *item) 
{
    if (line == NULL || item == NULL) 
    {
        return FAIL; // 或者其他错误代码
    }
     switch (fru_type) 
    {
        case FRU_CPU:
            if(zbx_strncasecmp(line,PRODUCT_MANUFACTURER,strlen(PRODUCT_MANUFACTURER)) == 0)
                item->mf = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_NAME,strlen(PRODUCT_NAME)) == 0)
                item->name = extract_value_after_colon(line);

            break;
        case FRU_MEMORY:
            if(zbx_strncasecmp(line, PRODUCT_MANUFACTURER, strlen(PRODUCT_MANUFACTURER)) == 0)
                item->mf = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_NAME,strlen(PRODUCT_NAME)) == 0)
                item->model = extract_value_after_colon(line);
            
            else if(zbx_strncasecmp(line,PRODUCT_SERIAL,strlen(PRODUCT_SERIAL)) == 0)
                item->serial = extract_value_after_colon(line);

            break;
        case FRU_DISK:

            if(zbx_strncasecmp(line,PRODUCT_NAME,strlen(PRODUCT_NAME)) == 0)
                item->name = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_PART_NUMBER,strlen(PRODUCT_PART_NUMBER)) == 0)
                item->model = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_SERIAL,strlen(PRODUCT_SERIAL)) == 0)
                item->serial = extract_value_after_colon(line);

            break;
        case FRU_NETWORK:
            if(zbx_strncasecmp(line,PRODUCT_NAME,strlen(PRODUCT_NAME)) == 0)
                item->name = extract_value_after_colon(line);

            break;
        case FRU_BIOS:
            if(zbx_strncasecmp(line,PRODUCT_MANUFACTURER,strlen(PRODUCT_MANUFACTURER)) == 0)
                item->mf = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_PART_NUMBER,strlen(PRODUCT_PART_NUMBER)) == 0)
                item->model = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_VERSION,strlen(PRODUCT_VERSION)) == 0)
                item->version = extract_value_after_colon(line);

            break;
        case FRU_PSU:
            if(zbx_strncasecmp(line,PRODUCT_MANUFACTURER,strlen(PRODUCT_MANUFACTURER)) == 0)
                item->mf = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_PART_NUMBER,strlen(PRODUCT_PART_NUMBER)) == 0)
                item->model = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_VERSION,strlen(PRODUCT_VERSION)) == 0)
                item->version = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_EXTRA,strlen(PRODUCT_EXTRA)) == 0)
                item->max_power = extract_value_after_colon(line);

            break;
        case FRU_BUILTIN:
            if(zbx_strncasecmp(line,PRODUCT_MANUFACTURER,strlen(PRODUCT_MANUFACTURER)) == 0)
                item->mf = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_PART_NUMBER,strlen(PRODUCT_PART_NUMBER)) == 0)
                item->model = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,PRODUCT_SERIAL,strlen(PRODUCT_SERIAL)) == 0)
                item->serial = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,CHASSSIS_TYPE,strlen(CHASSSIS_TYPE)) == 0)
                item->chassis = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,CHASSIS_SERIAL,strlen(CHASSIS_SERIAL)) == 0)
                item->chassis_serial = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,BOARD_PRODUCT,strlen(BOARD_PRODUCT)) == 0)
                item->boardpart_value = extract_value_after_colon(line);

            else if(zbx_strncasecmp(line,BOARD_SERIAL,strlen(BOARD_SERIAL)) == 0)
                item->board_serial_value = extract_value_after_colon(line);

            break;
        default:
            zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s()  unknow frutype=%d",__func__, fru_type);
            break;
    }
    return SUCCEED;
}

// 执行 ipmitool 命令

int run_ipmitool_cmd(char* cmd, ipmitool_option_t *ioption) 
{
    FILE *fp;
    char line[STR_LINE_LEN];
    int fru_type = FRU_UNKNOWN; // 当前FRU设备类型
    ipmi_item_info_t *item = NULL;
    int ret = SUCCEED;

    // 打开命令流
    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() ipmitool run failed", __func__);
        return FAIL;
    }

    while (1) 
    {
        if (fgets(line, sizeof(line), fp) == NULL)
        {
            // 检查是否到达文件结束或发生错误
            if (feof(fp))
            {
                zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() fgets reached EOF", __func__);
            }
            else if (ferror(fp))
            {
                zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() fgets error", __func__);
                ret = FAIL;
            }
            break; // 跳出循环
        }

        // 去除开头的空格
        char *start = line;
        while (*start != '\0' && isspace((unsigned char)*start)) 
            start++;

        // 如果去除空格后的行为空，则不处理
        if (*start == '\0') 
            continue;

        if (strstr(start, FRU_DEVICE_DESCRIPTION) != NULL) 
        {
            // 处理之前的item
            if (item != NULL) 
            {
                switch (fru_type) 
                {
                    case FRU_CPU:
                        zbx_vector_ptr_append(&ioption->i_pro->cpus, item);
                        break;
                    case FRU_MEMORY:
                        zbx_vector_ptr_append(&ioption->i_pro->memory, item);
                        break;
                    case FRU_DISK:
                        zbx_vector_ptr_append(&ioption->i_pro->disks, item);
                        break;
                    case FRU_NETWORK:
                        zbx_vector_ptr_append(&ioption->i_pro->networks, item);
                        break;
                    case FRU_BIOS:
                        zbx_vector_ptr_append(&ioption->i_pro->bios, item);
                        break;
                    case FRU_PSU:
                        zbx_vector_ptr_append(&ioption->i_pro->psus, item);
                    case FRU_BUILTIN:
                        zbx_vector_ptr_append(&ioption->i_pro->builtin_fru, item);
                        break;
                    default:
                        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s()  unknow frutype=%d",__func__, fru_type);
                        break;
                }
            }

            // 重置item和确定新的fru_type
            item = (ipmi_item_info_t *)zbx_malloc(NULL, sizeof(ipmi_item_info_t));
            memset(item, 0, sizeof(ipmi_item_info_t));

            if (strstr(start, "CPU") != NULL) 
                fru_type = FRU_CPU;
            else if(strstr(start, "PCI-E"))
                fru_type = FRU_MEMORY;
            else if(strstr(start, "SAS"))
                fru_type = FRU_DISK;
            else if(strstr(start, "Ethernet"))
                fru_type = FRU_NETWORK;
            else if(strstr(start, "BIOS"))
                fru_type = FRU_BIOS;
            else if(strstr(start, "PSU"))
                fru_type = FRU_PSU;
            else if(strstr(start, "Builtin FRU Device"))
                fru_type =  FRU_BUILTIN;
            else 
                fru_type = FRU_UNKNOWN;

        } 
        else if (item != NULL) 
        {
            // 填充数据到item
            parse_fru_fields(fru_type, start, item);
        }
    }

    // 处理最后一个item
    if (item != NULL) 
    {
        switch (fru_type) 
        {
            case FRU_CPU:
                zbx_vector_ptr_append(&ioption->i_pro->cpus, item);
                break;
            case FRU_MEMORY:
                zbx_vector_ptr_append(&ioption->i_pro->memory, item);
                break;
            case FRU_DISK:
                zbx_vector_ptr_append(&ioption->i_pro->disks, item);
                break;
            case FRU_NETWORK:
                zbx_vector_ptr_append(&ioption->i_pro->networks, item);
                break;
            case FRU_BIOS:
                zbx_vector_ptr_append(&ioption->i_pro->bios, item);
                break;
            case FRU_PSU:
                zbx_vector_ptr_append(&ioption->i_pro->psus, item);
                break;
            case FRU_BUILTIN:
                zbx_vector_ptr_append(&ioption->i_pro->builtin_fru, item);
                break;
            default:
                zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s()  unknow frutype=%d",__func__, fru_type);
                break;
        }
    }

    pclose(fp);
    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#IPMI end of %s()", __func__);
    return ret;
}


void init_ipmitool_option(ipmitool_option_t **option) {
    if (option == NULL) {
        return;
    }
    *option = (ipmitool_option_t *)zbx_malloc(NULL, sizeof(ipmitool_option_t));
    if (*option == NULL) {
        return; 
    }
    memset(*option, 0, sizeof(ipmitool_option_t));
    
    (*option)->i_pro = (ipmi_product_info_t *)zbx_malloc(NULL, sizeof(ipmi_product_info_t));
    if ((*option)->i_pro == NULL) {
        zbx_free(*option);
        return;
    }
    memset((*option)->i_pro, 0, sizeof(ipmi_product_info_t));

    // 初始化向量
    zbx_vector_ptr_create(&(*option)->i_pro->builtin_fru);
    zbx_vector_ptr_create(&(*option)->i_pro->cpus);
    zbx_vector_ptr_create(&(*option)->i_pro->disks);
    zbx_vector_ptr_create(&(*option)->i_pro->memory);
    zbx_vector_ptr_create(&(*option)->i_pro->networks);
    zbx_vector_ptr_create(&(*option)->i_pro->bios);
    zbx_vector_ptr_create(&(*option)->i_pro->psus);
}


void free_ipmitool_option(ipmitool_option_t *option) {
    if (option == NULL) {
        return;
    }

    if (option->i_pro != NULL) 
    {
        zbx_vector_ptr_destroy(&option->i_pro->builtin_fru);
        zbx_vector_ptr_destroy(&option->i_pro->bios);
        zbx_vector_ptr_destroy(&option->i_pro->cpus);
        zbx_vector_ptr_destroy(&option->i_pro->disks);
        zbx_vector_ptr_destroy(&option->i_pro->memory);
        zbx_vector_ptr_destroy(&option->i_pro->networks);
        zbx_vector_ptr_destroy(&option->i_pro->psus);

        zbx_free(option->i_pro);
    }

    // 释放其他可能分配的字段
    zbx_free(option->addr);
    zbx_free(option->username);
    zbx_free(option->password);
    zbx_free(option->mac_address_value);
    zbx_free(option->json);

    zbx_free(option);
}


char *extract_json_field(const char *json_str, const char *field_name) 
{
    struct zbx_json_parse jp, jp_data;
    char *extracted_json_str = NULL;
    int len;

    // 去掉开头的 '[' 和结尾的 ']'
    char *trimmed_json_str = strdup(json_str);
    if (trimmed_json_str[0] == '[') {
        trimmed_json_str++; 
    }
    int trimmed_json_str_len = strlen(trimmed_json_str);
    if (trimmed_json_str[trimmed_json_str_len - 1] == ']') {
        trimmed_json_str[trimmed_json_str_len - 1] = '\0'; 
    }

    if (SUCCEED != zbx_json_open(trimmed_json_str, &jp)) {
        zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#IPMI %s() Unable to parse JSON", __func__);
        trimmed_json_str--;
        zbx_free(trimmed_json_str);
        return NULL;
    }

    if (SUCCEED == zbx_json_brackets_by_name(&jp, field_name, &jp_data)) 
    {
        // 计算需要的字符串长度，包括结束的大括号
        len = jp_data.end - jp_data.start + 2; // 加 2 包括大括号和 null 结尾

        extracted_json_str = zbx_malloc(NULL, len + 1);
        if (extracted_json_str != NULL) {
            zbx_strlcpy(extracted_json_str, jp_data.start, len);
            extracted_json_str[len] = '\0'; // 确保字符串以 null 结尾
        }
    } else {
        zabbix_log(LOG_LEVEL_WARNING, "#TOGNIX#IPMI %s() '%s' not found", __func__, field_name);
    }

    trimmed_json_str--;
    zbx_free(trimmed_json_str); 
    return extracted_json_str; // 这里返回的字符串需要在外部释放
}

void update_ipmi_hostmacro(int hostid, char *ipmi_user, char *ipmi_password)
{
    DB_RESULT   result;
    DB_ROW      row;
    int password_id = 0, user_id = 0, sensor_matches_id = 0, sensor_not_matches_id = 0;


    zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#IPMI#%s() hostid:%d", __func__, hostid);

    // 查询数据库以获取宏的当前ID
    result = zbx_db_select("SELECT hostmacroid, macro FROM hostmacro WHERE hostid=" ZBX_FS_UI64, hostid);

    while (NULL != (row = zbx_db_fetch(result)))
    {
        char *macro = row[1]; // 
        if (0 == strcmp(macro, "{$IPMI.PASSWORD}"))
            password_id = zbx_atoi(row[0]); // 第一列是宏ID
        else if (0 == strcmp(macro, "{$IPMI.USER}"))
            user_id = zbx_atoi(row[0]);
        else if (0 == strcmp(macro, "{$IPMI.SENSOR_TYPE.MATCHES}"))
            sensor_matches_id = zbx_atoi(row[0]);
        else if (0 == strcmp(macro, "{$IPMI.SENSOR_TYPE.NOT_MATCHES}"))
            sensor_not_matches_id = zbx_atoi(row[0]);
    }
    zbx_db_free_result(result);

    // 更新宏数据
    update_hostmacro_data(password_id, hostid, "{$IPMI.PASSWORD}", ipmi_password, "");
    update_hostmacro_data(user_id, hostid, "{$IPMI.USER}", ipmi_user, "");
    update_hostmacro_data(sensor_matches_id, hostid, "{$IPMI.SENSOR_TYPE.MATCHES}", ".*", "");
    update_hostmacro_data(sensor_not_matches_id, hostid, "{$IPMI.SENSOR_TYPE.NOT_MATCHES}", "invalid", "");


    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}

int extract_memory_capacity(const char *str, char **capacity) 
{
    regex_t regex;
    regmatch_t match;
    size_t alloc_len = 0, offset = 0;  // 初始化内存分配长度和偏移量

    if (SUCCEED != regcomp(&regex, "\\b([0-9]+G)\\b", REG_EXTENDED)) 
    {
        zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#IPMI %s()Could not compile regex",__func__);
        regfree(&regex);
        return FAIL;
    }

    if (SUCCEED == regexec(&regex, str, 1, &match, 0)) 
    {
        char *temp_str = strndup(str + match.rm_so, match.rm_eo - match.rm_so);
        if (temp_str == NULL) 
        {
            regfree(&regex);
            return FAIL;
        }
        zbx_strcpy_alloc(capacity, &alloc_len, &offset, temp_str);
        free(temp_str);
    } 
    else 
    {
        zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#IPMI %s()Not found memory capacity",__func__);
        regfree(&regex);
        return FAIL;
    }

    regfree(&regex);
    zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#IPMI %s()end",__func__);
    return SUCCEED;
}


int extract_speed(const char *str, char **speed) 
{
    regex_t regex;
    regmatch_t match;
    size_t alloc_len = 0, offset = 0;
    if (regcomp(&regex, "\\b([0-9]+Gb)\\b", REG_EXTENDED) != 0) 
    {
        zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#IPMI %s()Could not compile regex",__func__);
        regfree(&regex);
        return FAIL;
    }

    if (SUCCEED == regexec(&regex, str, 1, &match, 0)) 
    {
        char *temp_str = strndup(str + match.rm_so,  match.rm_eo - match.rm_so);
        if (temp_str == NULL) 
        {
            regfree(&regex);
            return FAIL;
        }
        zbx_strcpy_alloc(speed, &alloc_len, &offset, temp_str);
        free(temp_str);
    } 
    else 
    {
        zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#IPMI %s()Not found memory",__func__);
        regfree(&regex);
        return FAIL;
    }
    regfree(&regex);
}

int extract_port_count(const char *str, char **port) 
{
    regex_t regex;
    regmatch_t match;
    size_t alloc_len = 0, offset = 0;

    if (SUCCEED != regcomp(&regex, "\\b([0-9]+)-port\\b", REG_EXTENDED)) 
    {
        zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#IPMI %s()Could not compile regex",__func__);
        regfree(&regex);
        return FAIL;
    }

    if (SUCCEED == regexec(&regex, str, 1, &match, 0)) 
    {
        char *temp_str = strndup(str + match.rm_so,  match.rm_eo - match.rm_so);
        if (temp_str == NULL) 
        {
            regfree(&regex);
            return FAIL;
        }
        zbx_strcpy_alloc(port, &alloc_len, &offset, temp_str);
        free(temp_str);
    } 
    else 
    {
        zabbix_log(LOG_LEVEL_DEBUG,"#TOGNIX#IPMI %s()Not found port",__func__);
        regfree(&regex);
        return FAIL;
    }
    regfree(&regex);
}


int get_ipmi_inventory_value(ipmitool_option_t *ioption, const char* ip,int port, const char *ipmi_username, const char *ipmi_password)
{
    const int max_retries = 3; // 设置最大重试次数
    int retries = 0;
    int result;
    char command[MAX_STRING_LEN];

    zbx_snprintf(command, sizeof(command), "ipmitool -I lanplus -H %s -p %u -U %s -P %s fru",
                                            ip, port, ipmi_username, ipmi_password);
    // 增加重试机制
    while (retries < max_retries)
    {
        result = run_ipmitool_cmd(command, ioption);
        if (result == SUCCEED) 
        {
            break; 
        }

        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() run_ipmitool_cmd failed, retry %d", __func__, retries + 1);
        retries++;
    }

    if (result != SUCCEED)
    {
        zabbix_log(LOG_LEVEL_ERR, "#TOGNIX#IPMI %s() run_ipmitool_cmd failed after retries", __func__);
        return FAIL;
    }
    create_ipmitool_value_response(ioption);
    return SUCCEED;
}
#endif
