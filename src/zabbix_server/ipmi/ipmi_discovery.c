#ifndef  __IPMI_DISCOVERY__C
#define  __IPMI_DISCOVERY__C

#include "ipmi_discovery.h"
#include "log.h"
#include <stddef.h>
// int IS_IPMI_INIT = FALSE;

/* 解析 ipmi discovery key */
int ipmitool_parsing_key(char *trimmed_key, char **tokens, int *token_len) 
{
    if (trimmed_key == NULL || tokens == NULL || token_len == NULL || *token_len <= 0) 
        return FAIL;

    // 检查并剔除开头的 "discovery[" 和结尾的"]"
    if (strncmp(trimmed_key, "discovery[", 10) == 0) 
    {
        char *start = trimmed_key + 10;

        char *end = strrchr(start, ']');
        if (end != NULL) 
            *end = '\0';  // 替换 ']' 为字符串结束符 '\0'

        // 分割处理过的字符串
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

    zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s() addr:%s port:%hu authtype:%d privilege:%d username:%s password:%s",
                                __func__, ioption->addr, ioption->port, ioption->authtype, ioption->privilege, ioption->username, ioption->password);
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
            // 重新构建 ipmitool 命令 在原本命令后面添加 "fru print"

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
            if (SUCCEED != ipmitool_parsing_key(trimmed_key, tokens, &token_len)) 
            {
                // 处理失败
                return FAIL;

            }
            zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s() token_len[%d]", __func__, token_len);

            get_ipmitool_discovery_value(command, tokens, token_len, ioption);
            // zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s() product_manu_value=[%s]", __func__, ioption->product_manu_value);

            zbx_free(trimmed_key);
        }
            break;
        default:
            break;
    }
    return SUCCEED;
}

// 创建返回报文为插入host表做准备 
// {#SYSNAME} 主机名 
// {#SYSDESC} 设备描述 制造商 型号 版本 Product Part Number<nx-1050> Product Manufacturer<制造商>
// {#ENTPHYSICALSERIALNUM} 网络设备序列号  Chassis Serial<机箱序列号> Board Serial<主板序列号> Product Serial<产品序列号>
// {#IFPHYSADDRESS} mac  MAC Address 
// {#ENTPHYSICALMODELNAME} 实体型号名称  
//  ipmi扫描逻辑,key的数据格式为"discovery[{#SYSNAME}| null |{#SYSDESC}| ProductManufacturer.ProductPartNumber|{#IFPHYSADDRESS}|MACAddress"
// discovery[{#SYSNAME}|null|{#SYSDESC}|Product Manufacturer|{#ENTPHYSICALSERIALNUM}|Board Serial.Product Serial|{#IFPHYSADDRESS}|MAC Address|{#ENTPHYSICALMODELNAME}|Product Part Number]
int get_ipmitool_discovery_value(char *command, char **tokens, int token_len, ipmitool_option_t *ioption)
{
    // 循环解析
    for(int i = 0; i < token_len; i += 2)
    {
        int ipmi_name_num = 10;
        char *ipmi_name[10] = {0};
        if (SUCCEED == strcmp(ZBX_DSERVICE_KEY_SYSNAME, tokens[i]))
        {
            // 主机名 
            zbx_split(tokens[i+1], ".", ipmi_name, &ipmi_name_num);
            for(int j = 0; j < ipmi_name_num; j++)
            {
                if(SUCCEED != get_ipmitool_value_by_name(command, ipmi_name[j], ioption))
                {
                    // error
                    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s() get ZBX_DSERVICE_KEY_SYSNAME fail ipmi_name=[%s]", __func__, ipmi_name[j]);
                }
            }
        }
        else if (SUCCEED == strcmp(ZBX_DSERVICE_KEY_SYSDESC, tokens[i]))
        {
            // 制造商 型号 版本
            zbx_split(tokens[i+1], ".", ipmi_name, &ipmi_name_num);
            for(int j = 0; j < ipmi_name_num; j++)
            {
                if(SUCCEED !=  get_ipmitool_value_by_name(command, ipmi_name[j], ioption))
                {
                    // error
                    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s() get ZBX_DSERVICE_KEY_SYSDESC fail ipmi_name=[%s]", __func__, ipmi_name[j]);
                }
            }
        }
        else if (SUCCEED == strcmp(ZBX_DSERVICE_KEY_IFPHYSADDRESS, tokens[i]))
        {
            // mac
            zbx_split(tokens[i+1], ".", ipmi_name, &ipmi_name_num);
            for(int j = 0; j < ipmi_name_num; j++)
            {
                if(SUCCEED != get_ipmitool_value_by_name(command, ipmi_name[j], ioption))
                {
                    // error
                    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s() get ZBX_DSERVICE_KEY_IFPHYSADDRESS fail ipmi_name=[%s]", __func__, ipmi_name[j]);
                }
            }
        }
        else if (SUCCEED == strcmp(ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM, tokens[i]))
        {
            // 序列号 <机箱 主板 产品>
            zbx_split(tokens[i+1], ".", ipmi_name, &ipmi_name_num);
            for(int j = 0; j < ipmi_name_num; j++)
            {
                if(SUCCEED != get_ipmitool_value_by_name(command, ipmi_name[j], ioption))
                {
                    // error
                    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s() get ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM fail ipmi_name=[%s]", __func__, ipmi_name[j]);
                }
            }
        }
        else if (SUCCEED == strcmp(ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME, tokens[i]))
        {
            // 实体型号名称
            zbx_split(tokens[i+1], ".", ipmi_name, &ipmi_name_num);
            for(int j = 0; j < ipmi_name_num; j++)
            {

                if(SUCCEED != get_ipmitool_value_by_name(command, ipmi_name[j], ioption))
                {
                    // error
                    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s() get ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME fail ipmi_name=[%s]", __func__, ipmi_name[j]);
                }
            }
        }
    }

    // 创建报文
    create_ipmitool_value_response(ioption);
    // zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s() json=[%s]", __func__, ioption->json);
    return SUCCEED;
}

/* 根据名称获取值*/
int get_ipmitool_value_by_name(char* ipmitoolcmd, const char* name, ipmitool_option_t *ioption)
{
    char cmd[MAX_STRING_LEN];

    // zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s() name =[%s]", __func__, name);
    if(strcmp(name, PRODUCT_MANUFACTURER) == SUCCEED) // 第一次启动会卡住 原因未找到
    {
        // strcat(cmd, "fru | grep \"Product Manufacturer\"");
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Product Manufacturer\"", ipmitoolcmd);
        if(SUCCEED != run_ipmitool_cmd(cmd, &ioption->product_manu_value)){}
        extract_value_after_colon(ioption->product_manu_value);
    }
    else if (strcmp(name, PRODUCT_PART_NUMBER) == SUCCEED)
    {
        // strcat(cmd, "fru | grep \"Product Part Number\"");
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Product Part Number\"", ipmitoolcmd);
        if(SUCCEED != run_ipmitool_cmd(cmd, &ioption->productpart_value)){}
        extract_value_after_colon(ioption->productpart_value);
    }
    else if (strcmp(name, PRODUCT_SERIAL) == SUCCEED)
    {
        // strcat(cmd, "fru | grep \"Product Serial\"");
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Product Serial\"", ipmitoolcmd);
        if(SUCCEED != run_ipmitool_cmd(cmd, &ioption->product_serial_value)){}
        extract_value_after_colon(ioption->product_serial_value);
    }
    else if (strcmp(name, BOARD_PART_NUMBER) == SUCCEED)
    {
        // strcat(cmd, "fru | grep \"Board Part Number\"");
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Board Part Number\"", ipmitoolcmd);
        if(SUCCEED != run_ipmitool_cmd(cmd, &ioption->boardpart_value)){}
        extract_value_after_colon(ioption->boardpart_value);
    }
    else if (strcmp(name, BOARE_SERIAL) == SUCCEED)
    {
        // strcat(cmd, "fru | grep \"Board Serial\"");
        zbx_snprintf(cmd, sizeof(cmd), "%s fru | grep \"Board Part Number\"", ipmitoolcmd);
        if(SUCCEED != run_ipmitool_cmd(cmd, &ioption->board_serial_value)){}
        extract_value_after_colon(ioption->board_serial_value);
    }
    else if (strcmp(name, MAC_ADDRESSS) == SUCCEED)
    {
        // strcat(cmd, "lan print | grep \"MAC Address\"");
        zbx_snprintf(cmd, sizeof(cmd), "%s lan print | grep \"MAC Address\"", ipmitoolcmd);
        if(SUCCEED != run_ipmitool_cmd(cmd, &ioption->mac_address_value)){}
        extract_value_after_colon(ioption->mac_address_value);
    } 
    else 
    {
        return FAIL;
    }
    // zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s() cmd =[%s]", __func__, cmd);
    return SUCCEED; // 成功
}

// 执行 ipmitool 命令
int run_ipmitool_cmd(char* cmd, char **output)
{
    FILE *fp;
    char buffer[1024];
    size_t n = 128;
    size_t len = 0;

    *output = (char *)zbx_malloc(*output, n * sizeof(char));
    if (*output == NULL) {
        zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s()Failed to allocate memory for output", __func__);
        return FAIL;
    }
    (*output)[0] = '\0'; // 确保初始字符串为空

    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s()Failed to run command", __func__);
        zbx_free(*output);
        return FAIL;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        len = strlen(buffer);
        if (len > 0)
        {
            char *new_ptr = (char *)zbx_realloc(*output, n + len + 1); // +1 for null-terminator
            if (new_ptr == NULL)
            {
                zabbix_log(LOG_LEVEL_DEBUG, "#ZOPS#IPMI %s()Failed to reallocate memory for output", __func__);
                zbx_free(*output);
                pclose(fp);
                return FAIL;
            }
            *output = new_ptr;
            strcat(*output, buffer); // 追加新读取的内容
            n += len;
        }
    }
    pclose(fp);

    if (**output == '\0') // 检查输出是否为空
    {
        zabbix_log(LOG_LEVEL_DEBUG, "Failed to read ipmitool output or ipmitool command failed");
        zbx_free(*output);
        return FAIL;
    }
    return SUCCEED;
}

void create_ipmitool_value_response(ipmitool_option_t *ioption)
{
    struct zbx_json j;
    // 初始化 JSON 对象
    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addstring(&j, "ipmi_username", ioption->username, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, "ipmi_password", ioption->password, ZBX_JSON_TYPE_STRING);
    zbx_json_addint64(&j, "ipmi_privilege", ioption->privilege);
    zbx_json_addint64(&j, "ipmi_authtype", ioption->authtype);
    
    zbx_json_addstring(&j, ZBX_DSERVICE_KEY_SYSNAME, ioption->productpart_value, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, ZBX_DSERVICE_KEY_SYSDESC, ioption->product_manu_value, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, ZBX_DSERVICE_KEY_IFPHYSADDRESS, ioption->mac_address_value, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, ZBX_DSERVICE_KEY_ENTPHYSICALSERIALNUM, ioption->product_serial_value, ZBX_JSON_TYPE_STRING);
    zbx_json_addstring(&j, ZBX_DSERVICE_KEY_ENTPHYSICALMODELNAME, ioption->productpart_value, ZBX_JSON_TYPE_STRING);
    zbx_json_close(&j);

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

void extract_value_after_colon(char *original_value) 
{
    if (original_value == NULL) {
        return; 
    }
    char *value_with_colon = strchr(original_value, ':');
    if (value_with_colon != NULL) {
        char *trimmed_value = value_with_colon + 1;
        while(isspace((unsigned char)*trimmed_value)) trimmed_value++;
        zbx_rtrim(trimmed_value, " \r\n");
        memmove(original_value, trimmed_value, strlen(trimmed_value) + 1); // 返回值未处理
    }
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
    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s()",__func__);
    // 查询 "Chassis by IPMI" 的 hostid 和 status
    zbx_snprintf(sql, sizeof(sql), "SELECT hostid, status FROM hosts WHERE host='Chassis by IPMI'");
    result = zbx_db_select(sql);
    if (NULL != (row = zbx_db_fetch(result)))
    {
        ZBX_STR2UINT64(template_hostid, row[0]);
        status = atoi(row[1]);

        if (3 != status)
        {
            zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s()Template 'Chassis by IPMI' is not in the correct status",__func__);
            zbx_db_free_result(result);
            return;
        }
    }
    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s()2222222 status=%d template_hostid= %d",__func__, status, template_hostid);
    zbx_db_free_result(result);

    if (0 == template_hostid)
    {
        zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s()Template 'Chassis by IPMI' not found",__func__);
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
    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s()33333 max_hosttemplateid = %d",__func__, max_hosttemplateid);
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
    zabbix_log(LOG_LEVEL_ERR, "#ZOPS#IPMI %s()4444 max_hostgroupid = %d",__func__, max_hostgroupid);
    zbx_db_free_result(result);
    zbx_db_execute(sql);
}


// 1 更新host表ipmi信息
// 2 绑定模板
// 3 填写模板宏定义
#endif


