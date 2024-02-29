/*
** Zabbix
** Copyright (C) 2001-2023 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

#include "zbxdiscovery.h"

#include "log.h"
#include "../../zabbix_server/events.h"
#include "../../zabbix_server/discoverer/user_discoverer.h"
#include "zbxtime.h"
#include "zbxnum.h"
#include "zbxserver.h"
#include "zbx_host_constants.h"
#include "zbxdbwrap.h"
#include "zbxsysinfo.h"

void inventory_free(DB_HOST_INVENTORY *inventory)
{
	zbx_free(inventory->dunique);
	zbx_free(inventory->manufacturer);
	zbx_free(inventory->physical_model);
	zbx_free(inventory->physical_serial);
	zbx_free(inventory->chassis);
	zbx_free(inventory->chassis_serial);
	zbx_free(inventory->board);
	zbx_free(inventory->board_serial);
	zbx_free(inventory->os_short);
	zbx_free(inventory->ip);
	zbx_free(inventory->name);
	zbx_free(inventory->description);
	zbx_free(inventory->cpu);
	zbx_free(inventory->memory);
	zbx_free(inventory->disk);
	zbx_free(inventory->network);
	zbx_free(inventory->bios);
	zbx_free(inventory->psu);	
}
 

static char* update_inventory_cpu(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return zbx_strdup(NULL,new);
	
	char cpu_num_old[16],core_num_old[16],mf_old[256],name_old[256];
	memset(cpu_num_old, 0, sizeof(cpu_num_old));
	memset(core_num_old, 0, sizeof(core_num_old));
	memset(mf_old, 0, sizeof(mf_old));
	memset(name_old, 0, sizeof(name_old));
	struct zbx_json_parse jp_old;
	if (SUCCEED == zbx_json_open(old, &jp_old))
	{
		zbx_json_value_by_name(&jp_old, "cpu_num", cpu_num_old, sizeof(cpu_num_old), NULL);
		zbx_json_value_by_name(&jp_old, "core_num", core_num_old, sizeof(core_num_old), NULL);
		zbx_json_value_by_name(&jp_old, "mf", mf_old, sizeof(mf_old), NULL);
		zbx_json_value_by_name(&jp_old, "name", name_old, sizeof(name_old), NULL);
	}

	struct zbx_json_parse jp_new;
	char cpu_num_new[16],core_num_new[16],mf_new[256],name_new[256];
	memset(cpu_num_new, 0, sizeof(cpu_num_new));
	memset(core_num_new, 0, sizeof(core_num_new));
	memset(mf_new, 0, sizeof(mf_new));
	memset(name_new, 0, sizeof(name_new));
	if (SUCCEED == zbx_json_open(new, &jp_new))
	{
		zbx_json_value_by_name(&jp_new, "cpu_num", cpu_num_new, sizeof(cpu_num_new), NULL);
		zbx_json_value_by_name(&jp_new, "core_num", core_num_new, sizeof(core_num_new), NULL);
		zbx_json_value_by_name(&jp_new, "mf", mf_new, sizeof(mf_new), NULL);
		zbx_json_value_by_name(&jp_new, "name", name_new, sizeof(name_new), NULL);
	}

	struct zbx_json j;
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);

	int cpu_num = zbx_atoi(get_2str_field(cpu_num_old, cpu_num_new));
	if(cpu_num > 0) zbx_json_addint64(&j, "cpu_num", cpu_num);

	int core_num = zbx_atoi(get_2str_field(core_num_old, core_num_new));
	if(core_num > 0) zbx_json_addint64(&j, "core_num", core_num);

	char *mf = get_2str_field(mf_old, mf_new);
	if(NULL != mf && strlen(mf) > 0) zbx_json_addstring(&j, "mf", mf, ZBX_JSON_TYPE_STRING);
	
	char *name = get_2str_field(name_old, name_new);
	if(NULL != name && strlen(name) > 0) zbx_json_addstring(&j, "name", name, ZBX_JSON_TYPE_STRING);

	zbx_json_close(&j);
    char *json = zbx_strdup(NULL, j.buffer);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	zbx_json_free(&j);
	zbx_free(old);
	return json;
}


static char* update_inventory_bios(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return zbx_strdup(NULL,new);

	char mf_old[256],model_old[256],version_old[256];
	memset(mf_old, 0, sizeof(mf_old));
	memset(model_old, 0, sizeof(model_old));
	memset(version_old, 0, sizeof(version_old));
	struct zbx_json_parse jp_old;
	if (SUCCEED == zbx_json_open(old, &jp_old))
	{
		zbx_json_value_by_name(&jp_old, "mf", mf_old, sizeof(mf_old), NULL);
		zbx_json_value_by_name(&jp_old, "model", model_old, sizeof(model_old), NULL);
		zbx_json_value_by_name(&jp_old, "version", version_old, sizeof(version_old), NULL);
	}
	//zbx_json_close(&jp_old);

	struct zbx_json_parse jp_new;
	char mf_new[256],model_new[256],version_new[256];
	memset(mf_new, 0, sizeof(mf_new));
	memset(model_new, 0, sizeof(model_new));
	memset(version_new, 0, sizeof(version_new));
	if (SUCCEED == zbx_json_open(new, &jp_new))
	{
		zbx_json_value_by_name(&jp_new, "mf", mf_new, sizeof(mf_new), NULL);
		zbx_json_value_by_name(&jp_new, "model", model_new, sizeof(model_new), NULL);
		zbx_json_value_by_name(&jp_new, "version", version_new, sizeof(version_new), NULL);
	}
	//zbx_json_close(&jp_new);

	struct zbx_json j;
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);

	char *mf = get_2str_field(mf_old, mf_new);
	if(NULL != mf && strlen(mf) > 0) zbx_json_addint64(&j, "mf", mf);

	char *model = get_2str_field(model_old, model_new);
	if(NULL != model && strlen(model) > 0) zbx_json_addstring(&j, "model", model, ZBX_JSON_TYPE_STRING);

	char *version = get_2str_field(version_old, version_new);
	if(NULL != version && strlen(version) > 0) zbx_json_addstring(&j, "version", version, ZBX_JSON_TYPE_STRING);
	
	zbx_json_close(&j);
    char *json = zbx_strdup(NULL, j.buffer); 

	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	zbx_json_free(&j);
	zbx_free(old);
	return json;
}

/**
 * 内存，json数据格式
 * {
	"capacity": "32G", //内存总容量
	"memory":[{
		"mf":"Micron",  //内存厂商
		"model":"镁光16G",  //内存型号
		"serial":"0000000",  //内存序列号
		"capacity": "16 G" //内存容量
		}
	  ]
	}
*/
static char* update_inventory_memory(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return zbx_strdup(NULL,new);

	struct zbx_json j;
	struct zbx_json_parse jp_old,jp_new;
	struct zbx_json_parse jp_memory_old,jp_memory_new;
	int result_old = zbx_json_open(old, &jp_old);
	int result_new = zbx_json_open(new, &jp_new);
	
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	char t_capacity_old[256],t_capacity_new[256];
	char mf_new[256],model_new[256],serial_new[256],capacity_new[256];


	if (SUCCEED == result_old && SUCCEED == result_new)
	{
		memset(t_capacity_old, 0, sizeof(t_capacity_old));
		memset(t_capacity_new, 0, sizeof(t_capacity_new));
		zbx_json_value_by_name(&jp_old, "capacity", t_capacity_old, sizeof(t_capacity_old), NULL);
		zbx_json_value_by_name(&jp_new, "capacity", t_capacity_new, sizeof(t_capacity_new), NULL);

		char *capacity = get_2str_field(t_capacity_old, t_capacity_new);
		if(NULL != capacity && strlen(capacity) > 0) zbx_json_addstring(&j, "capacity", capacity, ZBX_JSON_TYPE_STRING);

		int is_used_new = 0;
		const char *p = NULL;
		// 如果有新的对象有值，则用新的对象值
		if (SUCCEED == zbx_json_brackets_by_name(&jp_new, "memory", &jp_memory_new)
			&& zbx_json_count(&jp_memory_new) > 0)
		{
			is_used_new = 1;
			p = zbx_json_next(&jp_memory_new, p);
		}
		// 否则则用数据库对象值
		else if (SUCCEED == zbx_json_brackets_by_name(&jp_old, "memory", &jp_memory_old)
			&& zbx_json_count(&jp_memory_old) > 0)
		{
			p = zbx_json_next(&jp_memory_old, p);
		}

		zbx_json_addarray(&j, "memory");
		while (NULL != p)
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				zbx_json_addobject(&j, NULL);
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "mf", mf_new, sizeof(mf_new), NULL))
				{
					zbx_json_addstring(&j, "mf", mf_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "model", model_new, sizeof(model_new), NULL))
				{
					zbx_json_addstring(&j, "model", model_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "serial", serial_new, sizeof(serial_new), NULL))
				{
					zbx_json_addstring(&j, "serial", serial_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "capacity", capacity_new, sizeof(capacity_new), NULL))
				{
					zbx_json_addstring(&j, "capacity", capacity_new, ZBX_JSON_TYPE_STRING);
				}
				zbx_json_close(&j);
			}
			if(is_used_new)
				p = zbx_json_next(&jp_memory_new, p);
			else
				p = zbx_json_next(&jp_memory_old, p);
		}
		zbx_json_close(&j);

	} 
	zbx_json_close(&j);
    char *json = zbx_strdup(NULL, j.buffer);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	zbx_json_free(&j);
	zbx_free(old);
	return json;
}

/**
 * 磁盘，json数据格式
 * {
	"capacity": "32G", //磁盘总容量
	"disk":[{
		"name":"镁光MTFDKBA512TFH",  //磁盘名称
		"model":"Micron MTFDKABA512TFH",  //磁盘型号
		"serial":"5WBXT0C4DAU2EM",  //磁盘序列号
		"capacity": "512 G"  //磁盘容量
		}
	]
	}
*/
static char* update_inventory_disk(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return zbx_strdup(NULL,new);
	struct zbx_json j;
	struct zbx_json_parse jp_old,jp_new;
	struct zbx_json_parse jp_disk_old,jp_disk_new;
	int result_old = zbx_json_open(old, &jp_old);
	int result_new = zbx_json_open(new, &jp_new);

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	char t_capacity_old[256],t_capacity_new[256];
	char name_new[256],model_new[256],serial_new[256],capacity_new[256];
	if (SUCCEED == result_old && SUCCEED == result_new)
	{
		memset(t_capacity_old, 0, sizeof(t_capacity_old));
		memset(t_capacity_new, 0, sizeof(t_capacity_new));
		zbx_json_value_by_name(&jp_old, "capacity", t_capacity_old, sizeof(t_capacity_old), NULL);
		zbx_json_value_by_name(&jp_new, "capacity", t_capacity_new, sizeof(t_capacity_new), NULL);

		char *capacity = get_2str_field(t_capacity_old, t_capacity_new);
		if(NULL != capacity && strlen(capacity) > 0) zbx_json_addstring(&j, "capacity", capacity, ZBX_JSON_TYPE_STRING);

		int is_used_new = 0;
		const char *p = NULL;
		// 如果有新的对象有值，则用新的对象值
		if (SUCCEED == zbx_json_brackets_by_name(&jp_new, "disk", &jp_disk_new)
			&& zbx_json_count(&jp_disk_new) > 0)
		{
			is_used_new = 1;
			p = zbx_json_next(&jp_disk_new, p);
		}
		// 否则则用数据库对象值
		else if (SUCCEED == zbx_json_brackets_by_name(&jp_old, "disk", &jp_disk_old)
			&& zbx_json_count(&jp_disk_old) > 0)
		{
			p = zbx_json_next(&jp_disk_old, p);
		}
		zbx_json_addarray(&j, "disk");
		while (NULL != p)
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				zbx_json_addobject(&j, NULL);

				if (SUCCEED == zbx_json_value_by_name(&obj_j, "name", name_new, sizeof(name_new), NULL))
				{
					zbx_json_addstring(&j, "name", name_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "model", model_new, sizeof(model_new), NULL))
				{
					zbx_json_addstring(&j, "model", model_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "serial", serial_new, sizeof(serial_new), NULL))
				{
					zbx_json_addstring(&j, "serial", serial_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "capacity", capacity_new, sizeof(capacity_new), NULL))
				{
					zbx_json_addstring(&j, "capacity", capacity_new, ZBX_JSON_TYPE_STRING);
				}
				zbx_json_close(&j);
			}
			if(is_used_new)
				p = zbx_json_next(&jp_disk_new, p);
			else
				p = zbx_json_next(&jp_disk_old, p);
		}
		zbx_json_close(&j);

	} 
	zbx_json_close(&j);
    char *json = zbx_strdup(NULL, j.buffer);
	 
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	zbx_json_free(&j);
	zbx_free(old);
	return json;
}


/**
 * 网络，json数据格式
 * {
	"port_num": 48,   //端口数量
	"ethernet_num": 2,  //网卡数量
	"ethernet": [{
	"name": "HPE Ethernet 1Gb 4-port 331i Adapter - NIC",  //网卡名称(不是端口名称)
	"netspeed":"1G"     //传输速率
	},
	{
	"name": "HPE Ethernet 2Gb 8-port 689 Adapter - NIC"
	}
	]
	}
*/
static char* update_inventory_network(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return zbx_strdup(NULL,new);

	struct zbx_json j;
	struct zbx_json_parse jp_old,jp_new;
	struct zbx_json_parse jp_network_old,jp_network_new;
	int result_old = zbx_json_open(old, &jp_old);
	int result_new = zbx_json_open(new, &jp_new);

	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	char port_num_old[32],port_num_new[32];
	char ethernet_num_old[32],ethernet_num_new[32];
	char name_new[256],netspeed_new[256];
	if (SUCCEED == result_old && SUCCEED == result_new)
	{
		memset(port_num_old, 0, sizeof(port_num_old));
		memset(port_num_new, 0, sizeof(port_num_new));
		zbx_json_value_by_name(&jp_old, "port_num", port_num_old, sizeof(port_num_old), NULL);
		zbx_json_value_by_name(&jp_new, "port_num", port_num_new, sizeof(port_num_new), NULL);
		int port_num = zbx_atoi(get_2str_field(port_num_old, port_num_new));
		if(port_num > 0) zbx_json_addint64(&j, "port_num", port_num);
		
		memset(ethernet_num_old, 0, sizeof(ethernet_num_old));
		memset(ethernet_num_new, 0, sizeof(ethernet_num_new));
		zbx_json_value_by_name(&jp_old, "ethernet_num", ethernet_num_old, sizeof(ethernet_num_old), NULL);
		zbx_json_value_by_name(&jp_new, "ethernet_num", ethernet_num_new, sizeof(ethernet_num_new), NULL);
		int ethernet_num = zbx_atoi(get_2str_field(ethernet_num_old, ethernet_num_new));
		if(ethernet_num > 0) zbx_json_addint64(&j, "ethernet_num", ethernet_num);
		
		int is_used_new = 0;
		const char *p = NULL;

		// 如果有新的对象有值，则用新的对象值
		if (SUCCEED == zbx_json_brackets_by_name(&jp_new, "ethernet", &jp_network_new)
			&& zbx_json_count(&jp_network_new) > 0)
		{
			is_used_new = 1;
			p = zbx_json_next(&jp_network_new, p);
		}
		// 否则则用数据库对象值
		else if (SUCCEED == zbx_json_brackets_by_name(&jp_old, "ethernet", &jp_network_old)
			&& zbx_json_count(&jp_network_old) > 0)
		{
			p = zbx_json_next(&jp_network_old, p);
		}

		zbx_json_addarray(&j, "ethernet");
		while (NULL != p)
		{
			struct zbx_json_parse obj_j;
			if (SUCCEED == zbx_json_brackets_open(p, &obj_j))
			{
				zbx_json_addobject(&j, NULL);

				if (SUCCEED == zbx_json_value_by_name(&obj_j, "name", name_new, sizeof(name_new), NULL))
				{
					zbx_json_addstring(&j, "name", name_new, ZBX_JSON_TYPE_STRING);
				}
				if (SUCCEED == zbx_json_value_by_name(&obj_j, "netspeed", netspeed_new, sizeof(netspeed_new), NULL))
				{
					zbx_json_addstring(&j, "netspeed", netspeed_new, ZBX_JSON_TYPE_STRING);
				}
				zbx_json_close(&j);
			}
			if(is_used_new)
				p = zbx_json_next(&jp_network_new, p);
			else
				p = zbx_json_next(&jp_network_old, p);
		}
		zbx_json_close(&j);
		
	} 
	zbx_json_close(&j);
    char *json = zbx_strdup(NULL, j.buffer);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	zbx_json_free(&j);
	zbx_free(old);	
	return json;
}

/**
 * 电源信息，json格式定义:
 * {
	"psu_num": 2, //电源数量
	"mf":"DELTA",  //电源厂家
	"model":"865414-B21",  //电源型号
	"version":"1.00",  //电源版本
	"serial":"5WBXT0C4DAU2EM",  //电源序列号
	"max_power": 800,  //电源最大功率
	}
*/
static char* update_inventory_psu(char *old, char *new)
{
	if(new == NULL || strlen(new) <= 5)
		return old;
	else if(old == NULL || strlen(old) <= 5)
		return zbx_strdup(NULL,new);

	char psu_num_old[16],mf_old[256],name_old[256],version_old[256],serial_old[256],max_power_old[256];
	memset(psu_num_old, 0, sizeof(psu_num_old));
	memset(mf_old, 0, sizeof(mf_old));
	memset(name_old, 0, sizeof(name_old));
	memset(version_old, 0, sizeof(version_old));
	memset(serial_old, 0, sizeof(serial_old));
	memset(max_power_old, 0, sizeof(max_power_old));

	struct zbx_json_parse jp_old;
	if (SUCCEED == zbx_json_open(old, &jp_old))
	{
		zbx_json_value_by_name(&jp_old, "psu_num", psu_num_old, sizeof(psu_num_old), NULL);
		zbx_json_value_by_name(&jp_old, "mf", mf_old, sizeof(mf_old), NULL);
		zbx_json_value_by_name(&jp_old, "name", name_old, sizeof(name_old), NULL);
		zbx_json_value_by_name(&jp_old, "version", version_old, sizeof(version_old), NULL);
		zbx_json_value_by_name(&jp_old, "serial", serial_old, sizeof(serial_old), NULL);
		zbx_json_value_by_name(&jp_old, "max_power", max_power_old, sizeof(max_power_old), NULL);
	}

	struct zbx_json_parse jp_new;
	char psu_num_new[16],mf_new[256],name_new[256],version_new[256],serial_new[256],max_power_new[256];
	memset(psu_num_new, 0, sizeof(psu_num_new));
	memset(mf_new, 0, sizeof(mf_new));
	memset(name_new, 0, sizeof(name_new));
	memset(version_new, 0, sizeof(version_new));
	memset(serial_new, 0, sizeof(serial_new));
	memset(max_power_new, 0, sizeof(max_power_new));
	if (SUCCEED == zbx_json_open(new, &jp_new))
	{
		zbx_json_value_by_name(&jp_new, "psu_num", psu_num_new, sizeof(psu_num_new), NULL);
		zbx_json_value_by_name(&jp_new, "mf", mf_new, sizeof(mf_new), NULL);
		zbx_json_value_by_name(&jp_new, "name", name_new, sizeof(name_new), NULL);
		zbx_json_value_by_name(&jp_new, "version", version_new, sizeof(version_new), NULL);
		zbx_json_value_by_name(&jp_new, "serial", serial_new, sizeof(serial_new), NULL);
		zbx_json_value_by_name(&jp_new, "max_power", max_power_new, sizeof(max_power_new), NULL);
	}

	struct zbx_json j;
	zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
	int psu_num = zbx_atoi(get_2str_field(psu_num_old, psu_num_new));
	if(psu_num > 0) zbx_json_addint64(&j, "psu_num", psu_num);
	char *mf = get_2str_field(mf_old, mf_new);
	if(NULL != mf && strlen(mf) > 0) zbx_json_addstring(&j, "mf", mf, ZBX_JSON_TYPE_STRING);

	char *name = get_2str_field(name_old, name_new);
	if(NULL != name && strlen(name) > 0) zbx_json_addstring(&j, "name", name, ZBX_JSON_TYPE_STRING);

	char *version = get_2str_field(version_old, version_new);
	if(NULL != version && strlen(version) > 0) zbx_json_addstring(&j, "version", version, ZBX_JSON_TYPE_STRING);
	
	char *serial = get_2str_field(serial_old, serial_new);
	if(NULL != serial && strlen(serial) > 0) zbx_json_addstring(&j, "serial", serial, ZBX_JSON_TYPE_STRING);
	
	char *max_power = get_2str_field(max_power_old, max_power_new);
	if(NULL != max_power && strlen(max_power) > 0) zbx_json_addstring(&j, "max_power", max_power, ZBX_JSON_TYPE_STRING);

	zbx_json_close(&j);
    char *json = strdup(j.buffer);
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s, old:%s new:%s match:%s",
			   __func__, old, new, json);
	zbx_json_free(&j);
	zbx_free(old);
	return json;
}



/**
 * 资产信息插入或更新
*/
void discovery_register_host_inventory(DB_HOST_INVENTORY *inventory)
{
	DB_RESULT result;
	DB_ROW row;
	
	zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __func__);

	int is_find_inventory = 0, is_insert = 0;
	char *unique=NULL,*manufacturer=NULL;
	char *physical_model=NULL,*physical_serial=NULL,*chassis=NULL,*chassis_serial=NULL,*board=NULL,*board_serial=NULL;
	char *os_short=NULL,*description=NULL,*ip=NULL,*name=NULL,*cpu=NULL,*memory=NULL,*disk=NULL,*network=NULL,*bios=NULL,*psu=NULL;
	int inventory_mode=0,hostid=0,houseid=0,inventory_typeid=0,managerid=0,groupid=0;
	int create_time=0, update_time=0;
  
	int inventory_id = -1;
	int dunique_type = inventory->dunique_type;
	char *dunique = inventory->dunique;
	inventory_mode = -1;  // -1 - (默认) 关闭;0 - 手动;1 - 自动.
	// 根据mac地址找到对应的资产
	if (DUNIQUE_TYPE_MACS == inventory->dunique_type && strlen(inventory->dunique) > 0)
	{
		zbx_vector_str_t	macs_his; 
		zbx_vector_str_create(&macs_his); 
		zbx_vector_str_t	macs_dis; 
		zbx_vector_str_create(&macs_dis); 

		str_to_vector(&macs_dis, inventory->dunique, "/");
 
		//新发现的mac地址和主机表里面的任何一个mac地址匹配上了，说明在表里面
		result = zbx_db_select("select id, dunique from host_inventory where dunique_type = 1 ");
		while (NULL != (row = zbx_db_fetch(result)))
		{
			zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
			zbx_vector_str_clear(&macs_his);
			str_to_vector(&macs_his, row[1], "/");
			for (int i = 0; i < macs_dis.values_num; i++)
			{
				if (FAIL != zbx_vector_str_bsearch(&macs_his, macs_dis.values[i], ZBX_DEFAULT_STR_COMPARE_FUNC))
				{
					inventory_id = zbx_atoi(row[0]);
					break;
				}
			}
		}

		zbx_vector_str_clear_ext(&macs_his, zbx_str_free);
		zbx_vector_str_destroy(&macs_his);

		zbx_vector_str_clear_ext(&macs_dis, zbx_str_free);
		zbx_vector_str_destroy(&macs_dis);

		zbx_db_free_result(result);
	} 
	zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s dunique_type=%d, inventory_id=%d, dunique=%s",
		 __func__, dunique_type, inventory_id, dunique);

	if((dunique_type == DUNIQUE_TYPE_MACS && inventory_id >= 0) || 
		(dunique_type != DUNIQUE_TYPE_MACS && inventory->dunique != NULL && strlen(inventory->dunique) > 0))
	{
		char		*sql = NULL;
		size_t		sql_alloc = 512, sql_offset = 0;
		zbx_strcpy_alloc(&sql, &sql_alloc, &sql_offset,
					"select id,hostid,houseid,inventory_typeid,managerid,groupid,manufacturer," \
						"physical_model,physical_serial,chassis,chassis_serial,board,board_serial," \
						"os_short,description,ip,name,cpu,memory,disk,network,bios,psu from host_inventory " );
		if(inventory_id >= 0)
			zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, 
				" where id=%d", inventory_id);
		else
			zbx_snprintf_alloc(&sql, &sql_alloc, &sql_offset, 
				"  where dunique='%s'", inventory->dunique);
		
		//zabbix_log(LOG_LEVEL_DEBUG, "#TOGNIX#%s sql:'%s'", __func__, sql);
		
		result = zbx_db_select(sql); 
		while (NULL != (row = zbx_db_fetch(result)))
		{
			int i=0;
			int id  = zbx_atoi(row[i++]);
			hostid =  get_2int_field(zbx_atoi(row[i++]), inventory->hostid);
			houseid =  get_2int_field(zbx_atoi(row[i++]), inventory->houseid);
			inventory_typeid = get_2int_field(zbx_atoi(row[i++]), inventory->inventory_typeid);
			managerid = get_2int_field(zbx_atoi(row[i++]), inventory->managerid);
			groupid = get_2int_field(zbx_atoi(row[i++]), inventory->groupid);

			manufacturer = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->manufacturer);
			physical_model = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->physical_model);
			physical_serial = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->physical_serial);
			chassis = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->chassis);
			chassis_serial = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->chassis_serial);
			board = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->board);
			board_serial = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->board_serial);
			os_short = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->os_short);
			description = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->description);
			ip = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->ip);
			name = get_2str_field_lfree(zbx_strdup(NULL, row[i++]), inventory->name);
			
			cpu = zbx_strdup(NULL, row[i++]);
			memory = zbx_strdup(NULL, row[i++]);
			disk = zbx_strdup(NULL, row[i++]);
			network = zbx_strdup(NULL, row[i++]);
			bios = zbx_strdup(NULL, row[i++]);
			psu = zbx_strdup(NULL, row[i++]);

			cpu = update_inventory_cpu(cpu, inventory->cpu);
			memory = update_inventory_memory(memory, inventory->memory);
			disk = update_inventory_disk(disk, inventory->disk);
			network = update_inventory_network(network, inventory->network);
			bios = update_inventory_bios(bios, inventory->bios);
			psu = update_inventory_psu(psu, inventory->psu);
			update_time = (int)time(NULL);

			zbx_db_execute("update host_inventory set dunique_type=%d, dunique='%s', hostid=%d,houseid=%d, inventory_typeid=%d, managerid=%d, groupid=%d," \ 
				"manufacturer='%s',physical_model='%s', physical_serial='%s', chassis='%s', chassis_serial='%s', board='%s', board_serial='%s', " \
				"os_short='%s', description='%s', ip='%s',name='%s',cpu='%s', memory='%s', disk='%s', network='%s', bios='%s', psu='%s', update_time=%d " \
				" where id=%d ",
				dunique_type,dunique,hostid,houseid, inventory_typeid, managerid, groupid,  
				manufacturer, physical_model, physical_serial, chassis, chassis_serial, board, board_serial, 
				os_short, description, ip, name, cpu, memory, disk, network, bios, psu, update_time, id);
			is_find_inventory = 1;
			break;
		}
		zbx_free(sql);
		zbx_db_free_result(result);
	}

	if(!is_find_inventory)
	{
		hostid =  inventory->hostid;
		houseid =  inventory->houseid;
		managerid = inventory->managerid;
		inventory_typeid = inventory->inventory_typeid;
		groupid = inventory->groupid;
		manufacturer = zbx_get_db_escape_string(inventory->manufacturer);
		physical_model = zbx_get_db_escape_string(inventory->physical_model);
		physical_serial = zbx_get_db_escape_string(inventory->physical_serial);
		chassis = zbx_get_db_escape_string(inventory->chassis);
		chassis_serial = zbx_get_db_escape_string(inventory->chassis_serial);
		board = zbx_get_db_escape_string(inventory->board);
		board_serial = zbx_get_db_escape_string(inventory->board_serial);
		os_short = zbx_get_db_escape_string(inventory->os_short);
		description = zbx_get_db_escape_string(inventory->description);
		ip = zbx_get_db_escape_string(inventory->ip);
		name = zbx_get_db_escape_string(inventory->name);
			
		cpu = zbx_get_db_escape_string(inventory->cpu);
		memory = zbx_get_db_escape_string(inventory->memory);
		disk = zbx_get_db_escape_string(inventory->disk);
		network = zbx_get_db_escape_string(inventory->network);
		bios = zbx_get_db_escape_string(inventory->bios);
		psu = zbx_get_db_escape_string(inventory->psu);


		create_time = update_time = (int)time(NULL);
		zbx_db_execute("insert into host_inventory (dunique_type,dunique,inventory_mode,hostid,houseid,inventory_typeid,managerid,groupid," \
					"manufacturer,physical_model,physical_serial,chassis,chassis_serial,board,board_serial," \
 					"os_short,description,ip,name,cpu,memory,disk,network,bios,psu,update_time,create_time)" \
					   " values (%d,'%s',%d,%d,%d,%d,%d,%d,"\
					             "'%s','%s','%s','%s','%s','%s','%s'," \
								 "'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%d, %d)",
					dunique_type,dunique,inventory_mode,hostid, houseid, inventory_typeid, managerid, groupid,
					manufacturer, physical_model, physical_serial, chassis, chassis_serial, board, board_serial, 
					os_short, description, ip, name, cpu, memory, disk, network, bios, psu, update_time, create_time);
	}

	zbx_free(manufacturer);
	zbx_free(physical_model);
	zbx_free(physical_serial);
	zbx_free(chassis);
	zbx_free(chassis_serial);
	zbx_free(board);
	zbx_free(board_serial);
	zbx_free(os_short);
	zbx_free(description);
	zbx_free(ip);
	zbx_free(name);
	zbx_free(cpu);
	zbx_free(memory);
	zbx_free(disk);
	zbx_free(network);
	zbx_free(bios);
	zbx_free(psu);

	inventory_free(inventory);

	zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __func__);
}
 