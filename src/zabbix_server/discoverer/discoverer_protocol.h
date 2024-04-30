#ifndef ZABBIX_DISCOVERER_PROTOCOL_H
#define ZABBIX_DISCOVERER_PROTOCOL_H


#include "zbxdbhigh.h"
#define ZBX_IPC_SERVICE_DISCOVERER	"discoverer"

/* trapper -> discoverer */
#define ZBX_IPC_TRAPPER_SEND_SINGLE_SCAN		1500

/* manager <-> worker */
#define ZBX_IPC_DISCOVERER_WORKER_REGISTER      1551
#define ZBX_IPC_DISCOVERER_SINGLE_SCAN          1552
#define ZBX_IPC_DISCOVERER_WORKER_RESULT        1553


zbx_uint32_t zbx_discoverer_serialize_json(unsigned char **data, const char *json);
void zbx_discoverer_deserialize_json(const unsigned char *data, char **json);
zbx_uint32_t zbx_discoverer_serialize_tid_json(unsigned char **data, zbx_uint64_t trapper_id, const char *json);
void zbx_discoverer_deserialize_tid_json(const unsigned char *data, zbx_uint64_t *trapper_id, char **json);

#endif





