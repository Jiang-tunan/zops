
#include "discoverer_protocol.h"
#include "log.h"
#include "zbxipcservice.h"
#include "zbxserialize.h"



zbx_uint32_t zbx_discoverer_serialize_json(unsigned char **data, const char *json)
{
    unsigned char	*ptr;
	zbx_uint32_t	data_len = 0, json_len;

	zbx_serialize_prepare_str(data_len, json);

    *data = (unsigned char *)zbx_malloc(NULL, data_len);

    ptr = *data;
	(void)zbx_serialize_str(ptr, json, json_len);

    return data_len;
}

void zbx_discoverer_deserialize_json(const unsigned char *data, char **json)
{
    zbx_uint32_t	json_len;
	(void)zbx_deserialize_str(data, json, json_len);
}


zbx_uint32_t zbx_discoverer_serialize_tid_json(unsigned char **data, zbx_uint64_t trapper_id, const char *json)
{
    unsigned char	*ptr;
	zbx_uint32_t	data_len = 0, json_len;

    zbx_serialize_prepare_value(data_len, trapper_id);
	zbx_serialize_prepare_str(data_len, json);

    *data = (unsigned char *)zbx_malloc(NULL, data_len);

    ptr = *data;
    ptr += zbx_serialize_value(ptr, trapper_id);
	(void)zbx_serialize_str(ptr, json, json_len);

    return data_len;
}

void zbx_discoverer_deserialize_tid_json(const unsigned char *data, zbx_uint64_t *trapper_id, char **json)
{
    zbx_uint32_t	json_len;
    data += zbx_deserialize_value(data, trapper_id);
	(void)zbx_deserialize_str(data, json, json_len);
}



