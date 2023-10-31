#ifndef  __IPMI_DISCOVERY__H
#define  __IPMI_DISCOVERY__H


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

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

int IS_IPMI_INIT = FALSE;

void get_ipmi_value_by_ip(char *addr, const unsigned short port);

#endif