#ifndef LICPROVIDER_H
#define LICPROVIDER_H


#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ossllib.h"
#include "license.h"

#define ELICFILE 0x0001

void init_provider(int flag);
void exit_provider(int exit_code);

char *create_license(const char *company, const char *version, const char *lic_expired,
                     const char *productkey, int nodes, int monitor_size, struct service *monitor,
                     int func_size, struct service *func);

/***
 * usage:\nlic_provider <company> <version> <lic_expired> <productkey> <nodes>  \
<monitor_size> [func1:nodes1|func2:nodes2 ...] <func_size> [func1:allow1|func2:allow2 ...]
 * 例如: irigud 1.0.1 2026-9-10 730d1a4a864c353a9e0c60f249b4c148f3dd1afbff969aa16caa76115e199a54 500 3 base:10#database:20#middleware:60 2 vkvm:1#sms:1 
*/
void create_license_from_argv(int argc, const char *argv[]);


#endif // LICPROVIDER_H
