#ifndef LICHARDWARE_INFO_H
#define LICHARDWARE_INFO_H

#include <stdint.h>
#include <stdio.h>

//////////////////////////////////////
// Error config definitions
//////////////////////////////////////

#define CPUI_ERRORS                \
	CPUI_ERRORDEF(NOT_IMPLEMENTED) \
	CPUI_ERRORDEF(SYSCALL)         \
	CPUI_ERRORDEF(NOT_SUPPORTED)   \
	CPUI_ERRORDEF(INVALID_MEMORY_ALLOCATION)

#define CPUI_ERRORDEF(err) CPUI_ERROR_##err,

typedef enum
{
	CPUI_SUCCESS = 0,
	CPUI_ERRORS
		CPUI_UNKNOWN
} cpui_error_t;

#undef CPUI_ERRORDEF

#define CPUI_ERRORDEF(err) "CPUI_ERROR_" #err,

// const char *const cpui_error_strings[] = {
// 	"CPUI_SUCCESS",
// 	CPUI_ERRORS
// 	"CPUI_UNKNOWN"};

//////////////////////////////////////
// Header section
//////////////////////////////////////

#define CPUI_VENDOR_STRING_SIZE 32
#define CPUI_BRAND_STRING_SIZE 64
#define CPUI_MICROCODE_STRING_SIZE 32

/// Holds all available information about the current platforms CPU hardware
typedef struct
{
	char vendor_string[CPUI_VENDOR_STRING_SIZE];
	char brand_string[CPUI_BRAND_STRING_SIZE];
	char microcode_string[CPUI_MICROCODE_STRING_SIZE];
	uint32_t physical_cores;
	uint32_t logical_cores;
	size_t cache_line_size;
	size_t l1d_cache_size;
	size_t l1i_cache_size;
	size_t l2_cache_size;
	size_t l3_cache_size;
} cpui_result;

/// Gets all info from the platforms CPU hardware and stores it in `result`
cpui_error_t cpui_get_info(cpui_result *result);

/// Logs a `cpui_result` struct to the file pointed to by `file` in a formatted fashion
void cpui_log_result(FILE *file, cpui_result *result);

int get_sha_hardware_info(char *sha_hwinfo);

#endif // LICHARDWARE_INFO_H
