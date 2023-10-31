

#include "ossllib.h"

//////////////////////////////////////
// Config info for OS and platform
//////////////////////////////////////

#define CPUI_OS_MACOS 0
#define CPUI_OS_IOS 0
#define CPUI_OS_ANDROID 0
#define CPUI_OS_WINDOWS 0
#define CPUI_OS_LINUX 0

#if defined(__APPLE__) && defined(__MACH__)

#include <TargetConditionals.h>

#if TARGET_IPHONE_SIMULATOR == 1

#undef CPUI_OS_IOS
#define CPUI_OS_IOS 1

#elif TARGET_OS_IPHONE == 1

#undef CPUI_OS_IOS
#define CPUI_OS_IOS 1

#elif TARGET_OS_MAC == 1

#undef CPUI_OS_MACOS
#define CPUI_OS_MACOS 1

#endif
#elif defined(__WIN32__) || defined(__WINDOWS__) || defined(_WIN64) || defined(_WIN32) || defined(_WINDOWS) || defined(__TOS_WIN__)
#undef CPUI_OS_WINDOWS

#define CPUI_OS_WINDOWS 1

#elif defined(__linux__) || defined(__linux) || defined(linux_generic)

#undef CPUI_OS_LINUX
#define CPUI_OS_LINUX 1

#elif defined(__ANDROID__)

#undef CPUI_OS_ANDROID
#define CPUI_OS_ANDROID 1
#define CPUI_OS_ANDROID_API_LEVEL = __ANDROID_API__;

#endif

//////////////////////////////////////
// Implementation section
//////////////////////////////////////

#include <stddef.h>

void cpui_log_result(FILE *file, cpui_result *result)
{
    fprintf(file, "vendor_string: %s\n", result->vendor_string);
    fprintf(file, "brand_string: %s\n", result->brand_string);
    fprintf(file, "microcode_string: %s\n", result->microcode_string);
    fprintf(file, "physical_cores: %d\n", result->physical_cores);
    fprintf(file, "logical_cores: %d\n", result->logical_cores);
    fprintf(file, "cache_line_size: %zu\n", result->cache_line_size);
    fprintf(file, "l1d_cache_size: %zu\n", result->l1d_cache_size);
    fprintf(file, "l1i_cache_size: %zu\n", result->l1i_cache_size);
    fprintf(file, "l2_cache_size: %zu\n", result->l2_cache_size);
    fprintf(file, "l3_cache_size: %zu\n", result->l3_cache_size);
}

#if CPUI_OS_MACOS == 1

#include <sys/sysctl.h>

int cpui_sysctlbyname(const char *name, void *data, size_t *data_size, cpui_error_t *cpui_err)
{
    int err = sysctlbyname(name, data, data_size, NULL, 0);
    *cpui_err = err ? CPUI_ERROR_SYSCALL : CPUI_SUCCESS;
    return err;
}

cpui_error_t cpui_get_info(cpui_result *result)
{
    // Assuming an Intel processor with CPUID leaf 11
    cpui_error_t err = CPUI_SUCCESS;

    size_t len = sizeof(result->physical_cores);
    if (cpui_sysctlbyname("hw.physicalcpu", &result->physical_cores, &len, &err))
    {
        return err;
    }

    len = sizeof(result->logical_cores);
    if (cpui_sysctlbyname("hw.logicalcpu", &result->logical_cores, &len, &err))
    {
        return err;
    }

    len = sizeof(result->brand_string);
    if (cpui_sysctlbyname("machdep.cpu.brand_string", &result->brand_string, &len, &err))
    {
        return err;
    }

    len = sizeof(result->vendor_string);
    if (cpui_sysctlbyname("machdep.cpu.vendor", &result->vendor_string, &len, &err))
    {
        return err;
    }

    len = sizeof(result->cache_line_size);
    if (cpui_sysctlbyname("hw.cachelinesize", &result->cache_line_size, &len, &err))
    {
        return err;
    }

    len = sizeof(result->l1i_cache_size);
    if (cpui_sysctlbyname("hw.l1icachesize", &result->l1i_cache_size, &len, &err))
    {
        return err;
    }

    len = sizeof(result->l1d_cache_size);
    if (cpui_sysctlbyname("hw.l1dcachesize", &result->l1d_cache_size, &len, &err))
    {
        return err;
    }

    len = sizeof(result->l2_cache_size);
    if (cpui_sysctlbyname("hw.l2cachesize", &result->l2_cache_size, &len, &err))
    {
        return err;
    }

    len = sizeof(result->l3_cache_size);
    if (cpui_sysctlbyname("hw.l3cachesize", &result->l3_cache_size, &len, &err))
    {
        return err;
    }

    return CPUI_SUCCESS;
}

#elif CPUI_OS_WINDOWS == 1

// remove a bunch of unused stuff from Windows.h (these can all be found in Windows.h)
#define NOGDICAPMASKS     // - CC_*, LC_*, PC_*, CP_*, TC_*, RC_
#define NOVIRTUALKEYCODES // - VK_*
#define NOWINMESSAGES     // - WM_*, EM_*, LB_*, CB_*
#define NOWINSTYLES       // - WS_*, CS_*, ES_*, LBS_*, SBS_*, CBS_*
#define NOSYSMETRICS      // - SM_*
#define NOMENUS           // - MF_*
#define NOICONS           // - IDI_*
#define NOKEYSTATES       // - MK_*
#define NOSYSCOMMANDS     // - SC_*
#define NORASTEROPS       // - Binary and Tertiary raster ops
#define NOSHOWWINDOW      // - SW_*
#define OEMRESOURCE       // - OEM Resource values
#define NOATOM            // - Atom Manager routines
#define NOCLIPBOARD       // - Clipboard routines
#define NOCOLOR           // - Screen colors
#define NOCTLMGR          // - Control and Dialog routines
#define NODRAWTEXT        // - DrawText() and DT_*
#define NOGDI             // - All GDI defines and routines
#define NOKERNEL          // - All KERNEL defines and routines
#define NOUSER            // - All USER defines and routines
#define NONLS             // - All NLS defines and routines
#define NOMB              // - MB_* and MessageBox()
#define NOMEMMGR          // - GMEM_*, LMEM_*, GHND, LHND, associated routines
#define NOMETAFILE        // - typedef METAFILEPICT
#define NOMINMAX          // - Macros min(a,b) and max(a,b)
#define NOMSG             // - typedef MSG and associated routines
#define NOOPENFILE        // - OpenFile(), OemToAnsi, AnsiToOem, and OF_*
#define NOSCROLL          // - SB_* and scrolling routines
#define NOSERVICE         // - All Service Controller routines, SERVICE_ equates, etc.
#define NOSOUND           // - Sound driver routines
#define NOTEXTMETRIC      // - typedef TEXTMETRIC and associated routines
#define NOWH              // - SetWindowsHook and WH_*
#define NOWINOFFSETS      // - GWL_*, GCL_*, associated routines
#define NOCOMM            // - COMM driver routines
#define NOKANJI           // - Kanji support stuff.
#define NOHELP            // - Help engine interface.
#define NOPROFILER        // - Profiler interface.
#define NODEFERWINDOWPOS  // - DeferWindowPos routines
#define NOMCX             // - Modem Configuration Extensions

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <intrin.h>

enum cpui_cpuid_fn_id
{
    CPUID_FN_ID_EXTENDED_MAX = 0x80000000,
    CPUID_FN_ID_BRAND_STRING_BEGIN = 0x80000002,
    CPUID_FN_ID_BRAND_STRING_END = 0x80000004
};

void cpui_cpuid(uint32_t op, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    int regs[4];
    __cpuid(regs, op);
    *eax = (uint32_t)regs[0];
    *ebx = (uint32_t)regs[1];
    *ecx = (uint32_t)regs[2];
    *edx = (uint32_t)regs[3];
}

void cpui_get_cache_info(cpui_result *result, CACHE_DESCRIPTOR *cd)
{
    switch (cd->Level)
    {
    case 1:
    {
        result->cache_line_size = cd->LineSize;

        if (cd->Type == CacheData)
        {
            result->l1d_cache_size = cd->Size;
        }

        if (cd->Type == CacheInstruction)
        {
            result->l1i_cache_size = cd->Size;
        }
    }
    break;
    case 2:
    {
        result->l2_cache_size = cd->Size;
    }
    break;
    case 3:
    {
        result->l3_cache_size = cd->Size;
    }
    break;
    default:
        break;
    };
}

cpui_error_t cpui_get_info(cpui_result *result)
{
    typedef BOOL(WINAPI * glpi_t)(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    result->logical_cores = sysinfo.dwNumberOfProcessors;
    result->physical_cores = 0;

    glpi_t glpi = (glpi_t)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetLogicalProcessorInformation");

    // GLPI not supported on the current system
    if (glpi == NULL)
    {
        return CPUI_ERROR_NOT_SUPPORTED;
    }

    // Try and allocate buffer large enough for return info
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buf = NULL;
    DWORD ret_len = 0;
    while (1)
    {
        BOOL ret = glpi(buf, &ret_len);
        if (ret == TRUE)
        {
            break;
        }

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            if (buf)
                free(buf);

            buf = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(ret_len);
            if (buf == NULL)
            {
                return CPUI_ERROR_INVALID_MEMORY_ALLOCATION;
            }
        }
        else
        {
            return CPUI_UNKNOWN;
        }
    }

    DWORD byte_offset = 0;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION next = buf;
    // Scan all relations between logical processors
    while (byte_offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= ret_len)
    {
        switch (next->Relationship)
        {
        // Count physical cores
        case RelationProcessorCore:
        {
            result->physical_cores++;
        }
        break;

        case RelationCache:
        {
            cpui_get_cache_info(result, &next->Cache);
        }
        break;

        default:
            break;
        }

        byte_offset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
        next++;
    }

    // Get vendor string
    memset(result->vendor_string, 0, sizeof(result->vendor_string));
    uint32_t max_op = 0;
    cpui_cpuid(
        0,
        &max_op,
        (uint32_t *)&result->vendor_string[0],
        (uint32_t *)&result->vendor_string[8],
        (uint32_t *)&result->vendor_string[4]);

    // Get brand string
    uint32_t highest_ext_fn_id, ebx, ecx, edx;
    cpui_cpuid((uint32_t)CPUID_FN_ID_EXTENDED_MAX, &highest_ext_fn_id, &ebx, &ecx, &edx);

    memset(result->brand_string, 0, sizeof(result->brand_string));

    // check if extended features are supported or not
    if (highest_ext_fn_id < (uint32_t)CPUID_FN_ID_BRAND_STRING_END)
    {
        return CPUI_SUCCESS;
    }

    int registers[4];
    for (uint32_t i = 0; i <= (uint32_t)(CPUID_FN_ID_BRAND_STRING_END - CPUID_FN_ID_BRAND_STRING_BEGIN); ++i)
    {
        // each call to __cpuid contains 16 ASCII chars in each of the registers represetings a part
        // of the brand string
        __cpuid(registers, (uint32_t)CPUID_FN_ID_BRAND_STRING_BEGIN + i);
        memcpy(result->brand_string + i * 16, registers, sizeof(int) * 4);
    }

    // trim the brand name end
    int brand_str_end = (int)strlen(result->brand_string);
    for (int i = brand_str_end; i >= 0; --i)
    {
        if (result->brand_string[i] != ' ' && result->brand_string[i] != '\0' && i < brand_str_end)
        {
            result->brand_string[i + 1] = '\0';
            break;
        }
    }

    return CPUI_SUCCESS;
}

#elif CPUI_OS_LINUX == 1

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

/// Returns an integer representing the last characters position in a string
///
/// \return -1 for invalid string, 0 for empty string, or an integer index value
int cpui_strend(char *str)
{
    if (!str)
    {
        return -1;
    }

    if (!str[0])
    {
        return 0;
    }

    int result = -1;
    size_t len = strlen(str);
    for (size_t i = len; i > 0; --i)
    {
        if (isspace(str[i]))
        {
            result = (int)i;
            break;
        }
    }

    if (result == -1)
    {
        return (int)len;
    }
    return result;
}

/// Gets the value as an integer from the key/value pair contained within `line` pulled from `/proc/cpuinfo`
uint32_t cpui_cpuinfo_parse_numeric(char *line, uint32_t *result)
{
    char *colon = strchr(line, ':');
    if (colon != NULL)
    {
        *result = (uint32_t)atoi(colon + 2);
    }
}

/// Gets the value as a string from the key/value pair contained within `line` pulled from `/proc/cpuinfo`
void cpui_cpuinfo_parse_string(char *line, char *result)
{
    char *colon = strchr(line, ':');
    int strend = cpui_strend(colon + 2);
    if (colon != NULL && strend > -1)
    {
        strncpy(result, colon + 2, (size_t)strend);
    }
}

cpui_error_t cpui_get_info(cpui_result *result)
{
    memset(result, 0, sizeof(cpui_result));
    char str[256];
    FILE *cpuinfo = fopen("/proc/cpuinfo", "rb");

    // Getting cache info with sysconf is portable, whereas logical/hw core info isn't
    result->cache_line_size = (size_t)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    result->l1d_cache_size = (size_t)sysconf(_SC_LEVEL1_DCACHE_SIZE);
    result->l1i_cache_size = (size_t)sysconf(_SC_LEVEL1_ICACHE_SIZE);
    result->l2_cache_size = (size_t)sysconf(_SC_LEVEL2_CACHE_SIZE);
    result->l3_cache_size = (size_t)sysconf(_SC_LEVEL3_CACHE_SIZE);

    // Read through cpuinfo and parse results
    while (fgets(str, sizeof(str), cpuinfo))
    {
        if (!strncmp(str, "processor", 9))
        {
            result->logical_cores++;
        }

        if (!strncmp(str, "cpu cores", 9) && result->physical_cores == 0)
        {
            cpui_cpuinfo_parse_numeric(str, &result->physical_cores);
        }

        if (!strncmp(str, "vendor_id", 9) && result->vendor_string[0] == 0)
        {
            cpui_cpuinfo_parse_string(str, result->vendor_string);
        }
        if (!strncmp(str, "microcode", 9) && result->microcode_string[0] == 0)
        {
            cpui_cpuinfo_parse_string(str, result->microcode_string);
        }

        if (!strncmp(str, "model name", 10) && result->brand_string[0] == 0)
        {
            cpui_cpuinfo_parse_string(str, result->brand_string);
        }
    }

    fclose(cpuinfo);

    return CPUI_SUCCESS;
}

#define MACADDRESS_LEN 129
#define MACADDRESS_COUNT 6

void execute_command(const char *cmd, const char *label)
{
    FILE *fp;
    char buffer[128];

    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        lic_printf("Failed to execute command\n");
        return;
    }

    lic_printf("%s: ", label);
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        lic_printf("%s", buffer);
    }

    pclose(fp);
}

int get_macaddress_info(char (*mac_addr)[MACADDRESS_LEN])
{
    FILE *fp;
    char linebuf[256];
    int mac_count = 0;

    char *tokens[128] = {0};
    int i = 0, j = 0, num = 128;

    fp = popen("ifconfig -a", "r");
    if (fp == NULL)
    {
        lic_printf("Failed to execute command\n");
        return 0;
    }
    int ignore_lines = 0;
    while (fgets(linebuf, sizeof(linebuf), fp) != NULL)
    {
        char *buffer = trim(linebuf);
        // ignore docker's macaddress because docker macaddress will changed when system restart
        if (!strncmp(buffer, "docker", 6))
        {
            ignore_lines = 7;
        }
        if (ignore_lines > 0)
        {
            // lic_printf("lines=%d,buffer=%s\n",ignore_lines, buffer);
            ignore_lines--;
            continue;
        }

        //lic_printf("buffer=%s\n", buffer);

        // string format is "ether 02:42:e5:31:ee:19  txqueuelen 0  (Ethernet)"
        if (!strncmp(buffer, "ether", 5))
        {
            num = 128;
            split(buffer, " ", tokens, &num);
            //lic_printf("mac_count=%d, num=%d,mac=%s,macbuf=%s\n", mac_count, num, tokens[1], buffer);
            if (num > 1 && mac_count < MACADDRESS_COUNT)
            {
                strcpy(mac_addr[mac_count], tokens[1]);
                mac_count++;
            }
        }
    }
    pclose(fp);

    // 冒泡排序
    if (mac_count > 1)
    {
        char buf[129];
        int n = mac_count;
        for (i = 0; i < n - 1; ++i) // 比较n-1轮
        {
            for (j = 0; j < n - 1 - i; ++j) // 每轮比较n-1-i次,
            {
                if (strcmp(mac_addr[j], mac_addr[j + 1]) > 0 )
                { 
                    strcpy(buf, mac_addr[j]);
                    strcpy(mac_addr[j], mac_addr[j + 1]);
                    strcpy(mac_addr[j + 1], buf); 
                }
            }
        }
        
    }
    // for (i = 0; i < mac_count; i++)
    // {
    //     lic_printf("macaddress=%s\n", mac_addr[i]);
    // }
    return mac_count;
}

int get_sha_hardware_info(char *sha_hwinfo)
{
    if (NULL == sha_hwinfo)
    {
        return -1;
    }

    int i = 0;
    char *split = "-";
    cpui_result cpui;
    int hw_len = 2048;
    unsigned char hw_info[hw_len];
    unsigned char sha_buf[SHA256_DIGEST_SIZE];
    char mac_addr[MACADDRESS_COUNT][MACADDRESS_LEN];

    memset(hw_info, 0, hw_len);
    memset(sha_buf, 0, SHA256_DIGEST_SIZE);

    int info_err = cpui_get_info(&cpui);
    if (!info_err)
    {
        strncat(hw_info, cpui.vendor_string, hw_len - strlen(hw_info));
        strncat(hw_info, cpui.brand_string, hw_len - strlen(hw_info));
        strncat(hw_info, cpui.microcode_string, hw_len - strlen(hw_info));
    }
    int count = get_macaddress_info(mac_addr);
    for (i = 0; i < count; i++)
    {
        strncat(hw_info, split, hw_len - strlen(hw_info));
        strncat(hw_info, mac_addr[i], hw_len - strlen(hw_info));
    }
    lic_printf("hw_info=%s\n", hw_info);
    int str_len = strlen(hw_info);
    if (str_len > 0)
    {

        sha256((const unsigned char *)hw_info, str_len, sha_buf);

        for (i = 0; i < (int)SHA256_DIGEST_SIZE; i++)
        {
            sprintf(sha_hwinfo + 2 * i, "%02x", sha_buf[i]);
        }
        lic_printf("sha_hwinfo=%s\n", sha_hwinfo);
    }
    return strlen(sha_hwinfo);
}

#else

cpui_error_t cpui_get_info(cpui_result *result)
{
    return CPUI_ERROR_NOT_IMPLEMENTED;
}

#endif // conditional info
