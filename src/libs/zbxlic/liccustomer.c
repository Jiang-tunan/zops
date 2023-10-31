#include "license.h"
#include "ossllib.h"
#include "cJSON.h"

#define ELICOFL 0x0002
#define EPEMOFL 0x0003
#define ELICTST 0x0101

#define trim_newline(p)                              \
    {                                                \
        int i = strlen(p);                           \
        while ('\n' == p[i - 1] || '\r' == p[i - 1]) \
            p[--i] = 0;                              \
    }

// #define load_custome_privatekey() { \
//         customer_privatekey = get_prikey_ex(customer_pem); \
//         save_pubkey(customer_pub_pem, customer_privatekey); \
// }

#define load_custome_privatekey()                                \
    {                                                            \
        customer_privatekey = get_zops_customer_RSAPrivateKey(); \
    }

RSA *get_zops_customer_RSAPrivateKey()
{
    BIO *bp = NULL;
    char *chPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEA8SfuvcaJ7zNI3UZmRI/ndFu/YDhnIv0oTbDa63rpG9O+6d3c\
cs72IUdACJ2MXq+aNUWFEPhk7+3Z1yYCUEojtqG2j2inYbADdOgjJSW0tOnx68eO\
4dbjVVp7yh84YkZi04ZTVCNP40qmiBReEbUzw3dU4yY7E2bKTEw1IhQD5Ru5bMCc\
AEpycJ00MpULHp7TADZUt2H48I/eO8iQr5DjAgV3uimXmkW6ao5WVn4VS7imoBzl\
wKWjPPyL67Yo/o4rmkaZZAnfzEUvtDEhEQkmGisaWSxrexwdPsvwweq5kxgrXFFf\
VretH1lumzd+mJHb2aXVj+ECbmFznTeWQ2T3zwIDAQABAoIBAQCMSNqM8y3SRFci\
wY1EXSIbgjO12ZnFtNb5OuRfD8UDNw5cJX/UGaj8euI5IM1DV4uxaZua36R4HjkW\
+zllU3urBi+ZBRw5q5aXL2MifOi+RUlCC3iGz+a3BEf2sGqwYJmkywM2csRKSGbP\
ymlei7ZtAsIS0W6UPrt33u0ZweLyJylr1hacoyrtU7GbYYx2jJxV1UzHxxI5POKs\
crKIA2yvDVtdpiyGNmTgGFWSd9d8Sq0lDzbS9n/GTPHLUCyiZkTjWAOWMkqk4D3h\
L4m09PiUf69oIMY3CUg7qfKSQTtVlpACdgEXvvVNIL7H1Eizm7f6dBErIgE/dOdf\
aRTjK+/BAoGBAP8yIFoMOnX3D/qTpHL0OCp1cnUtf5iy+Z4JhdpiCdZoJxOsiWT0\
t6WfWcnhR7+ZgVg8J8o1MD0Ej/YiNVoEkA5lNcVVhPykPrJrWdZfkqOW39arTNMb\
RNQQQvpiUnFlyeee2c41lVOPinIcqTgujxSNzmAGftLyOBub8590A6V5AoGBAPHq\
eto6zItdfhVW70ChD18r91iB708TPDDS2H0gjR1mCuhzky7iPQZTlz83o+jHcpNy\
1df6Wn6MySSgGV8/6nUim2ei02tk+j/tZqZIEwLWt/B+8sHfuTU3+ZjYtOdbCPuP\
qF+/3/ISF1+11t+RpymrOF8dOZkPjZ50tJydCh2HAoGAXHoIuTj3MmpecvpvvGx9\
sf0vhgD/3RD2XeurgtDGKdlCV+HNRDVeG3mcawjlHCx/b78U2DTgDyyJErOgy8cd\
gOnyS1lLQNYwFi3Kt2GY3Qk+gic/Rrz5+zMNYnig0ZEGUpYA7bYDL+2zSNjUBZTx\
qowcvjV8XesCpBameSDsdVkCgYBtfL8fV69NgAHZbKAZ8wr++uoWX7BMbJs4SaT7\
dKkJXi6fp/c8J96Qp3JzhR4k82eyvi10c3VTgyph7ietiUL2wrPtAq+HEouENVDY\
/xPDnCRhr0L1Zejv4iaP+7xcXUJCgHEm7LNRXsi/Y5AdXVF3tWts+NAhqv1gctdv\
bk+urwKBgH44eVyLaZU5Ts9ZpWEaJagJB7k3am8n5167U0QKIFz6MeyP1bFVpejH\
SMovLUEco10fr60DHe7yvb3gLr8LpzBOmblS4XR3hzA/J9k7S9LJyBA2Sh/6PTV7\
4T1XJGM8xD9dWFnt4bjfNey8XwZjmA+dG5yvfzMx8fY0zcfGp5wg\n\
-----END RSA PRIVATE KEY-----";
    if ((bp = BIO_new_mem_buf(chPrivateKey, -1)) == NULL)
    {
        lic_printf("BIO_new_mem_buf failed!\n");
        return NULL;
    }
    RSA *rc = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, (void *)u);
    BIO_free(bp);
    return rc;
}

#define load_provider_publickey()                           \
    {                                                       \
        provider_publickey = get_zops_provider_publickey(); \
    }
RSA *get_zops_provider_publickey()
{
    BIO *bp = NULL;
    char *chPublicKey = "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAq1fqR/nyLUnfFq234nrfHFmy7neY/MHdFUNq0cI7yvq+gVP+uvI6\
//naRxLHp3S3BSS7boMn6gQFPwxAnrj6PLuu1QAXLSjq4e6m+D5B7Wr0XUsO1MnB\
k2CBlVDq1vMkIi5ggGCW/pROWj+1mKz6FZDw/C4FU7YZXzPuY14l3R+kPnlJs9Lt\
R4NCxXmlC8YY+Ts7Y5rJ/BokKAcVkrX8IW2aCjHTTBfpQVWuMo7YnIrBejv+gCxi\
j2BkjqJRoGSAMtJLW9/TKbzV5Kv7nsZ+QIA27feVMGSOMQoKXA3BRazb47XePv3y\
YqbZGAFUXhijBC+PFn7AXBTmIPYo+wP3qwIDAQAB\n\
-----END RSA PUBLIC KEY-----";
    if ((bp = BIO_new_mem_buf(chPublicKey, -1)) == NULL)
    {
        lic_printf("BIO_new_mem_buf failed!\n");
        return NULL;
    }
    RSA *rc = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    BIO_free(bp);
    return rc;
}

int g_license_init = 0;
int g_result = LICENSE_LOAD_ERROR;
time_t g_lic_expired = 0;
struct app_license g_app_lic;
RSA *customer_privatekey = NULL;
RSA *provider_publickey = NULL;

char provider_lic[256] = {"provider.lic"};

 
void free_license(char *session_key, char *enc_session_key, char *enc_license,
                  unsigned char *license_buffer, char *enc_sign, char *dec_buffer)
{
    if (dec_buffer)
        free(dec_buffer);
    if (session_key)
        free(session_key);
    if (enc_session_key)
        free(enc_session_key);
    if (license_buffer)
        free(license_buffer);
    if (enc_license)
        free(enc_license);
    if (enc_sign)
        free(enc_sign);
}

int parse_license_fromjson(char *license_buffer)
{
    //memset(&g_app_lic, 0, sizeof(g_app_lic));
    // 第一步：调用cJSON_Parse开始解析json文件，获得json根节点
    cJSON *root = cJSON_Parse(license_buffer);
    if (root == NULL || root->child == NULL)
    {
        return LICENSE_PARSE_JSON_ERROR;
    }

    cJSON *company = cJSON_GetObjectItem(root, "company");
    if (company != NULL)
    {
        strcpy(g_app_lic.company, company->valuestring);
    }
    else
    {
        return LICENSE_PARSE_JSON_ERROR;
    }

    cJSON *version = cJSON_GetObjectItem(root, "version");
    if (version != NULL)
    {
        strcpy(g_app_lic.version, version->valuestring);
    }
    else
    {
        return LICENSE_PARSE_JSON_ERROR;
    }

    cJSON *lic_begin = cJSON_GetObjectItem(root, "lic_begin");
    if (lic_begin != NULL)
    {
        strcpy(g_app_lic.lic_begin, lic_begin->valuestring);
    }
    else
    {
        return LICENSE_PARSE_JSON_ERROR;
    }

    cJSON *lic_expired = cJSON_GetObjectItem(root, "lic_expired");
    if (lic_expired != NULL)
    {
        strcpy(g_app_lic.lic_expired, lic_expired->valuestring);
        char *date_buf[10] = {0};
       //分割后子字符串的个数
        int num = 10;
        split(lic_expired->valuestring, "-", date_buf, &num);
        struct tm tm_time;
        tm_time.tm_year = atoi(date_buf[0])-1900;
        tm_time.tm_mon = atoi(date_buf[1])-1;
        tm_time.tm_mday = atoi(date_buf[2]);
        tm_time.tm_hour = 23;
        tm_time.tm_min = 59;
        tm_time.tm_sec = 59;
        //strptime(g_app_lic.lic_expired, "%Y-%m-%d", &tm_time);
        g_lic_expired = mktime(&tm_time);
    }
    else
    {
        return LICENSE_PARSE_JSON_ERROR;
    }

    cJSON *productkey = cJSON_GetObjectItem(root, "productkey");
    if (productkey != NULL)
    {
        strcpy(g_app_lic.productkey, productkey->valuestring);
    }
    else
    {
        return LICENSE_PARSE_JSON_ERROR;
    }

    cJSON *nodes = cJSON_GetObjectItem(root, "nodes");
    if (nodes != NULL)
    {
        g_app_lic.nodes = nodes->valueint;
    }
    else
    {
        return LICENSE_PARSE_JSON_ERROR;
    }

    int i = 0, list_size = 0;
    cJSON *monitor_list = cJSON_GetObjectItem(root, "monitor");
    if (monitor_list != NULL && cJSON_IsArray(monitor_list))
    {
        list_size = cJSON_GetArraySize(monitor_list);
        g_app_lic.monitor_size = list_size;
        if (list_size > 0)
        {
            g_app_lic.monitor = malloc(sizeof(struct service) * list_size);
            for (i = 0; i < list_size; i++)
            {
                cJSON *param = cJSON_GetArrayItem(monitor_list, i);
                if (param != NULL && cJSON_IsObject(param))
                {
                    cJSON *func = cJSON_GetObjectItem(param, "func");
                    strcpy(g_app_lic.monitor[i].func, func->valuestring);

                    cJSON *nodes = cJSON_GetObjectItem(param, "nodes");
                    g_app_lic.monitor[i].nodes = nodes->valueint;
                }
            }
        }
    }

    cJSON *func_list = cJSON_GetObjectItem(root, "function");
    if (func_list != NULL && cJSON_IsArray(func_list))
    {
        list_size = cJSON_GetArraySize(func_list);
        g_app_lic.func_size = list_size;
        if (list_size > 0)
        {
            g_app_lic.func = malloc(sizeof(struct service) * list_size);
            for (i = 0; i < list_size; i++)
            {
                cJSON *param = cJSON_GetArrayItem(func_list, i);
                if (param != NULL && cJSON_IsObject(param))
                {
                    cJSON *func = cJSON_GetObjectItem(param, "func");
                    strcpy(g_app_lic.func[i].func, func->valuestring);

                    cJSON *allow = cJSON_GetObjectItem(param, "allow");
                    g_app_lic.func[i].allow = allow->valueint;
                }
            }
        }
    }
    print_app_license(&g_app_lic);
    // 释放资源
    cJSON_Delete(root);
    return LICENSE_SUCCESS;
}

int load_license_from_file(const char *zops_lic, char **enc_session_key, char **enc_license, char **sign)
{

    FILE *file = NULL;
#ifdef _WIN64
    fopen_s(&file, zops_lic, "r");
#else
    file = fopen(zops_lic, "r");
#endif

    if (!file)
        return (LICENSE_LOAD_ERROR);

    char buf[8] = {"\0"};
    int ilen = 0, flen = 0;
    if (fgets(buf, 5, file) != NULL)
    {
        flen = atoi(buf);
        if (flen <= 0 || flen > 2048)
        {
            return LICENSE_LOAD_ERROR;
        }
        reallocate(enc_session_key, flen + 1);
        fgets(*enc_session_key, flen + 1, file);
        (*enc_session_key)[flen] = 0;
        lic_printf("flen=%d,enc_session_key=%s\n", flen, *enc_session_key);
    }
    else
    {
        return LICENSE_LOAD_ERROR;
    }

    memset(buf, 0, 8);
    if (fgets(buf, 5, file) != NULL)
    {
        flen = atoi(buf);
        if (flen <= 0 || flen > 2048)
        {
            return LICENSE_LOAD_ERROR;
        }
        reallocate(enc_license, flen + 1);
        fgets(*enc_license, flen + 1, file);
        (*enc_license)[flen] = 0;
        lic_printf("flen=%d,enc_license=%s\n", flen, *enc_license);
    }
    else
    {
        return LICENSE_LOAD_ERROR;
    }

    memset(buf, 0, 8);
    if (fgets(buf, 5, file) != NULL)
    {
        flen = atoi(buf);
        if (flen <= 0 || flen > 2048)
        {
            return LICENSE_LOAD_ERROR;
        }
        reallocate(sign, flen + 1);
        fgets(*sign, flen + 1, file);
        (*sign)[flen] = 0;
        lic_printf("flen=%d,sign=%s\n", flen, *sign);
    }
    else
    {
        return LICENSE_LOAD_ERROR;
    }
    if (file)
        fclose(file);

    return flen;
}



int verify_sign(char *session_key, char *license_buffer, char *enc_sign)
{
    int i = 0;
    char *v_sign = NULL;

    int len = pub_decrypt(enc_sign, &v_sign, provider_publickey);
    v_sign[len] = 0;

    char *buffer = malloc(strlen(session_key) + strlen(license_buffer) + 128);
    if (buffer == NULL)
        return LICENSE_VERIFY_SIGN_FAIL;

    strcpy(buffer, session_key);
    strcat(buffer, "|ZOps|");
    strcat(buffer, license_buffer);
    lic_printf("sha_src=%s\n", buffer);

    unsigned char sha_buf[SHA256_DIGEST_SIZE];
    unsigned char sign[2 * SHA256_DIGEST_SIZE + 1];
    sha256((const unsigned char *)buffer, strlen(buffer), sha_buf);
    for (i = 0; i < (int)SHA256_DIGEST_SIZE; i++)
    {
        sprintf(sign + 2 * i, "%02x", sha_buf[i]);
    }
    if (buffer)
        free(buffer);

    lic_printf("sign=%s, v_sign=%s\n", sign, v_sign);
    if (strcmp(sign, v_sign) == 0)
    {
        lic_printf("verify_sign success.\n");
    }
    else
    {
        lic_printf("verify_sign fail.\n");
        return LICENSE_VERIFY_SIGN_FAIL;
    }
    unsigned char v_productkey[2 * SHA256_DIGEST_SIZE + 1];
    int ret = get_sha_hardware_info(v_productkey);
    lic_printf("verify_productkey. ret=%d, v_productkey=%s\n", ret, v_productkey);
    if (ret > 0 && strcmp(g_app_lic.productkey, v_productkey) == 0)
    {
        lic_printf("verify_productkey success.\n");
    }
    else
    {
        lic_printf("verify_productkey fail.\n");
        return LICENSE_VERYFY_PRODUCTKEY_FAIL;
    }

    return LICENSE_SUCCESS;
}

/**
 * cleanups then exists
 * @exit_code exit code
 */
void exit_license()
{

    if (customer_privatekey)
        RSA_free(customer_privatekey);
    if (provider_publickey)
        RSA_free(provider_publickey);

    if (g_app_lic.monitor)
        free(g_app_lic.monitor);
    if (g_app_lic.func)
        free(g_app_lic.func);

    crypto_final();

}

int init_license(char *zops_lic_file)
{
    if(g_license_init ==1){
        return g_result;
    }
    g_license_init = 1;

    int result = 0;
    char *session_key = NULL;
    char *enc_session_key = NULL;
    char *enc_license = NULL;
    unsigned char *license_buffer = NULL;
    char *enc_sign = NULL;
    char *dec_buffer = NULL;

    crypto_init(exit_license);

    lic_printf("loading customer privatekey...\n");
    load_custome_privatekey();

    lic_printf("loading provider publickey...\n");
    load_provider_publickey();

    g_result = LICENSE_SUCCESS;
    if ((result = load_license_from_file(zops_lic_file, &enc_session_key, &enc_license, &enc_sign)) < 0)
    {
        free_license(session_key, enc_session_key, enc_license,
                     license_buffer, enc_sign, dec_buffer);
        g_result = result;
        return g_result;
    }

    if ((result = pri_decrypt(enc_session_key, &session_key, customer_privatekey)) < 0)
    {
        free_license(session_key, enc_session_key, enc_license,
                     license_buffer, enc_sign, dec_buffer);
        g_result = LICENSE_DECRYPT_SESSION_KEY_ERROR;
        return g_result;
    }
    lic_printf("session_key=%s\n", session_key);

    int len = base64_decode(enc_license, strlen(enc_license), &dec_buffer);
    if (len < 0)
    {
        free_license(session_key, enc_session_key, enc_license,
                     license_buffer, enc_sign, dec_buffer);
        g_result = LICENSE_DEBASE64_ERROR;
        return g_result;
    }
    len = decrypt(dec_buffer, len, &license_buffer, session_key);
    if (len < 0)
    {
        free_license(session_key, enc_session_key, enc_license,
                     license_buffer, enc_sign, dec_buffer);
        g_result = LICENSE_DECRYPT_ERROR;
        return g_result;
    }
    license_buffer[len] = 0;
    lic_printf("license_buffer=%s\n", license_buffer);

    if ((result = parse_license_fromjson(license_buffer)) != LICENSE_SUCCESS)
    {
        free_license(session_key, enc_session_key, enc_license,
                     license_buffer, enc_sign, dec_buffer);
        g_result = result;
        return g_result;
    }

    if ((result = verify_sign(session_key, license_buffer, enc_sign)) != LICENSE_SUCCESS)
    {
        free_license(session_key, enc_session_key, enc_license,
                     license_buffer, enc_sign, dec_buffer);
        g_result = result;
        return g_result;
    }
    return g_result;
}

int verify_license(int v_nodes,long *lic_expired, short v_monitor_size, struct service *v_monitor,
    short v_func_size, struct service *v_func)
{
    if(g_license_init == 0){
        init_license(provider_lic);
        
        lic_printf("init license done, g_result=%d\n",  g_result);
    }

    if(g_result != LICENSE_SUCCESS){
        return g_result;
    }
    if(g_app_lic.nodes > 0 && v_nodes > g_app_lic.nodes){
        return LICENSE_OVER_NODES;
    }

    time_t now = time(0);
    if (lic_expired != NULL) {
        *lic_expired = g_lic_expired;
    }
    lic_printf("verify time, now=%lld,g_lic_expired=%lld\n",now,g_lic_expired);
    if(now > g_lic_expired){
        return LICENSE_EXPIRED;
    }

    int i = 0, j = 0;
    int find = 0;
    if(v_monitor_size > 0 && v_monitor != NULL)
    {
        
        for(i = 0; i < v_monitor_size; i ++)
        {
            find = 0;
            struct service *pm = &v_monitor[i];
            if(pm == NULL) continue;
            char *func = pm->func;
            int nodes = pm->nodes;
            for(j = 0; j < g_app_lic.monitor_size; j ++)
            {
                if(strcmp(g_app_lic.monitor[j].func, func) == 0)
                {
                    find = 1;
                    int lic_nodes = g_app_lic.monitor[j].nodes;
                    if(lic_nodes > 0 && nodes > lic_nodes){
                        pm->allow = 0;
                    }else{
                        pm->allow = 1;
                    }
                    
                }
            }
            if(find == 0 && j == g_app_lic.monitor_size){
                pm->allow = 0;
            }
        }
    }
    
    if(v_func_size > 0 && v_func != NULL)
    {
        for(i = 0; i < v_func_size; i ++)
        {
            find = 0;
            struct service *pf = &v_func[i];
            if(pf == NULL) continue;
            char *func = pf->func;
            for(j = 0; j < g_app_lic.func_size; j ++)
            {
                if(strcmp(g_app_lic.func[j].func, func) == 0)
                {
                    find = 1;
                    pf->allow = g_app_lic.func[j].allow;
                }
            }
            if(find == 0 && j == g_app_lic.func_size)
            {
                pf->allow = 0;
            }
        }
    }
    return LICENSE_SUCCESS;
}

int create_productkey(char *productkey)
{
    return get_sha_hardware_info(productkey);
}

int query_license(struct app_license **lic)
{
    int lic_len = sizeof(g_app_lic);
    reallocate(lic, lic_len + 1);
    if(*lic == NULL){
        return -1;
    }
    memcpy((void *)*lic, (const void *)&g_app_lic, lic_len);
    return 0;
}

// int get_lic_expired()
// {
//     return g_lic_expired;
// }

int LIC_IS_SUCCESS(void)
{
	return (g_result == LICENSE_SUCCESS && g_lic_expired > 0) ? time(NULL) <= g_lic_expired : 0;
}
 