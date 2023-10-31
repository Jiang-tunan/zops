#include "licprovider.h"


RSA *provider_privatekey = NULL;
RSA *customer_publickey = NULL;

int g_provider_init = 0;

#define load_customer_publickey_file() { \
	customer_publickey = get_pubkey(customer_pub_pem); \
}

#define load_customer_publickey_memory()                           \
    {                                                       \
        customer_publickey = get_zops_customer_publickey(); \
    }

RSA *get_zops_customer_publickey()
{
    BIO *bp = NULL;
    RSA *rc = NULL;
    char *chPublicKey = "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA8SfuvcaJ7zNI3UZmRI/ndFu/YDhnIv0oTbDa63rpG9O+6d3ccs72\
IUdACJ2MXq+aNUWFEPhk7+3Z1yYCUEojtqG2j2inYbADdOgjJSW0tOnx68eO4dbj\
VVp7yh84YkZi04ZTVCNP40qmiBReEbUzw3dU4yY7E2bKTEw1IhQD5Ru5bMCcAEpy\
cJ00MpULHp7TADZUt2H48I/eO8iQr5DjAgV3uimXmkW6ao5WVn4VS7imoBzlwKWj\
PPyL67Yo/o4rmkaZZAnfzEUvtDEhEQkmGisaWSxrexwdPsvwweq5kxgrXFFfVret\
H1lumzd+mJHb2aXVj+ECbmFznTeWQ2T3zwIDAQAB\n\
-----END RSA PUBLIC KEY-----";
    if ((bp = BIO_new_mem_buf(chPublicKey, -1)) == NULL)
    {
        lic_printf("BIO_new_mem_buf failed!\n");
        return NULL;
    }
    if (NULL == (rc = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL)))
    {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        lic_printf("load private key failed[%s]\n", errBuf);
        lic_printf("chPublicKey[%s]\n", chPublicKey);
    }
    BIO_free(bp);
    return rc;
}

// #define load_provider_privatekey_file() { \
// 	provider_privatekey = get_prikey_ex(provider_pem); \
// 	save_pubkey(provider_pub_pem, provider_privatekey); \
// }
#define load_provider_privatekey_file() { \
	provider_privatekey = get_prikey_ex(provider_pem); \
}
#define load_provider_privatekey_memory()                               \
    {                                                            \
        provider_privatekey = get_zops_provider_RSAPrivateKey(); \
    }

RSA *get_zops_provider_RSAPrivateKey()
{
    BIO *bp = NULL;
    char *chPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpQIBAAKCAQEAq1fqR/nyLUnfFq234nrfHFmy7neY/MHdFUNq0cI7yvq+gVP+\
uvI6//naRxLHp3S3BSS7boMn6gQFPwxAnrj6PLuu1QAXLSjq4e6m+D5B7Wr0XUsO\
1MnBk2CBlVDq1vMkIi5ggGCW/pROWj+1mKz6FZDw/C4FU7YZXzPuY14l3R+kPnlJ\
s9LtR4NCxXmlC8YY+Ts7Y5rJ/BokKAcVkrX8IW2aCjHTTBfpQVWuMo7YnIrBejv+\
gCxij2BkjqJRoGSAMtJLW9/TKbzV5Kv7nsZ+QIA27feVMGSOMQoKXA3BRazb47Xe\
Pv3yYqbZGAFUXhijBC+PFn7AXBTmIPYo+wP3qwIDAQABAoIBADj1XsJSinkXp3uI\
gCpfoi9wehTf2RGc+HuLD8VvBiVxuUaQv4sx3v8c9bzOt2QpXnXtQgl4vBoFACF3\
VzvsTfNGiNXx08KFaZ91kDfRqmTcOyOQQfvmndz6JdmXLpoJ9acPN7E1arxyXKGP\
sDRyvCfTKOkL+2VakZCeWM7bi0a4JJyJbE4PNARknrPnGvHzDSimJUUMLvaxUmnr\
gqUjE0KFriTLa+nnaiL4bSVk+ktltBjQzBpQFFii3h22hmmjAxDJXjNjf9LVIASO\
MBKUBMDoP31n1/qLOkP3S76ByIknWx7YV904OErnjNIExypNSsHM73QWKWHwNV0H\
eTyKcBECgYEA3BdQaXK57fTpQOsZEYb3oHcABzFudp9/TQijzQbjY9jrtCuE6lzB\
pM0bkTKeKoCyehw8ruUEducLO74Rhg2WY3Tj4GrPuO1Q409UKBkyTTyN8FvKRjyp\
SQa2DVn7fYQjPXq7sj58VOqWZQeDWa/Vm6rYIVxwoclBgYwiDJtqqecCgYEAx0yG\
wQDr2bOnlABtnAmQykv/lPvkOTHINVktsZbrJipeHv74q3yih1uXS3DEwoDmjM65\
AffX0fxV7RdMDWYWvyNztKgMO+jW/HUq1ltAfNHgdP197NpcAoBlJc8IMaAetUBB\
d3JGd86BByoQ91SxYOZUYdi6mhhpgQzpGCqhc50CgYEAlkypkklRpanxvG6QYQLN\
ilyZvU/JguKrGZ1D1xjUInSZiiGKFE4hw3x6Te7GSno25+LuofUt1lEzv6mt5+DR\
ibvifngSwNP3wDOFYhjK3Cn1OGZGvS5h4MfffUCs2Otq8WomUbQQTiEhcX7u+Ul1\
02eZTzcEh8ebn29mNTvRXJMCgYEAw+0rnJn3QvInEIzLNNcCjJ3iCOkJGGEkXa3q\
CehADCkiln46oPvKHB+iwPt/s2ddP5gKsTCh70GOh6KblaCDRCzqFvQN8ueYUmAt\
WMYkw5DghKKgJTUVty/aQC0j9QVgqvccZPzm4ekVV6G3RC7yojxNQFP8Pnk5XzD+\
BlACoNECgYEAuqAjJ2zpcAtHwJUBb4ZZTsAgBsY6L1fMl6HKD/jCYxKehA/xhBje\
9sfUMtcT7PQiXOhJYHd8j18NogwqscQUSWd9DgtTrKVvWQGsy4IpDnj87ocdElB6\
Cl619LpjrI/wVgiBQIO2xlskf1zlgoW3KdvF9UFDaZ8jxpmG8uxYmMs=\n\
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

char *get_nowdate(char *timestr)
{
    time_t now;
    struct tm *p;
    now = time(0);
    p = gmtime(&now); // 无时区信息
    strftime(timestr, 128, "%Y-%m-%d", p);

    return timestr;
}

struct app_license *init_app_license(const char *company, const char *version, const char *lic_expired,
                                     const char *productkey, int nodes, int monitor_size, struct service *monitor,
                                     int func_size, struct service *func)
{

    struct app_license *lic = malloc(sizeof(struct app_license));

    strcpy(lic->company, company);
    strcpy(lic->version, version);

    char timestr[128] = "";
    get_nowdate(timestr);
    strcpy(lic->lic_begin, timestr);

    strcpy(lic->lic_expired, lic_expired);
    strcpy(lic->productkey, productkey);
    lic->nodes = nodes;

    lic->monitor_size = monitor_size;
    lic->monitor = monitor;

    lic->func_size = func_size;
    lic->func = func;
    return lic;
}

int get_lic_size(struct app_license *lic)
{
    int len = 0;
    char buf[8] = {"\0"};
    char *license_json = "{'company':'','version':'','lic_begin':'','lic_expired':'','productkey':'','nodes':,'monitor':[],'function':[]}";
    char *monitor_json = "{'func':'','nodes':},";
    char *func_json = "{'func':'','allow':},";

    len += strlen(lic->company);
    len += strlen(lic->version);
    len += strlen(lic->lic_begin);
    len += strlen(lic->lic_expired);
    len += strlen(lic->productkey);
    sprintf(buf, "%d", lic->nodes);
    len += strlen(buf);
    int i = 0;
    for (i = 0; i < lic->monitor_size; i++)
    {
        len += strlen(lic->monitor[i].func);
        sprintf(buf, "%d", lic->monitor[i].nodes);
        len += strlen(buf);
    }

    for (i = 0; i < lic->func_size; i++)
    {
        len += strlen(lic->func[i].func);
        sprintf(buf, "%d", lic->func[i].allow);
        len += strlen(buf);
    }

    len += len + strlen(license_json) +
           lic->monitor_size * strlen(monitor_json) +
           lic->func_size * strlen(func_json);
    lic_printf("json_len=%d\n", len);
    return len;
}

void make_json_string(struct app_license *lic, char **json_buf)
{
    int pos = 0, i = 0;
    int slen = 0;

    slen = get_lic_size(lic);

    reallocate(json_buf, slen);

    sprintf(*json_buf,
            "{\"company\":\"%s\",\"version\":\"%s\",\"lic_begin\":\"%s\",\"lic_expired\":\"%s\",\"productkey\":\"%s\",\"nodes\":%d",
            lic->company, lic->version, lic->lic_begin, lic->lic_expired, lic->productkey, lic->nodes);

    if (lic->monitor_size > 0)
    {
        pos = strlen(*json_buf);
        sprintf(*json_buf + pos, ",\"monitor\":[");
        int i, pos = strlen(*json_buf);
        for (i = 0; i < lic->monitor_size; i++)
        {
            sprintf(*json_buf + pos, "{\"func\":\"%s\",\"nodes\":%d}", lic->monitor[i].func, lic->monitor[i].nodes);
            pos = strlen(*json_buf);
            if (i < lic->monitor_size - 1)
                sprintf(*json_buf + pos++, ",");
        }

        pos = strlen(*json_buf);
        sprintf(*json_buf + pos, "]");
    }
    if (lic->func_size > 0)
    {
        pos = strlen(*json_buf);
        sprintf(*json_buf + pos, ",\"function\":[");
        pos = strlen(*json_buf);
        for (i = 0; i < lic->func_size; i++)
        {
            sprintf(*json_buf + pos, "{\"func\":\"%s\",\"allow\":%d}", lic->func[i].func, lic->func[i].allow);
            pos = strlen(*json_buf);
            if (i < lic->func_size - 1)
                sprintf(*json_buf + pos++, ",");
        }

        pos = strlen(*json_buf);
        sprintf(*json_buf + pos, "]");
    }
    pos = strlen(*json_buf);
    sprintf(*json_buf + pos, "}");
}

int make_session(char **session_key, char **enc_session_key)
{
    gen_session_key(16, session_key);
    lic_printf("session_key=%s\n", *session_key);
    return pub_encrypt(strlen(*session_key), *session_key, enc_session_key, customer_publickey);
}

void write_licese(const char *company, char *enc_session_key, char *enc_license, char *sign)
{
    // char *buffer = malloc(strlen(enc_session_key)+strlen(license_buffer)+1);
 
    char file_path[256] = {"zops_"};
      
    strcat(file_path, company);
    strcat(file_path, ".lic");
    lic_printf("file_path=%s\n", file_path);

    FILE *lic_file = fopen(file_path, "w");

    char buf[8] = {"\0"};
    sprintf(buf, "%04d", strlen(enc_session_key));
    fputs(buf, lic_file);
    fputs(enc_session_key, lic_file);

    memset(buf, 0, 8);
    sprintf(buf, "%04d", strlen(enc_license));
    fputs(buf, lic_file);
    fputs(enc_license, lic_file);

    memset(buf, 0, 8);
    sprintf(buf, "%04d", strlen(sign));
    fputs(buf, lic_file);
    fputs(sign, lic_file);

    if (lic_file)
        fclose(lic_file);

    return;
}

void make_license(char *session_key, char **license_buffer, char **enc_license, struct app_license *lic)
{
    int i = 0;
    make_json_string(lic, license_buffer);
    unsigned char *tmp_enc_license = NULL;

    int elen = encrypt(*license_buffer, strlen(*license_buffer), &tmp_enc_license, session_key);
    base64_encode(tmp_enc_license, elen, enc_license);
    free(tmp_enc_license);
}

void make_sign(char *session_key, char *license_buffer, char **enc_sign)
{
    char *buffer = malloc(strlen(session_key) + strlen(license_buffer) + 128);
    if (buffer == NULL)
        exit(1);

    strcpy(buffer, session_key);
    strcat(buffer, "|ZOps|");
    strcat(buffer, license_buffer);
    lic_printf("sha_src=%s\n", buffer);

    unsigned char sha_buf[SHA256_DIGEST_SIZE];
    unsigned char sign[2 * SHA256_DIGEST_SIZE + 1];

    sha256((const unsigned char *)buffer, strlen(buffer), sha_buf);

    for (int i = 0; i < (int)SHA256_DIGEST_SIZE; i++)
    {
        sprintf(sign + 2 * i, "%02x", sha_buf[i]);
    }
    lic_printf("sign=%s\n", sign);
    pri_encrypt(strlen(sign), sign, enc_sign, provider_privatekey);
    lic_printf("en_sign=%s\n", *enc_sign);
    free(buffer);
}

char *create_license(const char *company, const char *version, const char *lic_expired,
                     const char *productkey, int nodes, int monitor_size, struct service *monitor,
                     int func_size, struct service *func)
{
    char *session_key = NULL;
    char *enc_session_key = NULL;
    char *license_buffer = NULL;
    char *enc_license = NULL;
    char *enc_sign = NULL;

    struct app_license *lic = NULL;
    lic_printf("(1/6) loading init_app_license...\n");
    lic = init_app_license(company, version, lic_expired, productkey, nodes,
                           monitor_size, monitor, func_size, func);
    print_app_license(lic);

    lic_printf("(2/6) loading make_session...\n");
    make_session(&session_key, &enc_session_key);

    lic_printf("(3/6) loading make_license...\n");
    make_license(session_key, &license_buffer, &enc_license, lic);

    lic_printf("(4/6) loading make_sign...\n");
    make_sign(session_key, license_buffer, &enc_sign);

    lic_printf("(5/6) loading write_license...\n");
    write_licese(company, enc_session_key, enc_license, enc_sign);

    lic_printf("(6/6) loading free license...\n");
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

    if (lic)
    {
        if (lic->monitor)
            free(lic->monitor);
        if (lic->func)
            free(lic->func);
        free(lic);
    }
}

void create_license_from_argv(int argc, const char *argv[])
{
    int i = 0;
    int monitor_size = 0;
    struct service *monitor = NULL;

    int func_size = 0;
    struct service *func = NULL;

    char *p = NULL;
    

    int nodes = atoi(argv[6]);

    //分割后子字符串的个数
    int num = 50;
    char *tokens[50] = {0};

    if (argc > 8)
    {
        monitor_size = atoi(argv[7]);
        monitor = malloc(sizeof(struct service) * monitor_size);
        memset(monitor, 0, sizeof(struct service) * monitor_size);
        // lic_printf("monitor_size=%d\n", monitor_size);
        p = NULL;
        
        split((char *)argv[8], "#", tokens, &num);
        //tokens = split(argv[7], '#');
        if (num > 0)
        {
            for (i = 0; i < num; i ++)
            {

                p = strstr(tokens[i], ":");
                // lic_printf("i=%d,tokens=%s,p=%s\n", i, tokens[i], p + 1);
                if (p)
                {
                    strncpy(monitor[i].func, tokens[i], p - tokens[i]);
                    monitor[i].nodes = atoi(p + 1);
                }
                else
                {
                    strcpy(monitor[i].func, tokens[i]);
                    monitor[i].nodes = 0;
                }
                // free(tokens[i]);
                //free(*(tokens + i));
            }
            //free(tokens);
        }
    }

    if (argc > 10)
    {
        func_size = atoi(argv[9]);
        // lic_printf("func_size=%d\n", func_size);
        func = malloc(sizeof(struct service) * func_size);
        memset(func, 0, sizeof(struct service) * func_size);
        //tokens = split(argv[9], '#');
        num = 50;
        split((char *)argv[10], "#", tokens, &num);
        if (num > 0)
        {
            for (i = 0; i < num; i++)
            {

                p = strstr(tokens[i], ":");
                // lic_printf("i=%d,tokens=%s,p=%s\n", i, tokens[i], p + 1);
                if (p)
                {
                    strncpy(func[i].func, tokens[i], p - tokens[i]);
                    func[i].allow = atoi(p + 1);
                }
                else
                {
                    strcpy(func[i].func, tokens[i]);
                    func[i].allow = 0;
                }
            }
        }
    }

    create_license(argv[2], argv[3], argv[4], argv[5], nodes, monitor_size, monitor, func_size, func);
}




void exit_provider(int exit_code)
{

    if (customer_publickey)
        RSA_free(customer_publickey);
    if (provider_privatekey)
        RSA_free(provider_privatekey);

    crypto_final();

    lic_printf("program terminated with code (%d).\n", exit_code);

    exit(exit_code);
}

/**
 * 初始化
 * flag：0 - 从内存读, 1:从文件读
*/
void init_provider(int flag)
{
    if(g_provider_init == 1)
        return;
    g_provider_init = 1;
    
    crypto_init(exit_provider);

    
    if(flag)
    {   //文件
        lic_printf("loading provider_privatekey from file...\n");
        load_provider_privatekey_file();

        lic_printf("loading customer_publickey from file...\n");
        load_customer_publickey_file();
        
    }else
    { 
        lic_printf("loading provider_privatekey from memory...\n");
        load_provider_privatekey_memory();

        lic_printf("loading customer_publickey from memory...\n");
        load_customer_publickey_memory();
    }
        

    
    
}