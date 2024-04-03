#include "license.h"
#include "ossllib.h"
#include "md5.h"

const char *customer_pem = "customer.pem";
const char *customer_pub_pem = "customer-pub.pem";
const char *provider_pem = "provider.pem";
const char *provider_pub_pem = "provider-pub.pem";
 
void (*onerror)(int) = NULL;

void exit_on_error(const char *fname, const char *fn_name, int line, int error)
{
    lic_printf("vvv program is stopped on error: %d vvv\n(%s:%d::%s)\n",
           error, fname, line, fn_name);

    if (onerror)
        onerror(error);
}

int load_from_file(const char *fname, char **outb)
{

    if (!outb)
        return ERDFILE;

    FILE *file = NULL;
#ifdef _WIN64
    fopen_s(&file, fname, "r");
#else
    file = fopen(fname, "r");
#endif

    if (!file)
        return ERDFILE;

    if (fseek(file, 0, SEEK_END))
    {
        fclose(file);
        return ERDFILE;
    }

    int flen = ftell(file);
    rewind(file);

    reallocate(outb, flen + 1);
    fread(*outb, flen, 1, file);
    fclose(file);

    (*outb)[flen] = 0;

    return flen;
}

void print_app_license(struct app_license *p)
{
    if(p == NULL)
    {
        lic_printf("license is NULL!\n");
        return;
    }

    lic_printf("[app_license]:company=%s,version=%s,lic_begin=%s,lic_expired=%s,productkey=%s,nodes=%d\n",
           (p)->company, (p)->version, (p)->lic_begin, (p)->lic_expired, (p)->productkey, (p)->nodes);
    lic_printf("monitor_size=%d[", (p)->monitor_size);
    for (int i = 0; i < (p)->monitor_size; i++)
    {
        lic_printf("{func=%s,nodes=%d},", (p)->monitor[i].func, (p)->monitor[i].nodes);
    }
    lic_printf("]\nfunc_size=%d[", (p)->func_size);
    for (int i = 0; i < (p)->func_size; i++)
    {
        lic_printf("{func=%s,allow=%d},", (p)->func[i].func, (p)->func[i].allow);
    }
    lic_printf("]\n");
    return;
}

void split(char *src, const char *separator, char **dest, int *num)
{
    char *pNext;
    int count = 0;
    if (src == NULL || strlen(src) == 0)
        return;
    if (separator == NULL || strlen(separator) == 0)
        return;
    pNext = strtok(src, separator);
    while (pNext != NULL && count < *num)
    {
        *dest++ = pNext;
        ++count;
        pNext = strtok(NULL, separator);
    }
    *num = count;
}

char *trim(char *str)
{
    char *p = str;
    char *p1;
    if (p)
    {
        p1 = p + strlen(str) - 1;
        while (*p && isspace(*p))
            p++;
        while (p1 > p && isspace(*p1))
            *p1-- = '\0';
    }
    return p;
}


int grandom = 0;
char pwdcont[]="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+";
char spwdcont[] = "~!@#$%^&*()_+";

int matches(int type, char *pwd)
{
    int pw_len = strlen(pwd);
    int slen = strlen(spwdcont);
    for(int i = 0; i < pw_len; i++)
    {
        if(type == 1 && pwd[i] >= 0x30 && pwd[i] <= 0x39)
        {
            return 1;
        }
        else if(type == 2 && pwd[i] >= 0x41 && pwd[i] <= 0x5A)
        {
            return 1;
        }
        else if(type == 3 && pwd[i] >= 0x61 && pwd[i] <= 0x7A)
        {
            return 1;
        }
        else if(type == 4){
            for(int k=0; k < slen; k ++)
            {
                if(pwd[i] == spwdcont[k])
                    return 1;
            }
        }
    }
    return 0;
}


char* join(char *s1, char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);
    if (result == NULL) exit (1);

    strcpy(result, s1);
    strcat(result, s2);

    return result;
}

char* generate_pwd(int pwd_size)
{
	int i; 
	int random;
	char *password = (char *)malloc(pwd_size + 1);
	grandom++;
	srand((unsigned)time(NULL)+grandom);
	for(i = 0;i < pwd_size; i++)
	{
        random = rand()%(strlen(pwdcont));
		*(password + i) = pwdcont[random]; 
	}
	
	*(password + i)= '\0'; 
    if(!(matches(1,password) && matches(2,password) && matches(3,password) && matches(4,password)))
	{
        free(password);
        generate_pwd(pwd_size);
    }else{
        return password;
    }
} 

int create_key(unsigned char **key)
{
    unsigned char productkey[2 * SHA256_DIGEST_SIZE + 1];
    create_productkey(productkey);
    char* skey = join("tognixUn18*qR9", productkey);
    skey = join(skey, "bzyl6EpMn$8");
    char *target = NULL;
    char *b64key = base64_encode(skey, strlen(skey), &target);
 
    
    unsigned char crypt_key[16]={0};    //存放结果  
    MD5_CTX md5c; 
    MD5Init(&md5c); //初始化
    MD5Update(&md5c,(unsigned char *)b64key,strlen(b64key));  
    MD5Final(&md5c,crypt_key);  
    *key = (char *)malloc(16);
    memcpy(*key, crypt_key, 16);
    return 16;
}

int lic_encrypt_pwd(char *pwd, char **out_enpwd)
{
    if(pwd == NULL){
        pwd = generate_pwd(8);
    }

    unsigned char *crypt_key=NULL; 
    create_key(&crypt_key); 

	unsigned long outlen,inlen;
	unsigned char out_data[128];
	outlen = AES128_CBC_Encrypt(pwd,strlen(pwd),crypt_key,out_data);

    base64_encode(out_data, outlen, out_enpwd);
    return strlen(*out_enpwd);
}

int lic_decrypt_pwd(char *b64pwd, char **out_depwd)
{
    unsigned char *crypt_key=NULL;
    create_key(&crypt_key); 
    
    char *dpw_target = NULL;
    *out_depwd = malloc(strlen(b64pwd)+1);
    int b64_len = base64_decode(b64pwd, strlen(b64pwd), &dpw_target);
	int outlen = AES128_CBC_Decrypt(dpw_target,b64_len,crypt_key,*out_depwd);
    
    free(dpw_target);
    return outlen;
}
