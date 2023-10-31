#ifndef _LICENSE_H
#define _LICENSE_H


#define LICENSE_SUCCESS  					0		// license校验成功
#define LICENSE_LOAD_ERROR 					1101	// 加载license许可错误
#define LICENSE_DECRYPT_SESSION_KEY_ERROR 	1102	// session key解密失败
#define LICENSE_DEBASE64_ERROR 				1103	// base64 解码失败
#define LICENSE_DECRYPT_ERROR 				1104	// license 解密失败
#define LICENSE_PARSE_JSON_ERROR 			1105	// licese json 解析失败
#define LICENSE_VERIFY_SIGN_FAIL			1106	// 校验签名失败	
#define LICENSE_VERYFY_PRODUCTKEY_FAIL  	1107	// 校验productkey 失败
#define LICENSE_OVER_NODES  				1108	// 节点数超出
#define LICENSE_EXPIRED  					1109	// license过期

struct service
{
	char func[64];		// 名称
	int nodes;			// 节点数
	int allow;			// 是否允许, 0:不允许，1：允许
};

struct app_license
{
	char company[128];		//公司名称
	char version[16];		//zops的版本，目前不校验
	char lic_begin[24];		//license开始时间
	char lic_expired[24];	//license过期时间，时间为当天的23:59:59
	char productkey[128];	//产品key
	int nodes;				//节点数，就是主机数量+虚拟机数量+应用数量

	short monitor_size;		//monitor的size
	struct service *monitor;//监控列表，用来判断某个监控节点是否超标

	short func_size;		//func的size
	struct service *func;	//功能列表，用来判断某个功能是否允许使用
};

void print_app_license(struct app_license *p);

/**
 * 创建本服务器产品key,每台服务器都是唯一
 * productkey：生成的产品key
	返回： > 0 表示成功, <=0 表示失败
	用法：
    unsigned char productkey[2 * SHA256_DIGEST_SIZE + 1];
	create_productkey(productkey);
*/
int create_productkey(char *productkey);

/***
 * 初始化license服务
 * zops_lic：license 文件路径，如："zops_irigud.lic"
 * 返回：LICENSE_SUCCESS:成功，其他：失败看 LICENSE_XXX 定义
 * 用法：
 * char *lic_file = "zops_irigud.lic";
	init_license(lic_file);
*/
int init_license(char *zops_lic);

/***
 * 校验license 是否合法性，包括节点数是否超标，许可日期是否过期，某个功能是否允许。
 * 输出 allow：0:拒绝，1:允许
 * v_nodes：总节点数
 * lic_expired: 许可过期时间，这个参数是输出的，不是输入的。单位时间戳
 * v_monitor_size: 监控v_monitor的size
 * v_monitor：监控项，用来判断某个监控功能节点数是否超标(如：数据库监控的节点数是否超标),
 *            输出allow值，根据allow来判断是否允许。
 * v_func_size: 功能v_func的size
 * v_func：功能项，用来判断某个功能是否允许（如：短信功能是否允许）。
 *            输出allow值，根据allow来判断是否允许。
 * 返回: LICENSE_SUCCESS：合法，但是具体的某个监控项和功能项要根据该项的allow值判断是否允许使用。其他：不合法
 * 用法：
 *  long lic_expired = 0;
	int ret = verify_license(36, &lic_expired, 0, NULL, 0, NULL);
	if(ret != LICENSE_SUCCESS){
		exit_license();
		exit(0);
	}
*/
int verify_license(int v_nodes,long *lic_expired, short v_monitor_size, struct service *v_monitor,
    short v_func_size, struct service *v_func);


/**
 * 查询软件许可
 * 用完记得释放内存，否则会导致内存泄露，切记！
 * 返回：0:成功，其他:失败
 * 用法:
 *  struct app_license *lic = NULL;
    int result = query_license(&lic);
	if(lic) free(lic);
*/
int query_license(struct app_license **lic);

// /**
//  * 获取许可过期时间
//  * 返回：成功：返回时间戳，1970年以来的秒数，失败:0
// */
// int get_lic_expired();

/**
 * 判断软件许可是否是正常的(许可没有问题并且没有过期)
 * 返回：1:正常， 0:异常 
 * */
int LIC_IS_SUCCESS(void);

/**
 * 退出license服务
*/
void exit_license();

/***
 * AES CBC 加密
 * input_buff 被加密的内容
 * input_len  被加密内容的长度
 * p_key  密钥，必须是16位长度
 * output_buff 加密后的内容
 * 返回：加密后内容的长度
 * 例子：
 *  unsigned long outlen;
 * 	unsigned char in[]={"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF66"};//5*16+2 = 82
 * 	unsigned char out_data[96];
 * 	unsigned char in_data[96];
 * 	outlen=AES128_CBC_Encrypt(in,strlen(in),"qwertyuiopasdfgh",out_data);
*/
unsigned long AES128_CBC_Encrypt(unsigned char * input_buff,unsigned long input_len,unsigned char * p_key,unsigned char * output_buff);

/***
 * AES CBC 解密
 * input_buff 加密后的内容
 * input_len  加密后内容的长度
 * p_key  密钥，必须是16位长度
 * output_buff 解密后的内容
 * 返回：解密后内容的长度
*/
unsigned long AES128_CBC_Decrypt(unsigned char * input_buff,unsigned long input_len,unsigned char * p_key,unsigned char * output_buff);

char* generate_pwd(int pwd_size);

int create_key(unsigned char **key);

int lic_encrypt_pwd(char *pwd, char **out_enpwd);

int lic_decrypt_pwd(char *b64pwd, char **out_depwd);
#endif //_LICENSE_H
