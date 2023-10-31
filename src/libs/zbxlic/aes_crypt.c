#include <stdio.h>
#include <stdlib.h>
#include <string.h> 

unsigned char FA(unsigned char b);
unsigned char FB(unsigned char b);
unsigned char FC(unsigned char b);
unsigned char FD(unsigned char b);
unsigned char FE(unsigned char b);
unsigned char Ff(unsigned char b);
void Cipher(unsigned char* input, unsigned char* output,unsigned char* w);//加密 
void InvCipher(unsigned char* input, unsigned char* output,unsigned char* w);//解密 

static unsigned char AesSbox[16*16]=
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
 
static unsigned char AesiSbox[16*16]=
{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
static unsigned char AesRcon[11*4]=
{
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x1b, 0x00, 0x00, 0x00,
    0x36, 0x00, 0x00, 0x00
};


unsigned char  FA(unsigned char b){if (b < 0x80) return (b <<1);else return ( (b << 1) ^ (0x1b) );}
unsigned char  FB(unsigned char b){return  FA(b) ^ b ;}
unsigned char  FC(unsigned char b){return  FA(FA(FA(b))) ^ b ;}
unsigned char  FD(unsigned char b){return  FA(FA(FA(b))) ^ FA(b) ^ b ;}
unsigned char  FE(unsigned char b){return  FA(FA(FA(b))) ^ FA(FA(b)) ^ b;}
unsigned char  Ff(unsigned char b){return  FA(FA(FA(b))) ^ FA(FA(b)) ^ FA(b);}

void  Cipher(unsigned char* input, unsigned char* output,unsigned char* exp_key)
{
	int i,j;
	int round ;
	unsigned char ttt[4*4];
	unsigned char State[4][4];
	for(i=0;i<16;i++)  State[i%4][i/4]=input[i];
	for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=State[i][j]^exp_key[4*j+i];  
	for (round = 1; round <= 9; round++)
	{
		for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=AesSbox[State[i][j]];
		for(j=0;j<4;j++)for(i=0;i<4;i++)ttt[4*i+j]=State[i][j];
		for(i=1;i<4;i++)for(j=0;j<4;j++)
		{if(i==1)State[i][j]=ttt[4*i+(j+1)%4];else if(i==2)State[i][j]=ttt[4*i+(j+2)%4];else if(i==3)State[i][j]=ttt[4*i+(j+3)%4];}
		for(j=0;j<4;j++)  for(i=0;i<4;i++)	ttt[4*i+j]=State[i][j];
		for(j=0;j<4;j++)
		{
			State[0][j] = FA(ttt[0+j]) ^ FB(ttt[4*1+j]) ^ ttt[4*2+j] ^ ttt[4*3+j];
			State[1][j] = ttt[0+j] ^ FA(ttt[4*1+j]) ^ FB(ttt[4*2+j]) ^ ttt[4*3+j];
			State[2][j] = ttt[0+j] ^ ttt[4*1+j] ^ FA(ttt[4*2+j]) ^ FB(ttt[4*3+j]);
			State[3][j] = FB(ttt[0+j]) ^ ttt[4*1+j] ^ ttt[4*2+j] ^ FA(ttt[4*3+j]);
		}	
		for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=State[i][j]^exp_key[4*((round*4)+j)+i];  
	}
	for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=AesSbox[State[i][j]];
	for(j=0;j<4;j++)for(i=0;i<4;i++)ttt[4*i+j]=State[i][j];
	for(i=1;i<4;i++)for(j=0;j<4;j++)
	{if(i==1)State[i][j]=ttt[4*i+(j+1)%4];else if(i==2)State[i][j]=ttt[4*i+(j+2)%4];else if(i==3)State[i][j]=ttt[4*i+(j+3)%4];}
	for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=State[i][j]^exp_key[4*(40+j)+i];  
	for ( i = 0; i < 16; i++)output[i] =  State[i%4][i/4];
}
 
//Aes解密函数
void  InvCipher(unsigned char* input,unsigned char* output,unsigned char* exp_key)
{
	int round;
	int i,j;
	unsigned char ttt[4*4];
	unsigned char State[4][4];
	for ( i = 0; i < 16; i++)State[i % 4][ i / 4] = input[i];
	for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=State[i][j]^exp_key[4*(40+j)+i];  
	for (round = 9; round >= 1; round--)
	{
		for(j=0;j<4;j++)for(i=0;i<4;i++)ttt[4*i+j]=State[i][j];
		for(i=1;i<4;i++)for(j=0;j<4;j++)
		{if(i==1)State[i][j]=ttt[4*i+(j+3)%4];else if(i==2)State[i][j]=ttt[4*i+(j+2)%4];else if(i==3)State[i][j]=ttt[4*i+(j+1)%4];}
		for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=AesiSbox[State[i][j]]; 
		for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=State[i][j]^exp_key[4*((round*4)+j)+i];
		for (i = 0; i < 4; i++)for (j = 0; j < 4; j++) ttt[4*i+j] =  State[i][j];
		for (j = 0; j < 4; j++)
		{
			State[0][j] = Ff(ttt[j]) ^ FD(ttt[4+j]) ^ FE(ttt[4*2+j]) ^ FC(ttt[4*3+j]);
			State[1][j] = FC(ttt[j]) ^ Ff(ttt[4+j]) ^ FD(ttt[4*2+j]) ^ FE(ttt[4*3+j]);
			State[2][j] = FE(ttt[j]) ^ FC(ttt[4+j]) ^ Ff(ttt[4*2+j]) ^ FD(ttt[4*3+j]);
			State[3][j] = FD(ttt[j]) ^ FE(ttt[4+j]) ^ FC(ttt[4*2+j]) ^ Ff(ttt[4*3+j]);
		}
	}
	for(j=0;j<4;j++)for(i=0;i<4;i++)ttt[4*i+j]=State[i][j];
	for(i=1;i<4;i++)for(j=0;j<4;j++)
	{if(i==1)State[i][j]=ttt[4*i+(j+3)%4];else if(i==2)State[i][j]=ttt[4*i+(j+2)%4];else if(i==3)State[i][j]=ttt[4*i+(j+1)%4];}
	for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]=AesiSbox[State[i][j]]; 
	for(j=0;j<4;j++)for(i=0;i<4;i++)State[i][j]= State[i][j] ^ exp_key[4*j+i]; 
	for ( i = 0; i < 16; i++)output[i] =  State[i%4][i/4];
}

/*****************************************************
*函数功能: AES加密, 模式CBC,数据块128位,填充方式:pkcs5padding
* 参数:
* input_buff:需要加密的数组指针
* input_len:加密数据的字节长度
* p_key:   指向密钥数据的指针,  1~16字节长度 
* output_buff:加密结果输出指针 
*
* 返回值: OutLength 加密后的输出长度 
*********************************************************/ 
unsigned long AES128_CBC_Encrypt(unsigned char * input_buff,unsigned long input_len,unsigned char * p_key,unsigned char * output_buff)
{
    unsigned long OutLength=0;
    long i,j;
    unsigned char *lpCurInBuff=input_buff;
    unsigned char *lpCurOutBuff=output_buff;
    long blocknum=input_len/16;
    long leftnum=input_len%16;
    unsigned char iv[20] = "1234567890ABCDEF";//偏移量 
	int row;
	unsigned char temp[4];
	unsigned char ex_key[16*15];
	for( row=0;row<4;row++)       //拷贝seed 密钥
	{
		ex_key[4*row+0] =  *(p_key+4*row);
		ex_key[4*row+1] =  *(p_key+4*row+1);
		ex_key[4*row+2] =  *(p_key+4*row+2);
		ex_key[4*row+3] =  *(p_key+4*row+3);
	}
	for( row=4;row<44;row++)
	{
		temp[0]=ex_key[4*row-4];     //当前列的前一列  
		temp[1]=ex_key[4*row-3];
		temp[2]=ex_key[4*row-2];
		temp[3]=ex_key[4*row-1];
		if(row%4==0)
		{
			unsigned char exchange_buff=0;
			exchange_buff = temp[0];
			temp[0] = AesSbox[16*(temp[1] >> 4)+(temp[1] & 0x0f)];
			temp[1] = AesSbox[16*(temp[2] >> 4)+(temp[2] & 0x0f)];
			temp[2] = AesSbox[16*(temp[3] >> 4)+(temp[3] & 0x0f)];
			temp[3] = AesSbox[16*(exchange_buff >> 4)+(exchange_buff & 0x0f)];
			
			temp[0] = temp[0] ^ AesRcon[4*(row/4)+0] ;   
			temp[1] = temp[1] ^ AesRcon[4*(row/4)+1] ;
			temp[2] = temp[2] ^ AesRcon[4*(row/4)+2] ;
			temp[3] = temp[3] ^ AesRcon[4*(row/4)+3] ;	
		}
		ex_key[4*row+0] = ex_key[4*(row-4)+0] ^ temp[0] ;
		ex_key[4*row+1] = ex_key[4*(row-4)+1] ^ temp[1] ;
		ex_key[4*row+2] = ex_key[4*(row-4)+2] ^ temp[2] ;
		ex_key[4*row+3] = ex_key[4*(row-4)+3] ^ temp[3] ;
	}  
    for( i=0;i<blocknum;i++)
    {
        for(j = 0; j < 16; j++ )lpCurOutBuff[j] = lpCurInBuff[j] ^ iv[j] ;
        Cipher(lpCurOutBuff,lpCurOutBuff,ex_key);
        memcpy(iv, lpCurOutBuff, 16 );
        lpCurInBuff+=16;
        lpCurOutBuff+=16;
        OutLength+=16;
    }
    if(leftnum)
    {
        unsigned char inbuff[16];
        memset(inbuff,16-leftnum,16);
        memcpy(inbuff,lpCurInBuff,leftnum);
        for(j = 0; j < 16; j++ )lpCurOutBuff[j] = inbuff[j] ^ iv[j];
        Cipher(lpCurOutBuff,lpCurOutBuff,ex_key);
        memcpy(iv, lpCurOutBuff, 16 );
        lpCurOutBuff+=16;
        OutLength+=16;
    }
    else
    {
        unsigned char extrabuff[16];
        memset(extrabuff,16,16);
        for(j = 0; j < 16; j++ )lpCurOutBuff[j] = extrabuff[j] ^ iv[j];
        Cipher(lpCurOutBuff,lpCurOutBuff,ex_key);
        memcpy(iv, lpCurOutBuff, 16 );
        OutLength+=16;
    }
    return OutLength;
}
 
 
/*******************************************************
*函数功能: AES解密, 模式CBC,数据块128位,填充方式:pkcs5padding
* 参数:
* input_buff:需要解密的数组指针
* input_len:需要解密数据的字节长度
* p_key:   指向密钥数据的指针,  1~16字节长度 
* output_buff:加密结果输出指针 
*
* 返回值: OutLength 加密后的输出长度 
********************************************************/
unsigned long AES128_CBC_Decrypt(unsigned char * input_buff,unsigned long input_len,unsigned char * p_key,unsigned char * output_buff)
{
	unsigned long OutLength=0;
	long blocknum=input_len/16;
	long leftnum=input_len%16;
	long i,j;
	unsigned char temp[16];
	unsigned char iv[20] = "1234567890ABCDEF";
	unsigned char *pCurInBuf=input_buff;
	unsigned char *pCurOutBuf=output_buff;
	int row;
    if(leftnum)
    {return 0;}
    unsigned char ex_key[16*15];
	for( row=0;row<4;row++)
	{
		ex_key[4*row+0] =  *(p_key+4*row);
		ex_key[4*row+1] =  *(p_key+4*row+1);
		ex_key[4*row+2] =  *(p_key+4*row+2);
		ex_key[4*row+3] =  *(p_key+4*row+3);
	}
	for( row=4;row<44;row++)
	{
		temp[0]=ex_key[4*row-4];     //当前列的前一列  
		temp[1]=ex_key[4*row-3];
		temp[2]=ex_key[4*row-2];
		temp[3]=ex_key[4*row-1];
		if(row%4==0) 
		{
			unsigned char exchange_buff=0;
			exchange_buff = temp[0];
			temp[0] = AesSbox[16*(temp[1] >> 4)+(temp[1] & 0x0f)];
			temp[1] = AesSbox[16*(temp[2] >> 4)+(temp[2] & 0x0f)];
			temp[2] = AesSbox[16*(temp[3] >> 4)+(temp[3] & 0x0f)];
			temp[3] = AesSbox[16*(exchange_buff >> 4)+(exchange_buff & 0x0f)];
			temp[0] = temp[0] ^ AesRcon[4*(row/4)+0] ;   
			temp[1] = temp[1] ^ AesRcon[4*(row/4)+1] ;
			temp[2] = temp[2] ^ AesRcon[4*(row/4)+2] ;
			temp[3] = temp[3] ^ AesRcon[4*(row/4)+3] ;	
		}
		ex_key[4*row+0] = ex_key[4*(row-4)+0] ^ temp[0] ;
		ex_key[4*row+1] = ex_key[4*(row-4)+1] ^ temp[1] ;
		ex_key[4*row+2] = ex_key[4*(row-4)+2] ^ temp[2] ;
		ex_key[4*row+3] = ex_key[4*(row-4)+3] ^ temp[3] ;
	}  
    for(i=0;i<blocknum;i++)
    {
        InvCipher(pCurInBuf,pCurOutBuf,ex_key);
        for(j = 0; j < 16; j++ )
        {
            pCurOutBuf[j] = pCurOutBuf[j] ^ iv[j] ;
        }
        memcpy( iv, pCurInBuf, 16 );
        if(i == (blocknum-1))
        {
            memset(temp,0,16);
            if(pCurOutBuf[15] != 0x10)
            {
                if(pCurOutBuf[15] < 0x10)
                {
                    OutLength = input_len - pCurOutBuf[15];
                    memcpy( temp, pCurOutBuf, 16-pCurOutBuf[15] );
                    memcpy( pCurOutBuf, temp, 16 );
                }
                else
                    break;
            }
            else
            {
                OutLength = input_len - 16;
                memcpy( pCurOutBuf, temp, 16 );
            }
        }
        pCurInBuf+=16;
        pCurOutBuf+=16;
    }
    return OutLength;
}

// int main(int argc, char *argv[]) 
// {
// 	int i=0;
// 	unsigned long outlen;
// 	unsigned char in[]={"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF66"};//5*16+2 = 82
// 	unsigned char out_data[96];
// 	unsigned char in_data[96];
// 	outlen=AES128_CBC_Encrypt(in,82,"qwertyuiopasdfgh",out_data);
// 	printf("Encrypt_data: ");
// 	for(i=0;i<96;i++) 
// 	{
// 		printf("%x ",out_data[i]);
// 	}
// 	outlen=AES128_CBC_Decrypt(out_data,96,"qwertyuiopasdfgh",in_data);
// 	printf("\nDecrypt_data: ");
// 	for(i=0;i<82;i++) 
// 	{
// 		printf("%c ",in_data[i]);
// 	}
// 	printf("\n");
// 	return 0;
// }
