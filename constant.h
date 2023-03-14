#ifndef _CONSTANT_H
#define _CONSTANT_H

const int MAX_MESSAGE_LEN = 255;
#define JUMP_ORDER 0xc0
#define MAX_URL_LEN  100 // 最长域名长度
#define TYPE_A 1
#define TYPE_AAAA 28
#define TYPE_CNAME 5
#define MAX_FILE_NAME_LEN 100
#define CACHE_CAPACITY 300				//cache容量
int temp_cache_n = 0; // 当前cache容量 
const char* DEFAULT_FILE_PTR = "C:\\Users\\11954\\Desktop\\大二\\计算机网络\\课程设计\\可用资料\\dnsrelay.txt";


typedef unsigned short uint16_t; // 两个字节，16位，2个字节
typedef unsigned int uint32_t; // 两个字节，32位，4个字节

 
// 定义一个字符指针，存本地IP地址
const char* local_ip_ptr = "127.0.0.1";

// 定义一个字符指针，存外部DNS服务器的IP地址
const char* extern_ip_ptr = "10.3.9.44";

// 创建SOCKET
SOCKET my_socket; //监听本地的套接字
SOCKET extern_sock;  //中继给外部的套接字

// 套接字地址
SOCKADDR_IN local_addr;
SOCKADDR_IN extern_addr;

typedef struct 
{
    int debug_level; // 调试等级
    char* dns_server; // 外部DNS服务器
    char* file; // 本地的配置文件
}Arg;

Arg argument;



// 定义DNS的头部结构，一共12个字节
typedef struct 
{
    uint16_t ID; //事务ID
    uint16_t RD: 1; //RD字段
    uint16_t TC: 1; //TC字段
    uint16_t AA: 1; //AA字段
    uint16_t Opcode: 4; //Opcode字段
    uint16_t QR: 1; //QR字段，0表示请求，1表示响应
    uint16_t RCODE: 4; //返回码，表明返回包的类型
    uint16_t Z: 3; //Z字段
    uint16_t RA: 1; //RA字段
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
}DNSHeader;

// DNS报文中的问题字段的结构
typedef struct 
{
    char* QNAME;
    uint16_t QTYPE;
    uint16_t QCLASS;
}QUESTION;

// DNS报文中的资源记录字段（RR）的结构
typedef struct 
{
    char CNAME[MAX_URL_LEN];
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    uint16_t RDLENGTH;
    char RDATA[MAX_URL_LEN];
}RR;


typedef struct 
{
    unsigned short id;  //报文中的ID字段 
    BOOL qr;   //报文中的QR字段，0表示请求，1表示查询 
    int num_query;   //报文头部QDCOUNT的值
    int num_response;  //报文头部ANCOUNT的值
}MESSAGE_HEAD;


typedef struct  
{
	char Domain[100];
	char IP[100];
	int t;
}lru; 

static lru page[CACHE_CAPACITY];

//定义ID记录表
typedef struct 
{
	SOCKADDR_IN Addr;  //套接字
	unsigned short id; //对应id号
	int TIME;   //最后一次更新时时间
}ID_TABLE;

ID_TABLE id_table[100];



#endif
