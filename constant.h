#ifndef _CONSTANT_H
#define _CONSTANT_H

const int MAX_MESSAGE_LEN = 255;
#define JUMP_ORDER 0xc0
#define MAX_URL_LEN  100 // ���������
#define TYPE_A 1
#define TYPE_AAAA 28
#define TYPE_CNAME 5
#define MAX_FILE_NAME_LEN 100
#define CACHE_CAPACITY 300				//cache����
int temp_cache_n = 0; // ��ǰcache���� 
const char* DEFAULT_FILE_PTR = "C:\\Users\\11954\\Desktop\\���\\���������\\�γ����\\��������\\dnsrelay.txt";


typedef unsigned short uint16_t; // �����ֽڣ�16λ��2���ֽ�
typedef unsigned int uint32_t; // �����ֽڣ�32λ��4���ֽ�

 
// ����һ���ַ�ָ�룬�汾��IP��ַ
const char* local_ip_ptr = "127.0.0.1";

// ����һ���ַ�ָ�룬���ⲿDNS��������IP��ַ
const char* extern_ip_ptr = "10.3.9.44";

// ����SOCKET
SOCKET my_socket; //�������ص��׽���
SOCKET extern_sock;  //�м̸��ⲿ���׽���

// �׽��ֵ�ַ
SOCKADDR_IN local_addr;
SOCKADDR_IN extern_addr;

typedef struct 
{
    int debug_level; // ���Եȼ�
    char* dns_server; // �ⲿDNS������
    char* file; // ���ص������ļ�
}Arg;

Arg argument;



// ����DNS��ͷ���ṹ��һ��12���ֽ�
typedef struct 
{
    uint16_t ID; //����ID
    uint16_t RD: 1; //RD�ֶ�
    uint16_t TC: 1; //TC�ֶ�
    uint16_t AA: 1; //AA�ֶ�
    uint16_t Opcode: 4; //Opcode�ֶ�
    uint16_t QR: 1; //QR�ֶΣ�0��ʾ����1��ʾ��Ӧ
    uint16_t RCODE: 4; //�����룬�������ذ�������
    uint16_t Z: 3; //Z�ֶ�
    uint16_t RA: 1; //RA�ֶ�
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
}DNSHeader;

// DNS�����е������ֶεĽṹ
typedef struct 
{
    char* QNAME;
    uint16_t QTYPE;
    uint16_t QCLASS;
}QUESTION;

// DNS�����е���Դ��¼�ֶΣ�RR���Ľṹ
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
    unsigned short id;  //�����е�ID�ֶ� 
    BOOL qr;   //�����е�QR�ֶΣ�0��ʾ����1��ʾ��ѯ 
    int num_query;   //����ͷ��QDCOUNT��ֵ
    int num_response;  //����ͷ��ANCOUNT��ֵ
}MESSAGE_HEAD;


typedef struct  
{
	char Domain[100];
	char IP[100];
	int t;
}lru; 

static lru page[CACHE_CAPACITY];

//����ID��¼��
typedef struct 
{
	SOCKADDR_IN Addr;  //�׽���
	unsigned short id; //��Ӧid��
	int TIME;   //���һ�θ���ʱʱ��
}ID_TABLE;

ID_TABLE id_table[100];



#endif
