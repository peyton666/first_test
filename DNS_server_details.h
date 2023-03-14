#ifndef _DNS_SERVER_DETAILS_H
#define _DNS_SERVER_DETAILS_H

#include<stdio.h>
#include<WinSock2.h>
#include<string.h>
#include<stdlib.h>
#include"constant.h"
#include<time.h>

// 开头输出内容
void print_beginning()
{
    printf("***********************************************************\n");
	printf("* @Course Name: Course Design of Computer Network         *\n");
	printf("* @Name of Team members: Chen Pengyu, Fan Rujie, Guo Yanyao    *\n");
	printf("* @Teacher: Gao Zhanchun         @Class number: 310 and 307    *\n");
	printf("* ------------------------------------------------------- *\n");
	printf("*               DNS Relay Server - Ver 1.0                *\n");
	printf("***********************************************************\n");
	printf("Command syntax : dnsrelay [-d | -dd] [dns-server-IP-addr]  \n");
}


// 初始化ID转换记录表
void init_ID_table()
{
    int i = 0;
	for (i = 0; i <= 99; i++)
	{
		id_table[i].id = 100;
	}
    if(argument.debug_level == 2)
        printf("\n！！！ID转换表初始化成功！！！\n");
}

// 对用户的输入的调试等级进行初始化
Arg init_argument(int argc, char** argv)
{
    argument.debug_level = -1;
    if(argv[1] == NULL) // 无调试信息输出
	{
        argument.debug_level = 0;
		argument.file = (char*)DEFAULT_FILE_PTR;
        argument.dns_server =(char*)extern_ip_ptr;		
	}
	
    else if(argv[1][0]=='-' && argv[1][1]=='d' && argv[1][2]=='\0')
	{
        argument.debug_level = 1;
		if(argv[2] != NULL)
        {
            argument.dns_server = argv[2];
		    if(argv[3] != NULL)  // 设置所给的配置文件
		    {
			    argument.file = argv[3];	
		    }
            else argument.file = (char*)DEFAULT_FILE_PTR;	
        }
        else 
        {
            argument.dns_server =(char*)extern_ip_ptr;
            argument.file =(char*)DEFAULT_FILE_PTR;
        }
	}

    else if(argv[1][0]=='-'&&argv[1][1]=='d'&&argv[1][2]=='d'&&argv[1][3] == '\0') // 二级调试
	{
        argument.debug_level = 2;
		if(argv[2] != NULL)
        {
            argument.dns_server = argv[2];
		    if(argv[3] != NULL)  // 设置所给的配置文件
		    {
			    argument.file = argv[3];	
		    }
            else argument.file = (char*)DEFAULT_FILE_PTR;	
        }
        else 
        {
            argument.dns_server =(char*)extern_ip_ptr;
            argument.file =(char*)DEFAULT_FILE_PTR;
        }
	}
    

    return argument;
}

// 初始化套接字
void init_socket()
{
    // 初始化winsock32
    WSADATA wsa;

    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        if(argument.debug_level == 2)
            printf("Failed.Error Code:%d", WSAGetLastError());
        exit(-1);
    }

    my_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if(my_socket < 0)
    {
        if(argument.debug_level == 2)
            printf("Could not create socket:%d", WSAGetLastError());
        exit(-1);
    }


    int non_block = 1;
    //ioctlsocket(extern_sock, FIONBIO, (u_long FAR*)&non_block);
    //ioctlsocket(my_socket, FIONBIO, (u_long FAR*)&non_block);   
    

    // 将相应的ip地址与端口绑定到my_socket
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(53);  

    // 绑定外部的socket
    extern_addr.sin_family = AF_INET;
    //extern_addr.sin_addr.s_addr = 16885952;
    extern_addr.sin_addr.s_addr = inet_addr("10.3.9.44");
    extern_addr.sin_port = htons(53); 


    /* Set the socket option to avoid the port has been occupied */
    int reuse = 1;
    setsockopt(my_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
	

    // 尝试绑定
    if(bind(my_socket, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0)
    {
        printf("Bind error");
        exit(-1);
    } 

    if(argument.debug_level == 2)
        printf("\n！！！套接字初始化成功！！！\n");



}


// 解析报头
MESSAGE_HEAD translate_head(char* buf)
{
    DNSHeader* header = (DNSHeader*)buf;
    MESSAGE_HEAD message_head;
    message_head.id = ntohs(header->ID);
    message_head.qr = header->QR;
    message_head.num_query = ntohs(header->QDCOUNT);
    message_head.num_response = ntohs(header->ANCOUNT);
	return message_head;
}


BOOL judge_jump_order(char* temp_ptr)
{

    if (((*(unsigned char*)temp_ptr) & JUMP_ORDER) == JUMP_ORDER) 
    {
        return TRUE;
    }
    else return FALSE;
}



// 对压缩或者非压缩的NAME字段进行解析
char* transform_dname(char* norm_name, char* udp_name, char* buf)
{
    int subscript_n = 0; // subscript_n 代表 norm_name 的下标
    int subscript_b = udp_name - buf; // cnt_b 代表 buf 的下标
    int return_pos = 0; // 保留 buffer 最后的位置
    unsigned __int8 cpy_len;
    // 记录下需要复制几个字节, cnt_b 右移到第一个需要赋值的字节上
    if (judge_jump_order(udp_name) == TRUE) 
    {
        return_pos = subscript_b + 2;

        subscript_b = (int)(ntohs(*(unsigned short*)udp_name) ^ (JUMP_ORDER << 8));
    }

    cpy_len = buf[subscript_b++];
    while (cpy_len != 0) 
    {
        if ((cpy_len & JUMP_ORDER) == JUMP_ORDER) 
        {
            if (return_pos == 0) 
            {
            return_pos = subscript_b + 1; // 记录当前最后指针位置用于返回
            }
        subscript_b = (int)(ntohs(*((unsigned short*)&buf[subscript_b - 1])) ^ (JUMP_ORDER << 8)); // 跳转
        cpy_len = buf[subscript_b++]; // 重新载入 cpy_len
        continue;
        }
        int i; 
        for (i = 0; i < cpy_len; i++) 
        {
            norm_name[subscript_n++] = buf[subscript_b++];
        }
        cpy_len = buf[subscript_b++];
        if (cpy_len != 0) 
        {
            norm_name[subscript_n++] = '.';
        } 
    }
    norm_name[subscript_n] = '\0';

    if (return_pos == 0) 
    {
        return_pos = subscript_b;
    }
    return buf + return_pos;
}


// 解析问题字段,返回值是一个字符指针，指向查询报RR中的第一个字节
char* translate_questions(MESSAGE_HEAD message_head, 
        QUESTION* ques, char* query_ptr, char* buf)
{
	int i;
    for(i = 0; i < message_head.num_query; i++)
    {	
        ques[i].QNAME = (char*)malloc(MAX_URL_LEN * sizeof(char));
        query_ptr = transform_dname(ques[i].QNAME, query_ptr, buf);
        // 此时query_ptr指向问题类型字段的第一个字节
        ques[i].QTYPE = ntohs(*((uint16_t*)query_ptr));
        query_ptr += 2;
        ques[i].QCLASS = ntohs(*((uint16_t*)query_ptr));
        query_ptr += 2;
    }
    return query_ptr;
}

// 解析资源记录字段
void translate_rr(MESSAGE_HEAD message_head,
        RR* rr_recode, char* rr_ptr, char* buf)
{
	int i;
    for(i = 0; i < message_head.num_response; i++)
    {
        rr_ptr = transform_dname(rr_recode[i].CNAME, rr_ptr, buf);
        rr_recode[i].TYPE = ntohs(*(unsigned short*)rr_ptr);
        rr_ptr += sizeof(unsigned short);
        rr_recode[i].CLASS = ntohs(*(unsigned short*)rr_ptr);
        rr_ptr += sizeof(unsigned short);
        rr_recode[i].TTL = ntohl(*(unsigned int*)rr_ptr);
        rr_ptr += sizeof(unsigned int);
        rr_recode[i].RDLENGTH = *(unsigned short*)rr_ptr;
        rr_ptr += sizeof(unsigned short);
        // 对资源记录的类型进行判断
        if(rr_recode[i].TYPE == TYPE_A)
        {
            unsigned int ip1,ip2,ip3,ip4;
            ip1 = *(unsigned char*)(rr_ptr++);
            ip2 = *(unsigned char*)(rr_ptr++);
            ip3 = *(unsigned char*)(rr_ptr++);
            ip4 = *(unsigned char*)(rr_ptr++);
            sprintf(rr_recode[i].RDATA, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
        }
        else if(rr_recode[i].TYPE == TYPE_CNAME)
        {
            rr_ptr = transform_dname(rr_recode[i].RDATA, rr_ptr, buf);    
        }
        else memset(rr_recode[i].RDATA, '0', sizeof(rr_recode[i].RDATA));
    }
}

// 输出Cache内容
void print_cache() 
{
	int i;
	printf("\nCache存储状态：\n");
	for (i = 0; i < temp_cache_n; i++) 
    {
		printf("Domain = %s   IP = %s   time = %d\n\n", page[i].Domain, page[i].IP, page[i].t);
	}
}


// 更新cache时间
void update_cache_time(char ans_ip[MAX_URL_LEN])
{
    int i,flag;
    // 更新cache中每个项的t，不针对配置文件的项
	for (i = 0; i < temp_cache_n; i++) 
    {
		flag = strcmp("0.0.0.0", page[i].IP) && strcmp("11.111.11.111", page[i].IP) && strcmp("22.22.222.222", page[i].IP)
        && strcmp("202.108.33.89", page[i].IP) && strcmp("61.135.181.175", page[i].IP) 
        && strcmp("123.127.134.10", page[i].IP) && strcmp(ans_ip, page[i].IP);
		if (flag != 0) 
        {
			page[i].t += 1;
		}
        if(strcmp(page[i].IP, ans_ip) == 0)
            page[i].t = 0;
	}
    //print_cache();
    if(argument.debug_level == 2)
        printf("\ncache每个项的时间更新完成！\n");
}


// LRU算法
int Cache_LRU(char domin[MAX_URL_LEN], char ip[MAX_URL_LEN]) 
{
	int i, j, k, flag;
	k = 0;

    if(temp_cache_n < CACHE_CAPACITY)  // cache中还有容量
    {
        strcpy(page[temp_cache_n].IP, ip);
	    strcpy(page[temp_cache_n].Domain, domin);
        page[temp_cache_n++].t = 0;
        if(argument.debug_level == 2)
        {
            printf("\n添加成功！！！\n");
            update_cache_time(ip); //更新时间
            print_cache();
        }
        return 0;
    }

    // cache中容量满了
    else 
    {
        // LRU算法替换
        for (i = 0; i < CACHE_CAPACITY; i++) 
        {
            flag = strcmp("0.0.0.0", page[i].IP) && strcmp("11.111.11.111", page[i].IP) && strcmp("22.22.222.222", page[i].IP)
            && strcmp("202.108.33.89", page[i].IP) && strcmp("61.135.181.175", page[i].IP) && strcmp("123.127.134.10", page[i].IP);
            if (page[i].Domain[0] == '\0') 
            {
                j = i;
                break;
            } 
            else if (k < page[i].t || flag != 0) 
            {
                k = page[i].t;
                j = i;
            }
        }
        strcpy(page[j].IP, ip);
        strcpy(page[j].Domain, domin);
        page[j].t = 0;

        // 更新cache中每个项的t，不针对配置文件的项
        update_cache_time(ip);
        if(argument.debug_level == 2)
        {
            printf("\n替换成功！\n");
            print_cache();
        }
    }
	return 0;

}

// 初始化cache
void init_cache()
{
    FILE *fp;
	int j = 0;
    // 打开配置文件
	fp = fopen(argument.file, "r");
	//if (fp == NULL)
	//	printf("ERROR");
	while(1) 
    {
        // 向cache中加入配置文件内容
		int flag1, flag2;
		char ip[MAX_URL_LEN];
		char dom[MAX_URL_LEN];
		flag1 = fscanf(fp, "%s", ip);
		flag2 = fscanf(fp, "%s", dom);
		if (flag1 == EOF || flag2 == EOF)
			break;
		strcpy(page[j].Domain, dom);
		strcpy(page[j].IP, ip);
		j++;
		//printf("Domain=%s   IP=%s   time=%d\n", page[i].Domain, page[i].IP, page[i].t);
    }
    temp_cache_n = j;
    if(argument.debug_level == 2)
        printf("\n！！！cache初始化成功！！！\n");
}

// 向ID转换表中添加新的项
void Register_New_ID(SOCKADDR_IN temp_Addr, uint16_t temp_id, clock_t now_time)
{
	int index;
	index = temp_Addr.sin_addr.s_addr % 100;
	//若该id已有其他用户占用
	if (id_table[index].id != 100)
	{
		index++;
		while (id_table[index].id != 100 && index <= 99)
		{
			index++;
		}
		if (index == 100)
		{
			index = 0;
			while (id_table[index].id != 100 && index <= 99)
			{
				index++;
			}
		}
	}
	
    // 记录表项
    id_table[index].id = temp_id; 
	id_table[index].Addr = temp_Addr;
	id_table[index].TIME = now_time;
    
    if(argument.debug_level == 2)
        printf("\n该项成功在ID转换记录表中记录！！！\n");
}

// 在ID转换表中查询特定项
SOCKADDR_IN  query_id_address(Arg argument, unsigned temp_id)
{
    int i;
    for(i = 0; i < 100; i++)
    {
        if(id_table[i].id == temp_id)
            return id_table[i].Addr;
    }
    if(i == 100)
        if(argument.debug_level == 2)
            printf("找不到该项！");
}

// 封装并发送响应报给本地_IPV4
void generate_and_send_ans_message(char recvData[MAX_MESSAGE_LEN], int recv_len, char ans_ip[MAX_URL_LEN], SOCKADDR_IN remoteAddr)
{
    char sendData[MAX_MESSAGE_LEN];
    memcpy(sendData, recvData, recv_len);

    if(strcmp(ans_ip, "0.0.0.0") == 0) // 拦截
    {
        unsigned short flag = htons(0x8180);
        unsigned short num_answers = htons(0x0000);
        memcpy(&sendData[2], &flag, sizeof(unsigned short));
        memcpy(&sendData[6], &num_answers, sizeof(unsigned short));
    }
    else   // 不拦截
    {
        unsigned short flag = htons(0x8180);
        unsigned short num_answers = htons(0x1);
        memcpy(&sendData[2], &flag, sizeof(unsigned short));
        memcpy(&sendData[6], &num_answers, sizeof(unsigned short));
    }

    int cur_Len = 0;
    char rr_answer[16];
    unsigned short name = htons(0xc00c);  /* Pointer of domain */
    memcpy(rr_answer, &name, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned short Type_A = htons(0x0001);  /* Type */
    memcpy(rr_answer + cur_Len, &Type_A, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned short Class_IN = htons(0x0001);  /* Class */
    memcpy(rr_answer + cur_Len, &Class_IN, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned long ttl = htonl(0x7b); /* Time to live */
    memcpy(rr_answer + cur_Len, &ttl, sizeof(unsigned long));
    cur_Len += sizeof(unsigned long);

    unsigned short data_length = htons(0x0004);  /* Data length */
    memcpy(rr_answer + cur_Len, &data_length, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned long IP = (unsigned long)inet_addr(ans_ip); /* Actually data is IP */

    memcpy(rr_answer + cur_Len, &IP, sizeof(unsigned long));
    cur_Len += sizeof(unsigned long);
    cur_Len += recv_len;
    memcpy(sendData + recv_len, rr_answer, sizeof(rr_answer));
    int len = sizeof(remoteAddr);

    int length = sendto(my_socket, sendData, cur_Len, 0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if(argument.debug_level == 2)
    {
        printf("\n向本地发送构造好的回复报文：\n");
        int i;
        for(i = 0; i < length; i++)
            printf("%02x ", sendData[i]);
    }

}


// 如果发送过，再发送一个响应报给本地
void generate_and_send_ans_message_f(char recvData[MAX_MESSAGE_LEN], int recv_len, char ans_ip[MAX_URL_LEN], SOCKADDR_IN remoteAddr)
{
    char sendData[MAX_MESSAGE_LEN];
    memcpy(sendData, recvData, recv_len);

    if(strcmp(ans_ip, "0.0.0.0") == 0) // 拦截
    {
        unsigned short flag = htons(0x8180);
        unsigned short num_answers = htons(0x0000);
        memcpy(&sendData[2], &flag, sizeof(unsigned short));
        memcpy(&sendData[6], &num_answers, sizeof(unsigned short));
    }
    else   // 不拦截
    {
        unsigned short flag = htons(0x8180);
        unsigned short num_answers = htons(0x0000);
        memcpy(&sendData[2], &flag, sizeof(unsigned short));
        memcpy(&sendData[6], &num_answers, sizeof(unsigned short));
    }

    int cur_Len = 0;
    char rr_answer[16];
    unsigned short name = htons(0xc00c);  /* Pointer of domain */
    memcpy(rr_answer, &name, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned short Type_A = htons(0x0001);  /* Type */
    memcpy(rr_answer + cur_Len, &Type_A, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned short Class_IN = htons(0x0001);  /* Class */
    memcpy(rr_answer + cur_Len, &Class_IN, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned long ttl = htonl(0x7b); /* Time to live */
    memcpy(rr_answer + cur_Len, &ttl, sizeof(unsigned long));
    cur_Len += sizeof(unsigned long);

    unsigned short data_length = htons(0x0004);  /* Data length */
    memcpy(rr_answer + cur_Len, &data_length, sizeof(unsigned short));
    cur_Len += sizeof(unsigned short);

    unsigned long IP = (unsigned long)inet_addr(ans_ip); /* Actually data is IP */

    memcpy(rr_answer + cur_Len, &IP, sizeof(unsigned long));
    cur_Len += sizeof(unsigned long);
    cur_Len += recv_len;
    memcpy(sendData + recv_len, rr_answer, sizeof(rr_answer));
    int len = sizeof(remoteAddr);

    int length = sendto(my_socket, sendData, cur_Len, 0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if(argument.debug_level == 2)
    {
        printf("向本地发送构造好的回复报文：\n");
        int i;
        for(i = 0; i < length; i++)
            printf("%02x ", sendData[i]);
    }
}




// 监听本地nslookup发来的请求报文
int receive_from_local(Arg argument)
{
    int ret;
    char recvData[MAX_MESSAGE_LEN];
    memset(recvData, 0, MAX_MESSAGE_LEN);
    SOCKADDR_IN remoteAddr;
    int len = sizeof(remoteAddr);
    
    // 接受本地请求报文
    ret = recvfrom(my_socket, recvData, 255, 0, (struct sockaddr*)&remoteAddr, &len);
    
    if(argument.debug_level == 2)
    {
        printf("\n收到本地发来的查询报文：\n");
        int i;
        for(i = 0; i < ret; i++)
            printf("%02x ", recvData[i]);
    }


    // 解析本地请求报文的头部字段
    MESSAGE_HEAD message_head = translate_head(recvData);
    clock_t now_time;   //记录时间
    now_time = clock();  //更新时间
    
    // 解析本地请求报文的问题字段
    QUESTION* ques = (QUESTION*)malloc(message_head.num_query * sizeof(QUESTION));
	
	char* query_ptr = recvData + 12;
	query_ptr = translate_questions(message_head, ques, query_ptr, recvData);
    
    if (argument.debug_level)
	{
		printf("\n\n---- Recv : Clinet [Domin:%s]----\n", ques[0].QNAME);

		/* Output time now */
		time_t t = time(NULL);
		char temp[64];
		strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
		printf("%s\n", temp);
	}


    int temp_ques_num;
    for(temp_ques_num = 0; temp_ques_num < message_head.num_query; temp_ques_num++)
    {
        // 是IPV4地址
        if(ques[temp_ques_num].QTYPE == TYPE_A)
        {
            // 在cache中查找
            int temp_n;
            for(temp_n = 0; temp_n < temp_cache_n; temp_n++)
            {
                // 在cache中找到该域名-IP
                if(strcmp(ques[temp_ques_num].QNAME, page[temp_n].Domain) == 0)
                {
                    char ans_ip[MAX_URL_LEN];
                    memcpy(ans_ip, page[temp_n].IP, strlen(page[temp_n].IP));
                    ans_ip[strlen(page[temp_n].IP)] = '\0';
                    //封装并发送报文
                    generate_and_send_ans_message(recvData, ret, ans_ip, remoteAddr);
                    // 更新cache的时间
                    update_cache_time(ans_ip);
                    if(argument.debug_level == 2)
                        print_cache();
                    return 0;
                }
            }
            if(temp_n == temp_cache_n)  //cache中没有，也需要中继
            {
                // 将这个报文ID记录并且转换
                Register_New_ID(remoteAddr, message_head.id, now_time);
                int x;
                for (x = 0; x <= 99; x++)
                {
                    //过期则删除该条记录
                    if (now_time - id_table[x].TIME >= 10000)
                    {
                        id_table[x].id = 100;
                    }
                }
                //转发给外部DNS服务器
                extern_sock = socket(AF_INET, SOCK_DGRAM, 0);
	            if (argument.debug_level)
                {
                    printf("\n\n---- Send : Clinet [Domin:%s]----\n", ques[0].QNAME);
                
                    /* Output time now */
                    time_t t = time(NULL);
                    char temp[64];
                    strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
                    printf("%s\n", temp);
                }
                // 中继出去
                int length = sendto(extern_sock, recvData, ret, 0, (struct sockaddr*)&extern_addr, sizeof(extern_addr));
            }
        }
        // 是IPV6地址
        else if(ques[temp_ques_num].QTYPE == TYPE_AAAA)
        {
            // 在cache中查找
            int temp_n;
            for(temp_n = 0; temp_n < temp_cache_n; temp_n++)
            {
                // 在cache中找到该域名-IP
                if(strcmp(ques[temp_ques_num].QNAME, page[temp_n].Domain) == 0)
                {
                    char ans_ip[MAX_URL_LEN];
                    memcpy(ans_ip, page[temp_n].IP, strlen(page[temp_n].IP));
                    ans_ip[strlen(page[temp_n].IP)] = '\0';
                    //update_cache_time(ans_ip);
                    //封装并发送报文
                    generate_and_send_ans_message_f(recvData, ret, ans_ip, remoteAddr);
                    return 0;
                }
            }
            if(temp_n == temp_cache_n)  //cache中没有，也需要中继
            {
                // 将这个报文ID记录并且转换
                Register_New_ID(remoteAddr, message_head.id, now_time);

                //转发给外部DNS服务器
                extern_sock = socket(AF_INET, SOCK_DGRAM, 0);
	            int length = sendto(extern_sock, recvData, ret, 0, (struct sockaddr*)&extern_addr, sizeof(extern_addr));
            }
        }
    }
}



// 接收外部DNS服务器发来的响应报文
void receive_from_external(Arg argument)
{
    int length;
    char buf[MAX_MESSAGE_LEN];
	memset(buf, 0, MAX_MESSAGE_LEN);
	struct sockaddr_in client, external;
	int length_client = sizeof(client);
    
    // 接收外部DNS发来响应报文
    length = recvfrom(extern_sock, buf, 255, 0, (struct sockaddr*)&external, &length_client);

    if (argument.debug_level == 2)
	{
        int m;
        printf("\n接收到外部DNS服务器发来的报文：\n");
        for(m = 0; m < length; m++)
            printf("%02x ", buf[m]);
        printf("\n");
	}

    // 解析外部的DNS响应报文
    MESSAGE_HEAD message_head = translate_head(buf);

    // 解析本地请求报文的问题字段
    QUESTION* ques = (QUESTION*)malloc(message_head.num_query * sizeof(QUESTION));

	char* query_ptr = buf + 12;
	query_ptr = translate_questions(message_head, ques, query_ptr, buf);
    
    RR* rr_recode = (RR*)malloc(message_head.num_response * sizeof(RR));
    translate_rr(message_head, rr_recode, query_ptr, buf);
    
    if (argument.debug_level)
	{
		printf("\n\n---- Recv : Extern [Domin:%s]----\n", ques[0].QNAME);

		/* Output time now */
		time_t t = time(NULL);
		char temp[64];
		strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
		printf("%s\n", temp);
	}


    char cache_ans_ip[MAX_URL_LEN];
    int j;
    int temp_ques_num;
    for(temp_ques_num = 0; temp_ques_num < message_head.num_query; temp_ques_num++)
    {
        for(j = 0; j < message_head.num_response; j++)
        {
            if(rr_recode[j].TYPE == TYPE_A)
            {
                memcpy(cache_ans_ip, rr_recode[j].RDATA, strlen(rr_recode[j].RDATA));
                cache_ans_ip[strlen(rr_recode[j].RDATA)] = '\0';    
                // LRU算法装载Cache
                Cache_LRU(ques[temp_ques_num].QNAME, cache_ans_ip);
                break;
            }
        }
    }
    SOCKADDR_IN remoteAddr = query_id_address(argument, message_head.id);

    int len = sizeof(remoteAddr);

    if (argument.debug_level)
	{
		printf("\n\n---- Send : Clinet [Domin:%s]----\n", ques[0].QNAME);
    
		/* Output time now */
		time_t t = time(NULL);
		char temp[64];
		strftime(temp, sizeof(temp), "%Y/%m/%d %X %A", localtime(&t));
		printf("%s\n", temp);
	}
    // 将外部得到的响应报文内容发回给本地
	length = sendto(my_socket, buf, length, 0, (struct sockaddr*)&remoteAddr, len);


}

#endif
