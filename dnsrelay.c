#include"DNS_server_details.h"
#include"constant.h"

int main(int argc, char** argv)
{

    // 开头输出内容
    print_beginning();

    // 初始化用户输入
    argument = init_argument(argc, argv);

    if(argument.debug_level == -1)
    {
        printf("\n********************输入错误，可选调试开关只有 “-d” 和 “-dd”********************\n");
        return;
    }

        
    // 初始化cache
    init_cache();
    
	// 初始化套接字
    init_socket();
    
    // 初始化ID转换记录表
	init_ID_table(argument);
    
    while(1)
    {
        int is_relay = 1;
        // 接收本地发来的查询报文
        is_relay = receive_from_local(argument);
        if(is_relay == 0)  continue;
        // 接收外部DNS发来的响应报文
        receive_from_external(argument);
    }

}
