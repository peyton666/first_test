#include"DNS_server_details.h"
#include"constant.h"

int main(int argc, char** argv)
{

    // ��ͷ�������
    print_beginning();

    // ��ʼ���û�����
    argument = init_argument(argc, argv);

    if(argument.debug_level == -1)
    {
        printf("\n********************������󣬿�ѡ���Կ���ֻ�� ��-d�� �� ��-dd��********************\n");
        return;
    }

        
    // ��ʼ��cache
    init_cache();
    
	// ��ʼ���׽���
    init_socket();
    
    // ��ʼ��IDת����¼��
	init_ID_table(argument);
    
    while(1)
    {
        int is_relay = 1;
        // ���ձ��ط����Ĳ�ѯ����
        is_relay = receive_from_local(argument);
        if(is_relay == 0)  continue;
        // �����ⲿDNS��������Ӧ����
        receive_from_external(argument);
    }

}
