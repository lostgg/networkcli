
#ifdef _USRDLL
#define LICENSE_API __declspec(dllexport)
#else
#define LICENSE_API __declspec(dllimport)
#endif

#include <string>

LICENSE_API bool lic_license();

LICENSE_API void lic_init( /*checkout*/
	/* ��Ȩ���������ӵ�ַ */
	const char *addr, 
	/* ��Ȩ���������Ӷ˿� */
	unsigned short port, 
	/* ��ĿID */
	const int pid, 
	/* ѭ����ȡ��Ȩ�ļ��ʱ�� */
	const int req_time = 30, 
	/* ��Ȩ������״̬�µ���Ч�� */
	const int local_valid_time = 360);

LICENSE_API void lic_check_in();



// ���������IP��ַ�Ͷ˿ں�
// ͬʱ�ڲ�������µ�IP��ַ�Ͷ˿ںŽ�����������
LICENSE_API void reset_endpoint(const char *addr, const unsigned short port);

// ��ȡ���µ���־��Ϣ,��Ҫ���� free_log_stream �ͷ�
LICENSE_API const char *log_stream();

// ��־������Ӧ�õ�����������ͷ�
LICENSE_API void free_log_stream(const char *s);

#ifndef _USRDLL
#pragma comment(lib,"networklic_10.lib")
#endif