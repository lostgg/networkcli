
#ifdef _USRDLL
#define LICENSE_API __declspec(dllexport)
#else
#define LICENSE_API __declspec(dllimport)
#endif

#include <string>

LICENSE_API bool lic_license();

LICENSE_API void lic_init( /*checkout*/
	/* 授权服务器连接地址 */
	const char *addr, 
	/* 授权服务器连接端口 */
	unsigned short port, 
	/* 项目ID */
	const int pid, 
	/* 循环获取授权的间隔时间 */
	const int req_time = 30, 
	/* 授权在离线状态下的有效期 */
	const int local_valid_time = 360);

LICENSE_API void lic_check_in();



// 重设服务器IP地址和端口号
// 同时内部会根据新的IP地址和端口号进行重新连接
LICENSE_API void reset_endpoint(const char *addr, const unsigned short port);

// 获取最新的日志信息,需要调用 free_log_stream 释放
LICENSE_API const char *log_stream();

// 日志数据流应该调用这个函数释放
LICENSE_API void free_log_stream(const char *s);

#ifndef _USRDLL
#pragma comment(lib,"networklic_10.lib")
#endif