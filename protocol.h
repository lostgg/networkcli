
#ifndef AUTH_SERVER_PROTOCOL_H
#define AUTH_SERVER_PROTOCOL_H

#include <stdint.h>

#define TIME_MIN_SECOND(min) (min * 60)
#define TIME_HOUR_SECOND(hour) (TIME_MIN_SECOND(60) * hour)
#define TIME_DAY_SECOND(day) (TIME_HOUR_SECOND(24) * day)

/////////////////////////////////////////////////////////////////////////

// GP 模式宽限时间
#define GRACE_PERIOD_EXPIRE_SECOND TIME_DAY_SECOND(30)
// GUIServer 一页显示的设备数量
#define _PAGE_NUMBER_DDD_ 25

// 网络模块数据包ID 起始地址
#define IDP_START_POS_NETWORK 0x10000
// 客户端数据包ID 起始地址
#define IDP_START_POS_CLIENT 0x20000
// 服务端数据包ID 起始地址
#define IDP_START_POS_SERVER 0x30000


#pragma pack(1)

//激活状态
enum active_status
{
	IDA_NETWORK_ACTIVED = 0, // 正常网络模式下激活状态
	IDA_NETWORK_CONNECTION, // 正常网络模式但没有激活
	IDA_GRACE_PERIOD_MODEL, // GP 模式
	IDA_LOCK_GRACE_PERIOD_MODEL // GP 锁定模式
};


struct PacketHead
{
	int length;
	int opcode;
};

// opcode
// network to logic
enum network_pid
{
	PID_CONNECTION_CONNECT = IDP_START_POS_NETWORK,
	PID_CONNECTION_DISCONNECT
};

struct CConnect : public PacketHead
{
	enum { ENUM_PACKET_ID = PID_CONNECTION_CONNECT };
	char ip[16];
	uint16_t port;
};

struct CDisconnect : public PacketHead
{
	enum { ENUM_PACKET_ID = PID_CONNECTION_DISCONNECT };
};

// opcode
// client to server
enum client_pid
{
	PID_LICENSE_ACTIVE = IDP_START_POS_CLIENT, // 授权
	PID_REQUEST_LICENSE, // checkout
	PID_LICNESE_OFFLINE, // checkin
	PID_CLIENT_INIT, // 客户端初始化, 发送 MAC 地址
	PID_REQUEST_PROJUCTS, // 请求授权的项目列表
	PID_REQUEST_CLIENT_DETAILS, // 请求项目中的客户列表
	PID_GP_MODEL_CONROL // GP 模式控制
};

struct ActiveLicense : PacketHead
{
	enum { ENUM_PACKET_ID = PID_LICENSE_ACTIVE };
	char lincense[300];
};

struct InitConnection : PacketHead
{
	enum { ENUM_PACKET_ID = PID_CLIENT_INIT };
	char mac[50];
	char computer[100];
	int pid;
};

#define ICP_GP_CONTROL_LOCK 0
#define ICP_GP_CONTROL_UNLOCK 1

struct GPModelControl : PacketHead
{
	enum { ENUM_PACKET_ID = PID_GP_MODEL_CONROL };
	int cop;
	char mac[50];
	int pid;
};

struct LicenceReq : PacketHead
{
	enum { ENUM_PACKET_ID = PID_REQUEST_LICENSE};
	int  pid;
};
struct LicenseCheckin : PacketHead
{
	enum { ENUM_PACKET_ID = PID_LICNESE_OFFLINE };
};

struct ProjuctsReq : PacketHead
{
	enum { ENUM_PACKET_ID = PID_REQUEST_PROJUCTS};
};

struct CDetails : PacketHead
{
	enum { ENUM_PACKET_ID = PID_REQUEST_CLIENT_DETAILS };
	int   page; // 1 page = 24 nodes
	int64_t proid;
};



// server to client
// 获取许可失败，返回错误
enum server_pid
{
	PID_LICENSE_ERROR = IDP_START_POS_SERVER,
	PID_ACTIVE_POJUCETS ,
	PID_DEVICES_DETAIL,
	PID_DEVICE_CHECKIN
};

#define LICENSE_ACTIVE_SUCCESS 0
#define LICENSE_LIMIT_MAX_SIZE 1
#define LICENSE_CODE_INVALID 2
#define LICENSE_EXPIRE_DATE_ERROR 3

// server to client
struct LicenseError :public PacketHead
{
	enum { ENUM_PACKET_ID = PID_LICENSE_ERROR };
	int error;
	int year; // 到期时间
	int month;
	int day;
	int maxuser; // 最大用户数
	int cuser; // 当前用户数
	int auser; // 授权用户数
};

struct DeviceCheckin : public PacketHead {
	enum { ENUM_PACKET_ID = PID_DEVICE_CHECKIN };
};

struct ProjuctNodes : public PacketHead
{
	enum { ENUM_PACKET_ID = PID_ACTIVE_POJUCETS };
	int vcount;
	int64_t epoint[50]; //  max projuects 50
};

struct Devices : public PacketHead
{
	enum { ENUM_PACKET_ID = PID_DEVICES_DETAIL };
	struct Device
	{
		char mac[48];
		char computer[100]; 
		char ip[16];
		uint8_t conns; // 进程数 连接数
		uint8_t active_status; 
		uint32_t create_time; 
		uint32_t gp_valid_time; // gp 有效时间
	};
	Device cli[_PAGE_NUMBER_DDD_];
	int total;
	int licensed;
	int vcount;
};

#pragma pack()


#define PACKET_HEADER_INIT(packet) \
	packet.length = sizeof(packet); \
	packet.opcode = packet.ENUM_PACKET_ID

#define PACKET_PTR_HEADER_INIT(packet) \
	PACKET_HEADER_INIT((*packet))

#endif
