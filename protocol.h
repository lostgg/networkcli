
#ifndef AUTH_SERVER_PROTOCOL_H
#define AUTH_SERVER_PROTOCOL_H

#include <stdint.h>

#define TIME_MIN_SECOND(min) (min * 60)
#define TIME_HOUR_SECOND(hour) (TIME_MIN_SECOND(60) * hour)
#define TIME_DAY_SECOND(day) (TIME_HOUR_SECOND(24) * day)

/////////////////////////////////////////////////////////////////////////

// GP ģʽ����ʱ��
#define GRACE_PERIOD_EXPIRE_SECOND TIME_DAY_SECOND(30)
// GUIServer һҳ��ʾ���豸����
#define _PAGE_NUMBER_DDD_ 25

// ����ģ�����ݰ�ID ��ʼ��ַ
#define IDP_START_POS_NETWORK 0x10000
// �ͻ������ݰ�ID ��ʼ��ַ
#define IDP_START_POS_CLIENT 0x20000
// ��������ݰ�ID ��ʼ��ַ
#define IDP_START_POS_SERVER 0x30000


#pragma pack(1)

//����״̬
enum active_status
{
	IDA_NETWORK_ACTIVED = 0, // ��������ģʽ�¼���״̬
	IDA_NETWORK_CONNECTION, // ��������ģʽ��û�м���
	IDA_GRACE_PERIOD_MODEL, // GP ģʽ
	IDA_LOCK_GRACE_PERIOD_MODEL // GP ����ģʽ
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
	PID_LICENSE_ACTIVE = IDP_START_POS_CLIENT, // ��Ȩ
	PID_REQUEST_LICENSE, // checkout
	PID_LICNESE_OFFLINE, // checkin
	PID_CLIENT_INIT, // �ͻ��˳�ʼ��, ���� MAC ��ַ
	PID_REQUEST_PROJUCTS, // ������Ȩ����Ŀ�б�
	PID_REQUEST_CLIENT_DETAILS, // ������Ŀ�еĿͻ��б�
	PID_GP_MODEL_CONROL // GP ģʽ����
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
// ��ȡ���ʧ�ܣ����ش���
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
	int year; // ����ʱ��
	int month;
	int day;
	int maxuser; // ����û���
	int cuser; // ��ǰ�û���
	int auser; // ��Ȩ�û���
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
		uint8_t conns; // ������ ������
		uint8_t active_status; 
		uint32_t create_time; 
		uint32_t gp_valid_time; // gp ��Чʱ��
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
