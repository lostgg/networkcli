
// networkcli 客户端网络授权模块
// [c](wdb)
// [e](yemo520@vip.qq.com)

#include "../AuthServer/protocol.h"
//#include "dumps.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS 

#include "networklic.h"

#include <sstream>
#include <string>
#include <ctime>
#include <vector>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <sstream>

#include <iphlpapi.h>
#include <stdlib.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"Dbghelp.lib")


#define mtl_endl "\n"



bool GenMachineCode(std::string &strMAC) {
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG	nBufLen = 15360;//15K
	ULONG	maxTries = 5;
	ULONG	nReturn = ERROR_SUCCESS;

	do
	{
		pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(nBufLen);
		if (pAddresses == NULL)
			return false;
		nReturn = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &nBufLen);
		if (nReturn == ERROR_BUFFER_OVERFLOW)
		{
			free(pAddresses);
			pAddresses = NULL;
		}

		maxTries--;

	} while ((nReturn == ERROR_BUFFER_OVERFLOW) && (maxTries > 0));

	if (nReturn == ERROR_SUCCESS)
	{
		PIP_ADAPTER_ADDRESSES pCurAddresses = NULL;
		char	chBuf[MAX_ADAPTER_NAME_LENGTH] = { 0 };
		char	*pBuf = chBuf;

		pCurAddresses = pAddresses;

		while (pCurAddresses != NULL)
		{
			memset(chBuf, 0, 16);
			pBuf = chBuf;

			if (pCurAddresses->PhysicalAddressLength != 0 &&
				(pCurAddresses->IfType == IF_TYPE_ETHERNET_CSMACD || pCurAddresses->IfType == IF_TYPE_IEEE80211))
			{
				for (int i = 0; i < (int)pCurAddresses->PhysicalAddressLength;i++)
				{
					sprintf_s(pBuf, 3, "%02X", pCurAddresses->PhysicalAddress[i]);
					pBuf += 2;
				}
				strMAC.append(chBuf);
				break;
			}

			pCurAddresses = pCurAddresses->Next;
		}
	}

	if (pAddresses != NULL)
	{
		free(pAddresses);
		pAddresses = NULL;
	}

	return true;
}

std::string str_date() {
	time_t now = time(0);
	tm t;
	localtime_s(&t, &now);
	char buff[1024];
	sprintf_s(buff, "---[%d/%d/%d %d:%d:%d] \r\n",
		t.tm_year + 1900,
		t.tm_mon + 1,
		t.tm_mday,
		t.tm_hour,
		t.tm_min,
		t.tm_sec);
	return std::string(buff);
}

class SimpleMutex
{
public:
	SimpleMutex() {
		InitializeCriticalSection(&mutex_);
	}
	~SimpleMutex() {
		DeleteCriticalSection(&mutex_);
	}

	inline void lock() {
		EnterCriticalSection(&mutex_);
	}
	inline void unlock() {
		LeaveCriticalSection(&mutex_);
	}

private:
	CRITICAL_SECTION mutex_;
};

class ThreadLog
{
public:


	void Push(const char *buffer)
	{
		mutex_.lock();
		logs_.push_back(buffer);
		mutex_.unlock();
	}

	ThreadLog &operator << (const char *log) {
		this->Push(log);
		return *this;
	}

	void GetAll(std::string &stream) {
		mutex_.lock();
		for (std::size_t index = 0; index != logs_.size(); ++index) {
			stream += logs_[index];
		}
		logs_.clear();
		mutex_.unlock();
	}
private:
	SimpleMutex mutex_;
	std::vector<std::string> logs_;
};



ThreadLog os;

class NetPacket
{
public:

	NetPacket() {
		this->buffer_ = new char[4096];
		this->init();
	}
	~NetPacket() {
		delete this->buffer_;
	}

	inline std::size_t size() {
		return size_;
	}

	inline std::size_t valid_size() {
		return currentsize_;
	}

	inline void init() {
		this->set_size(4);
	}

	inline unsigned int length() {
		return currentsize_ >= sizeof(unsigned int) ? *(unsigned int *)this->buffer_ : 0;
	}

	inline void set_size(std::size_t s) {
		this->size_ = s;
		this->currentsize_ = 0;
	}

	inline void extent_of_size(std::size_t s) {
		this->size_ = s;
	}

	inline std::size_t fill_buffer(const char *buffer, std::size_t bsize) {
		std::size_t fill_size = (this->size_ - currentsize_) > bsize ? bsize : this->size_ - currentsize_;
		memcpy(&this->buffer_[currentsize_], buffer, fill_size);
		currentsize_ += fill_size;
		return fill_size;
	}

	inline const bool is_full() const {
		return 0 == size_ - currentsize_;
	}

	std::string str() {
		return std::string().append(this->buffer_, size_);
	}

private:
	char *      buffer_;
	std::size_t currentsize_;
	std::size_t size_;
};


class KeepConnection;


class NCModel
{
public:
	static NCModel *GetInstance() {
		if (!NCModel::this_ptr_)
			NCModel::this_ptr_ = new NCModel();
		return NCModel::this_ptr_;
	}

	inline void set_addr(const std::string &v) { this->addr_ = v; }
	inline void set_port(uint16_t v) { this->port_ = v; }
	inline void set_lic_response_time(time_t v) { this->lic_response_time_ = v; }
	inline void set_lic_local_valid_time(time_t v) { this->lic_local_valid_time_ = v; }
	inline void set_lic_status(bool v) { this->current_license_ = v; }
	inline void set_retry_interval(uint32_t v) { this->retry_interval_ = v; }
	inline void set_pid(uint32_t v) { this->pid_ = v; }
	inline void set_active_interval_max(uint32_t v) { this->active_interval_max_ = v; }
	inline void set_run(bool r) { this->run_control_flag_ = r; }
	inline void set_active_time(time_t t) { this->lic_active_time_ = t; }

	inline time_t lic_active_time() const { return this->lic_active_time_; }
	inline time_t lic_response_time() const { return this->lic_response_time_; }
	inline time_t lic_local_valid_time() const { return this->lic_local_valid_time_; }
	inline uint32_t pid()const { return this->pid_; }
	inline bool lic_status() const { return this->current_license_; }
	inline std::string addr() const { return this->addr_; }
	inline uint16_t port() const { return this->port_; }
	inline uint32_t retry_interval() const { return this->retry_interval_; }
	inline uint32_t active_interval_max() const { return this->active_interval_max_; }
	inline bool is_run() const { return this->run_control_flag_; }

protected:
	NCModel() {
		this->run_control_flag_ = false;
		check_in_op = false;
		gp_model = false;
		connptr = NULL;
	}

public:

	bool check_in_op;
	bool gp_model;
	int year;
	int month;
	int day;

	KeepConnection *connptr;

private:

	bool run_control_flag_;
	uint16_t port_;
	uint32_t retry_interval_;
	uint32_t pid_;
	uint32_t active_interval_max_;
	std::string addr_;
	time_t lic_active_time_;
	time_t lic_response_time_; // 获取许可时间
	time_t lic_local_valid_time_;
	bool current_license_; // 获取到许可
	static NCModel *this_ptr_;

};


class GracePeriodHandler
{

public:

	// 从本地读文件 判断GP模式是否有效 有效则进入

	static bool GPStatusValid() {
		bool ret = false;
		bool is_delete = false;
		HANDLE hx = CreateMutex(NULL, FALSE, L"GP_INFO_WREITE_M");
		if (hx && WaitForSingleObject(hx, 2) != WAIT_TIMEOUT)
		{
			FILE *fd;
			char *dive, *filename;
			char filepath[MAX_PATH];
			size_t size = 0;

			_dupenv_s(&dive, &size, "HOMEDRIVE");
			_dupenv_s(&filename, &size, "HOMEPATH");

			sprintf_s(filepath, "%s%s\\autodwg_%d.lic", dive, filename, NCModel::GetInstance()->pid());

			delete filename;
			delete dive;

			if (!fopen_s(&fd, filepath, "rb+")) {

				char buff[4096];
				fpos_t filesize = 0;
				if (0 == fseek(fd, 0, SEEK_END))
					fgetpos(fd, &filesize);
				fseek(fd, 0, SEEK_SET);

				std::string mac;
				GenMachineCode(mac);

				if (filesize >= sizeof(time_t) * 2 + mac.length() && filesize <= 4096 ) {
					size_t readl = fread(buff, 1, mac.length(), fd);
					buff[readl] = 0;
					if (mac == buff)
					{
						fread(buff, 1, filesize - mac.length(), fd);
						time_t ex, create, now;
						ex = *(time_t *)buff;
						create = *(time_t *)(((char *)buff) + sizeof(time_t));
						now = time(0);
						if (ex < now || create + GRACE_PERIOD_EXPIRE_SECOND < now)
							is_delete = true; // 文件存在且过期
						else
							ret = true;
					}
					else {
						is_delete = true;
					}
					
				}
				fclose(fd);
			}
		}
		ReleaseMutex(hx);
		CloseHandle(hx);

		if (is_delete) {
			GracePeriodHandler::Exit();
		}

		return ret;
	}

	static bool Entry() {

		if (!NCModel::GetInstance()->lic_status())
			return false;

		std::stringstream oss;
		time_t now = time(0);
		time_t ex = now + GRACE_PERIOD_EXPIRE_SECOND; //mktime(&t);

		HANDLE hx = CreateMutex(NULL, FALSE, L"GP_INFO_WREITE_M");
		if (hx && WaitForSingleObject(hx, 2) != WAIT_TIMEOUT)
		{
			FILE *fd;

			// 获取 homepath 目录
			char *dive,*filename;
			char filepath[MAX_PATH];
			size_t size = 0;

			_dupenv_s(&dive, &size, "HOMEDRIVE");
			_dupenv_s(&filename, &size, "HOMEPATH");

			sprintf_s(filepath, "%s%s\\autodwg_%d.lic", dive, filename, NCModel::GetInstance()->pid());

			delete filename;
			delete dive;

			if (!fopen_s(&fd, filepath, "wb")) {
				std::string mac;
				GenMachineCode(mac);
				fwrite(mac.c_str(), 1, mac.length(), fd);
				fwrite((const char *)&ex,1,sizeof(ex), fd);
				fwrite((const char *)&now, 1, sizeof(now), fd);
				fclose(fd);
			}
		}

		ReleaseMutex(hx);
		CloseHandle(hx);

		return GracePeriodHandler::GPStatusValid();
	}

	static void Exit() {
		HANDLE hx = CreateMutex(NULL, FALSE, L"GP_INFO_WREITE_M");
		if (hx && WaitForSingleObject(hx, 2) != WAIT_TIMEOUT)
		{
			DeleteFile(L"nomean.ls");
		}
		ReleaseMutex(hx);
		CloseHandle(hx);
	}
};

class Connection
{
public:

	Connection() :
		addr_(""),
		port_(0),
		socket_file_(INVALID_SOCKET)
	{

	}
	~Connection()
	{

	}

	void Init(const std::string &addr, const unsigned short port) {
		this->addr_ = addr_;
		this->port_ = port;
	}

	void Close() {
		this->open_close_mutex_.lock();
		if (this->socket_file_ != INVALID_SOCKET) {
			closesocket(this->socket_file_);
			this->socket_file_ = INVALID_SOCKET;
		}
		this->open_close_mutex_.unlock();
	}

	bool IsOpen() {
		return this->socket_file_ != INVALID_SOCKET;
	}

	bool Connect(const std::string &addr = "", const unsigned short port = 0) {
		if (this->addr_.empty() || this->port_ < 1024) {
			if (addr.empty() || port < 1024)
				return false;
		}

		if (this->IsOpen())
			return true;

		os << "正在连接服务器..." << str_date().c_str() << mtl_endl;

		this->addr_ = addr.empty() ? this->addr_ : addr;
		this->port_ = port < 1024 ? this->port_ : port;

		this->open_close_mutex_.lock();
		if ((socket_file_ = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET) {
			SOCKADDR_IN sin;
			sin.sin_family = AF_INET;
			sin.sin_port = htons(this->port_);
			sin.sin_addr.s_addr = inet_addr(this->addr_.c_str());
			//inet_pton(AF_INET, this->addr_.c_str(), &sin.sin_addr);
			if (0 != ::connect(socket_file_, (sockaddr *)&sin, sizeof(sockaddr))) {
				this->open_close_mutex_.unlock();
				this->Close();
				this->open_close_mutex_.lock();
				os << "服务器连接失败" << str_date().c_str() << mtl_endl;
			}
		}

		this->open_close_mutex_.unlock();

		if (this->IsOpen()) {
			os << "服务器连接成功" << str_date().c_str() << mtl_endl;
			// 发送PID 和 MAC 地址
			InitConnection ic;
			PACKET_HEADER_INIT(ic);
			std::string mac;
			GenMachineCode(mac);
			memset(ic.mac, 0, sizeof(ic.mac));
			memcpy(ic.mac, mac.c_str(), mac.length());

			// 计算机名
			memset(ic.computer, 0, sizeof(ic.computer));
			DWORD size = sizeof(ic.computer);
			int t = 0;
			::GetComputerNameExA((COMPUTER_NAME_FORMAT)t, ic.computer, &size);
			if (size < sizeof(ic.computer))
				ic.computer[size] = 0;

			ic.pid = NCModel::GetInstance()->pid();
			std::string tt;
			tt.assign((const char *)&ic, ic.length);
			this->SendSome(tt);
		}

		return this->IsOpen();
	}

	std::size_t ParserStream(const char *buffer, const std::size_t size, std::vector<std::string> &messages)
	{
		std::size_t offset = 0, usrs = 0, bsize = size;

		while (1) {

			offset += usrs = cache_packet_.fill_buffer(&buffer[offset], bsize);
			bsize -= usrs;

			if (cache_packet_.is_full()) {
				if (cache_packet_.valid_size() == sizeof(unsigned int)) {
					cache_packet_.extent_of_size(cache_packet_.length());
					continue;
				}
				messages.push_back(cache_packet_.str());
				cache_packet_.init();
			}

			if (!bsize)
				break;
		}

		return messages.size();
	}

	virtual int32_t ReadSome(std::string &buffer) {
		if (this->IsOpen()) {
			char buff[4096];
			int32_t r = ::recv(this->socket_file_, buff, sizeof(buff), 0);
			if (r > 0) {
				buffer = "";
				buffer.assign(buff, r);
				return r;
			}
			return r;
		}
		//pass
		return 0;
	}

	virtual int32_t SendSome(std::string &buffer) {
		if (this->IsOpen()) {
			return send(this->socket_file_, buffer.c_str(), (int )buffer.length(), 0);
		}
		return 0;
	}

private:

	std::string addr_;
	unsigned short port_;
	NetPacket cache_packet_;
	SimpleMutex open_close_mutex_;
	SOCKET socket_file_;
};



NCModel *NCModel::this_ptr_ = NULL;

class KeepConnection : public Connection
{
public:

	class TimerHandler
	{
	public:
		virtual void do_time_event(KeepConnection *p) = 0;
	};

	static int32_t __timer_work_thread(void *p) {

		KeepConnection *this_ptr = static_cast<KeepConnection *>(p);
		uint32_t reconnect_count = 0;
		while (NCModel::GetInstance()->is_run()) {
			Sleep(1000);
			this_ptr->KeepAliveTimer(reconnect_count);
			this_ptr->TimerEvent();
		}
		return 0;
	}

	KeepConnection():timer_ptr_(0){

	}

	void TimerEvent() {
		if (timer_ptr_) {
			timer_ptr_->do_time_event(this);
		}
	}

	inline void set_timer(TimerHandler *p) { this->timer_ptr_ = p; }

	void KeepAliveTimer( uint32_t &reconnect_count) {
		// 心跳计数器
		this->safe_set_active_time(this->r_active_tick_tm_ + 1);
		// 重连计数器
		reconnect_count = this->IsOpen() ? 0 : ++reconnect_count;
		// 超过重连时间
		// 长时间没有收到心跳包 重连
		if (reconnect_count >= NCModel::GetInstance()->retry_interval() ||
			this->r_active_tick_tm_ >= NCModel::GetInstance()->active_interval_max()) {
			this->safe_set_active_time(0);
			reconnect_count = 0;
			if (this->IsOpen())
				this->Close();
			this->Connect();
		}
	}


	inline int32_t safe_set_active_time(const int32_t active) {
		count_mutex_.lock();
		this->r_active_tick_tm_ = active;
		count_mutex_.unlock();
		return this->r_active_tick_tm_;
	}

	bool do_keep_runner() {
		HANDLE h = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&__timer_work_thread, this, 0, 0);
		if (h) {
			CloseHandle(h);
			return true;
		}
		return false;
	}

	int32_t ReadSome(std::string &buffer) {
		int32_t t = Connection::ReadSome(buffer);
		if (t > 0)
			this->safe_set_active_time(0);
		return t;
	}

	int32_t SendSome(std::string &buffer) {
		return Connection::SendSome(buffer);
	}

private:
	uint32_t r_active_tick_tm_;
	SimpleMutex count_mutex_;
	TimerHandler *timer_ptr_;
};


class LicenseMgr : public KeepConnection::TimerHandler
{
public:

	LicenseMgr() :last_requset_time_(0) {

	}

	void do_time_event(KeepConnection *conn) {

		// 一般情况下定时器一秒钟触发一次
		time_t now = time(0);

		if (NCModel::GetInstance()->check_in_op) {
			NCModel::GetInstance()->check_in_op = false;
			LicenseCheckin in;
			PACKET_HEADER_INIT(in);
			std::string packet;
			packet.assign((char *)&in, in.length);
			conn->SendSome(packet);
		}

		if (!conn->IsOpen()) {
			// 如果网络断开情况下不获取授权信息，重置获取授权时间
			last_requset_time_ = time(0);
		}
		else {

			// 网络状态下始终记录GP信息 checkin 后删除
			GracePeriodHandler::Entry();

			// 大于30秒重新获取授权
			if (now - NCModel::GetInstance()->lic_response_time() > last_requset_time_) {
				last_requset_time_ = time(0);
				NCModel::GetInstance()->set_active_time(time(0));
				//重新获取授权
				LicenceReq req;
				req.opcode = PID_REQUEST_LICENSE;
				req.pid = NCModel::GetInstance()->pid();
				req.length = sizeof(LicenceReq);
				std::string buffer;
				buffer.assign((char *)&req, sizeof(req));
				os << "正在获取授权" << str_date().c_str() << mtl_endl;
				conn->SendSome(buffer);
			}
		}

		// 判断授权有效时间
		if (now - NCModel::GetInstance()->lic_active_time() > NCModel::GetInstance()->lic_local_valid_time()  &&
			NCModel::GetInstance()->lic_status() &&
			// 非GP模式下
			!GracePeriodHandler::GPStatusValid()) {
			// 服务器超时没有返回
			os << "授权过期" << str_date().c_str() << mtl_endl;
			NCModel::GetInstance()->set_lic_status(false);
		}

	}

private:
	time_t last_requset_time_;

};

void message_handler(const char *buffer, std::size_t size, Connection *io_instance_ptr) {
	
	PacketHead *phead = (PacketHead *)buffer;

	switch (phead->opcode)
	{
	case PID_LICENSE_ERROR:
	{
		LicenseError *pres = (LicenseError *)phead;
		switch (pres->error)
		{
		case LICENSE_ACTIVE_SUCCESS:
			os << "授权成功" << str_date().c_str() << mtl_endl;
			NCModel::GetInstance()->year = pres->year;
			NCModel::GetInstance()->month = pres->month;
			NCModel::GetInstance()->day = pres->day;
			NCModel::GetInstance()->set_lic_status(true);
			break;
			// 许可错误
		case LICENSE_LIMIT_MAX_SIZE:
		case LICENSE_CODE_INVALID:	
		{
			NCModel::GetInstance()->set_lic_status(false);
			GracePeriodHandler::Exit();
		}
			break;
		default:
			break;
		}
	}
	break;
	case PID_DEVICE_CHECKIN:
		NCModel::GetInstance()->set_lic_status(false);
		GracePeriodHandler::Exit();
		break;
	default:
		break;
	}
}

int32_t dllrun(void *p)
{
	NCModel::GetInstance()->connptr = new KeepConnection();

	// 失败后根据重试间隔自动重连,所以不判断返回值
	NCModel::GetInstance()->connptr->Connect(NCModel::GetInstance()->addr(),
		NCModel::GetInstance()->port());
	NCModel::GetInstance()->connptr->set_timer(new LicenseMgr());
	NCModel::GetInstance()->connptr->do_keep_runner();

	std::string buff_stream;
	std::vector<std::string > messages;
	while (NCModel::GetInstance()->is_run()) {

		if (!NCModel::GetInstance()->connptr->IsOpen()) {
			Sleep(1000);
			continue;
		}

		buff_stream = "";
		if (NCModel::GetInstance()->connptr->ReadSome(buff_stream) < 1) {
			if(NCModel::GetInstance()->connptr->IsOpen())
				NCModel::GetInstance()->connptr->Close();
			continue;
		}

		messages.clear();
		if (NCModel::GetInstance()->connptr->ParserStream(buff_stream.c_str(), buff_stream.length(), messages)) {
			for (int i = 0; i != messages.size(); ++i) {
				message_handler(messages[i].c_str(), messages[i].length(), NCModel::GetInstance()->connptr);
			}
		}
	}

	return 0;
}

LICENSE_API bool lic_license()
{
	return NCModel::GetInstance()->lic_status();
}

LICENSE_API void lic_check_in()
{
	// 清除本地 GP 状态
	if (NCModel::GetInstance()->lic_status()) {
		NCModel::GetInstance()->check_in_op = true;
		// 设置chekcout的时间30天
		NCModel::GetInstance()->set_lic_response_time(GRACE_PERIOD_EXPIRE_SECOND);
		int c = 5;
		while (c-- && NCModel::GetInstance()->lic_status())
			Sleep(1000);
	}
}

LICENSE_API void reset_endpoint(const char *addr, const unsigned short port)
{
	NCModel::GetInstance()->set_addr(addr);
	NCModel::GetInstance()->set_port(port);
	if(NCModel::GetInstance()->connptr->IsOpen())
		NCModel::GetInstance()->connptr->Close();
	NCModel::GetInstance()->connptr->Connect(addr, port);
}

LICENSE_API void lic_init(const char *addr, unsigned short port, const int pid, const int req_time, const int local_valid_time )
{
	SimpleMutex mutex;
	mutex.lock();
	if (!NCModel::GetInstance()->is_run()) {

		/*DumpProcessFile d;
		d.Setup();*/
		// 项目ID
		NCModel::GetInstance()->set_pid(pid);

		NCModel::GetInstance()->set_run(true);

		//初始化winsock
		WSADATA WSAData;
		WSAStartup(MAKEWORD(2, 2), &WSAData);

		std::string addrs = addr;

		NCModel::GetInstance()->set_lic_status(GracePeriodHandler::GPStatusValid());

		NCModel::GetInstance()->set_addr(addrs);
		NCModel::GetInstance()->set_port(port);
		NCModel::GetInstance()->set_active_time(0);
		//设置重连时间
		NCModel::GetInstance()->set_retry_interval(10);
		//设置心跳时间
		NCModel::GetInstance()->set_active_interval_max(180);
		// 循环获取许可证时间
		NCModel::GetInstance()->set_lic_response_time(req_time);
		// 没有获得许可证的情况下，上一次许可证的有最长效时间
		NCModel::GetInstance()->set_lic_local_valid_time(local_valid_time);
		
		// 创建获取许可的工作线程
		HANDLE h = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)dllrun, NULL, NULL, NULL);
		if (h) {
			CloseHandle(h);
		}
	}
	mutex.unlock();

}

LICENSE_API void free_log_stream(const char *s)
{
	delete s;
}

LICENSE_API const char *log_stream()
{
	std::string str;
	os.GetAll(str);
	if (str.length()) {
		char *buffer = new char[str.length() + 1];
		memcpy(buffer, str.c_str(), str.length() + 1);
		return buffer;
	}
	return NULL;
}