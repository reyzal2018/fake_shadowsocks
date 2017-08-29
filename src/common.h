#ifndef _COMMON_H_
#define _COMMON_H_

#include <list>
#include <iostream>
#include <set>
#include <map>
#include <vector>
#include <cassert>
#include <string>
#include <sstream>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/timeb.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
typedef int SOCKET;
#define INVALID_SOCKET -1
#endif

using namespace std;

#include "log.hpp"
#include "getopt.h"


const int kUpStreamBufSize = 16 * 1024;
const int kDownStreamBufSize = 32 * 1024;
const int kBuffSize = 16 * 1024;

enum SOCKET_OP
{
    kPollNull = 0x00,
    kPollIn = 0x01,
    kPollOut = 0x04,
    kPollErr = 0x08,
    kPollHup = 0x10,
    kPollNval = 0x20
};


class ISockNotify
{
public:
    ISockNotify() {};
    virtual ~ISockNotify() {};
    //invoke when socket has signaled
    virtual void HandleEvent(SOCKET s, int event) = 0;

};

class IPeriodicNotify
{
public:
    IPeriodicNotify() {};
    virtual ~IPeriodicNotify() {};
    //invoke when socket has signaled
    virtual void HandlePeriodic() = 0;
};

class IDNSNotify
{
public:
    IDNSNotify() {};
    virtual ~IDNSNotify() {};
    //invoke when dns has resolved
    virtual void DNSResolved(string hostname, string ip, string err) = 0;
};


enum
{
    ADDRTYPE_IPV4 = 0x01,
    ADDRTYPE_IPV6 = 0x04,
    ADDRTYPE_HOST = 0x03,
    ADDRTYPE_AUTH = 0x10,
    ADDRTYPE_MASK = 0xF
};

struct Sock5Header
{
    int addrtype;
    string remote_addr;
    int remote_port;
    size_t header_length;
};

bool ParseHeader(vector<char>& data, Sock5Header* header);

string GetIpByHostName(const string& host);

bool IsIp(const char* ip);

int SetNoBlocking(SOCKET s);

int SetReUseAddr(SOCKET s);

int BufferSend(SOCKET s, char* buffer, int len);

int BufferRecv(SOCKET s, char* buffer, int len);

bool SocketIsBlock(SOCKET s);

void FsSleep(uint32_t ms);

int GetSocketErrorCode();

void CloseSocket(SOCKET s);

int64_t GetTimeStamp();

int BufferSendTo(SOCKET s, char* buffer, int len, const struct sockaddr *to, int tolen);

int BufferRecvFrom(SOCKET s, char* buffer, int len, struct sockaddr *from, int *fromlen);

int GetPeerName(SOCKET s, struct sockaddr *name, int	*namelen);

#include "config.h"
#include "lrucache.h"
#include "event_loop.h"
#include "dns_resolve.h"
#include "tcp_relay.h"
#include "udp_relay.h"

#endif
