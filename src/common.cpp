#include "common.h"

bool ParseHeader(vector<char>& data, Sock5Header * header)
{
    if (data.size() == 0) return false;
    char addrtype = data[0];
    string dest_addr;
    int dest_port;
    size_t header_length = 0;
    if ((addrtype & ADDRTYPE_MASK) == ADDRTYPE_IPV4)
    {
        if (data.size() > 7)
        {
            char buf[30];
            if (NULL == inet_ntop(AF_INET, &data[1], buf, 30))
                return false;
            dest_addr = buf;
            dest_port = *(unsigned char*)(&data[5]) * 256 + *(unsigned char*)(&data[6]);
            header_length = 7;
        }
        else
        {
            LOGW << "header is too short\n";
        }
    }
    else if ((addrtype & ADDRTYPE_MASK) == ADDRTYPE_HOST)
    {
        if (data.size() > 2)
        {
            size_t addrlen = data[1];
            if (data.size() >= 4 + addrlen)
            {
                dest_addr = string(&data[2], &data[2 + addrlen]);
                dest_port = *(unsigned char*)(&data[2 + addrlen]) * 256 + *(unsigned char*)(&data[3 + addrlen]);
                header_length = 4 + addrlen;
            }
        }
        else
            LOGW << "header is too short\n";
    }
    else if ((addrtype & ADDRTYPE_MASK) == ADDRTYPE_IPV6)
    {
        if (data.size() >= 19)
        {
            char buf[30];
            if (NULL == inet_ntop(AF_INET6, &data[1], buf, 30))
                return false;
            dest_addr = buf;
            dest_port = *(unsigned char*)(&data[17]) * 256 + *(unsigned char*)(&data[18]);
            header_length = 19;
        }
        else
            LOGW << "header is too short\n";
    }
    else
        LOGW << "unsupported addrtype %d, maybe wrong password or encryption method" << addrtype<<"\n";
    if (dest_addr.empty())
        return false;
    header->addrtype = addrtype;
    header->header_length = header_length;
    header->remote_addr = dest_addr;
    header->remote_port = dest_port;
    return true;
}

string GetIpStr(const struct sockaddr *sa)
{
    char s[100];
    int maxlen = 100;
    switch (sa->sa_family)
    {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                  s, maxlen);
        break;

    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                  s, maxlen);
        break;

    default:
        LOGI << "Unknown AF\n";
        return NULL;
    }

    return s;
}

string GetIpByHostName(const string& host)
{
    string result = "";
    addrinfo *addr;
    int err = getaddrinfo(host.c_str(), NULL, NULL, &addr);
    if (err == 0)
    {
        for (addrinfo *res = addr; res != NULL; res = res->ai_next)
        {
            result = GetIpStr(res->ai_addr);
            break;
        }
    }
    LOGI << "resolve " << host << ":" << result<<"\n";
    return result;
}

bool IsIp(const char* ip)
{
    in_addr addr;
    if (1 == inet_pton(AF_INET, ip, &addr))
        return true;
    in6_addr addr6;
    if (1 == inet_pton(AF_INET6, ip, &addr6))
        return true;
    return false;
}

int SetNoBlocking(SOCKET s)
{
#ifdef _WIN32
    unsigned long nonblocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonblocking) == SOCKET_ERROR)
    {
        LOGW << "ioctlsocket failed\n";
        return -1;
    }
#else
    int flags;
    if ((flags = fcntl(s, F_GETFL, NULL)) < 0)
    {
        LOGW << "fcntl(" << s << ", F_GETFL)\n";
        return -1;
    }
    if (!(flags & O_NONBLOCK))
    {
        if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            LOGW << "fcntl(" << s << ", F_SETFL)\n";
            return -1;
        }
    }
#endif
    return 0;
}

int SetReUseAddr(SOCKET s)
{
    //允许端口重用
    unsigned value = 1;
    return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&value, sizeof(value));
}


int BufferSend(SOCKET s, char* buffer, int len)
{
    int n = -1;
#ifdef _WIN32
    n = send(s, buffer, len, 0);
#else
    n = write(s, buffer, len);
#endif
    return n;
}

int BufferRecv(SOCKET s, char* buffer, int len)
{
    int n = -1;
#ifdef _WIN32
    n = recv(s, buffer, len, 0);
#else
    n = read(s, buffer, len);
#endif
    return n;
}

int BufferSendTo(SOCKET s, char* buffer, int len, const struct sockaddr *to, int tolen)
{
    int n = -1;
#ifdef _WIN32
    n = sendto(s, buffer, len, 0, to, tolen);
#else
    n = sendto(s, buffer, len, 0, to, (socklen_t)tolen);
#endif
    return n;
}

int BufferRecvFrom(SOCKET s, char* buffer, int len, struct sockaddr *from, int *fromlen)
{
    int n = -1;
#ifdef _WIN32
    n = recvfrom(s, buffer, len, 0, from, fromlen);
#else
    n = recvfrom(s, buffer, len, 0, from, (socklen_t*)fromlen);
#endif
    return n;
}

bool SocketIsBlock(SOCKET s)
{
    bool blocked = false;
#ifdef _WIN32
    int err = WSAGetLastError();
    blocked = (err == WSAEINPROGRESS || err == WSAEWOULDBLOCK);
#else
    blocked = (errno == EINPROGRESS);
#endif
    return blocked;
}

void FsSleep(uint32_t ms)
{
#ifdef _WIN32
    ::Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

int GetSocketErrorCode()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

void CloseSocket(SOCKET s)
{
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

int64_t GetTimeStamp()
{
#ifdef _WIN32
    _timeb timebuffer;
    _ftime64_s(&timebuffer);
    return timebuffer.time * 1000 + timebuffer.millitm;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return  tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

int GetPeerName(SOCKET s, struct sockaddr *name, int	*namelen)
{
#ifdef _WIN32
    return getpeername(s, name, namelen);
#else
    return getpeername(s, name, (socklen_t*)namelen);
#endif
}

