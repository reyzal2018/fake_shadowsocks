#include "common.h"
#include "udp_relay.h"


// SOCKS5 UDP Request
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// SOCKS5 UDP Response
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// shadowsocks UDP Request (before encrypted)
// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+

// shadowsocks UDP Response (before encrypted)
// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+

// shadowsocks UDP Request and Response (after encrypted)
// +-------+--------------+
// |   IV  |    PAYLOAD   |
// +-------+--------------+
// | Fixed |   Variable   |
// +-------+--------------+


UDPRelay::UDPRelay(Config * config, DNSResolve * dns_resolver, bool is_local)
{
    this->config_ = config;
    if (is_local)
    {
        listen_addr_ = config_->GetStr("local_address");
        listen_port_ = config_->GetInt("local_port");
        remote_addr_ = config_->GetStr("server_address");
        remote_port_ = config_->GetInt("server_port");
    }
    else
    {
        listen_addr_ = config_->GetStr("server_address");
        listen_port_ = config_->GetInt("server_port");
        remote_addr_ = "";
        remote_port_ = 0;
    }

    dns_resolver_ = dns_resolver;
    is_local_ = is_local;
    is_closed_ = false;
    this->event_loop_ = NULL;
}

bool UDPRelay::Init()
{
    server_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_socket_ == INVALID_SOCKET)
        return false;
    struct sockaddr_in service;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, listen_addr_.c_str(), &service.sin_addr.s_addr);
    service.sin_port = htons(listen_port_);

    if (0 != bind(server_socket_, (sockaddr *)&service,
                  sizeof(service)))
    {
        return false;
    }
    SetNoBlocking(server_socket_);
    return true;
}

void UDPRelay::SelectAServer()
{
    select_server_ = config_->GetStr("server_address");
    select_port_ = config_->GetInt("server_port");
}

UDPRelay::~UDPRelay()
{
}

void UDPRelay::HandleServer()
{
    vector<char> data(kBuffSize);
    sockaddr_in addr;
    int addr_len = sizeof(sockaddr_in);
    int recv_len = BufferRecvFrom(server_socket_, &data[0], kBuffSize, (sockaddr*)&addr, &addr_len);
    if (recv_len <= 0)
    {
        LOGW << "UDP handle_server: data is empty";
        return;
    }
    data.resize(recv_len);
    if (is_local_)
    {
        if (data[2] != 0)
        {
            LOGW << "UDP drop a message since frag is not 0";
        }
        else
        {
            data.erase(data.begin(), data.begin() + 2);
        }
    }
    else
    {
        //TODO decrypt data
    }
    Sock5Header header_result;
    if (!ParseHeader(data, &header_result))
    {
        LOGE << "can not parse header";
        return;
    }
    LOGI << "udp data to " << header_result.remote_addr <<
         header_result.remote_port << "from " <<
         addr.sin_addr.s_addr << ":" << addr.sin_port;
    if (is_local_)
    {
        SelectAServer();
    }
    else
    {
        select_server_ = header_result.remote_addr;
        select_port_ = header_result.remote_port;
    }
    if (dns_cache_.count(select_server_) == 0)
    {
        string ip = GetIpByHostName(select_server_);
        dns_cache_[select_server_] = ip;
    }
    string ip = dns_cache_[select_server_];
    string key = GetClientKey(addr, AF_INET);
    if (key_sockets_.count(key) == 0)
    {
        SOCKET s;
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SetNoBlocking(server_socket_);
        key_sockets_[key] = s;
        socket_to_addr_[s] = addr;
        sockets_.insert(s);
        event_loop_->Add(s, kPollIn, this);
    }
    SOCKET new_socket = key_sockets_[key];
    if (is_local_)
    {
        //TODO encrypt
    }
    else
    {
        data.erase(data.begin(), data.begin() + header_result.header_length);
    }
    if (data.size() == 0)
    {
        return;
    }
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(select_port_);
    inet_pton(AF_INET, select_server_.c_str(), &server_addr.sin_addr);
    BufferSendTo(new_socket, &data[0], data.size(), (sockaddr*)&server_addr, sizeof(server_addr));
}

string UDPRelay::GetClientKey(sockaddr_in dest_addr, int server_af)
{
    stringstream ss;
    ss << dest_addr.sin_addr.s_addr << ":" <<
       dest_addr.sin_port << ":" << server_af;
    return ss.str();
}

void UDPRelay::HandleClient(SOCKET s)
{
    vector<char> data(kBuffSize);
    sockaddr_in addr;
    int addr_len = sizeof(sockaddr_in);
    int recv_len = BufferRecvFrom(server_socket_, &data[0], kBuffSize, (sockaddr*)&addr, &addr_len);
    if (recv_len <= 0)
    {
        LOGW << "UDP handle_client: data is empty";
        return;
    }
    if (!is_local_)
    {
        char response[7] = {0x01 };
        memcpy(&response[1], &addr.sin_addr, 4);
        memcpy(&response[5], &addr.sin_port, 2);
        data.insert(data.begin(), &response[0], &response[7]);
    }
    else
    {
        Sock5Header header_result;
        if (!ParseHeader(data, &header_result))
        {
            LOGW << "can not parse header";
            return;
        }
        char response[3] = { 0x00, 0x00, 0x00 };
        data.insert(data.begin(), &response[0], &response[7]);
    }
    if (socket_to_addr_.count(s) > 0)
    {
        sockaddr_in client_addr =  socket_to_addr_[s];
        LOGI << "sendto UDP";
        BufferSendTo(server_socket_, &data[0], data.size(), (sockaddr*)&client_addr, sizeof(sockaddr_in));
    }
}

void UDPRelay::HandleEvent(SOCKET s, int event)
{
    if (s == server_socket_)
    {
        if (event & kPollErr)
        {
            LOGI << "UDP server_socket err";
        }
        HandleServer();
    }
    else if(s != INVALID_SOCKET &&
            sockets_.find(s) != sockets_.end())
    {
        if (event & kPollErr)
        {
            LOGI << "UDP client_socket err";
        }
        HandleClient(s);
    }
}

bool UDPRelay::AddToLoop(EventLoop * event_loop)
{
    if (event_loop_)
    {
        LOGW << "already add to loop";
        return false;
    }
    if (is_closed_)
    {
        LOGW << "already closed";
        return false;
    }
    event_loop_ = event_loop;
    event_loop_->Add(server_socket_, kPollIn | kPollErr, this);
    return true;
}
