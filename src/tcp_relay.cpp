#include "common.h"
#include "tcp_relay.h"

// for each opening port, we have a TCP Relay

// for each connection, we have a TCP Relay Handler to handle the connection

// for each handler, we have 2 sockets:
//    local:   connected to the client
//    remote:  connected to remote server

// for each handler, it could be at one of several stages:

// as sslocal:
// stage 0 auth METHOD received from local, reply with selection message
// stage 1 addr received from local, query DNS for remote
// stage 2 UDP assoc
// stage 3 DNS resolved, connect to remote
// stage 4 still connecting, more data from local received
// stage 5 remote connected, piping local and remote

// as ssserver:
// stage 0 just jump to stage 1
// stage 1 addr received from local, query DNS for remote
// stage 3 DNS resolved, connect to remote
// stage 4 still connecting, more data from local received
// stage 5 remote connected, piping local and remote
enum STAGE
{
    kStageInit = 0,
    kStageAddr = 1,
    kStageUdpAssoc = 2,
    kStageDns = 3,
    kStageConnecting = 4,
    kStageStream = 5,
    kStageDestroyed = -1
};


// SOCKS METHOD definition
const int kMethodNoauth = 0;

// SOCKS command definition
enum SOCKS_COMMAND
{
    kCmdConnect = 1,
    kCmdBind = 2,
    kCmdUdpAssociate = 3
};

// for each handler, we have 2 stream directions:
//    upstream:    from client to server direction
//                 read local and write to remote
//    downstream:  from server to client direction
//                 read remote and write to local

const int kStreamUp = 0;
const int kStreamDown = 1;

// for each stream, it's waiting for reading, or writing, or both
const int kWaitStatusInit = 0;
const int kWaitStatusReading = 1;
const int kWaitStatusWriting = 2;
const int kWaitStatusReadWriting = kWaitStatusReading | kWaitStatusWriting;


TCPRelayHandler::TCPRelayHandler(TCPRelay * server,
                                 EventLoop * event_loop,
                                 DNSResolve* dns_resolver,
                                 SOCKET local_socket,
                                 Config * config,
                                 bool is_local):
    server_(server),
    event_loop_(event_loop),
    dns_resolver_(dns_resolver),
    local_socket_(local_socket),
    remote_socket_(INVALID_SOCKET),
    config_(config),
    is_local_(is_local),
    stage_(kStageInit),
    upstream_status_(kWaitStatusReading),
    downstream_status_(kWaitStatusInit),
    recv_data_size(0),
    send_data_size(0)
{
    if (is_local_)
    {
        SelectAServer();
    }
    SetNoBlocking(local_socket_);

    int addr_len = sizeof(sockaddr_in);
    sockaddr_in addr;
    GetPeerName(local_socket_, (sockaddr*)&addr, &addr_len);
    char buf[30];
    inet_ntop(addr.sin_family, &addr.sin_addr, buf, 30);
    local_address_ = buf;
    local_port_ = addr.sin_port;

    event_loop_->Add(local_socket_, kPollIn | kPollErr, static_cast<ISockNotify*>(this->server_));
    server_->AddHandler(local_socket_, this);
}

void TCPRelayHandler::SelectAServer()
{
    remote_address_ = config_->GetStr("server_address");
    remote_port_ = config_->GetInt("server_port");
}

void TCPRelayHandler::UpdateStream(int stream, int status)
{
    bool dirty = false;
    if (stream == kStreamDown)
    {
        if (downstream_status_ != status)
        {
            downstream_status_ = status;
            dirty = true;
        }
    }
    else if (stream == kStreamUp)
    {
        if (upstream_status_ != status)
        {
            upstream_status_ = status;
            dirty = true;
        }
    }
    if (!dirty) return;
    if (local_socket_ != INVALID_SOCKET)
    {
        int event = kPollErr;
        if (downstream_status_ & kWaitStatusWriting)
            event |= kPollOut;
        if (upstream_status_ & kWaitStatusReading)
            event |= kPollIn;
        event_loop_->Modify(local_socket_, event);
    }
    if (remote_socket_ != INVALID_SOCKET)
    {
        int event = kPollErr;
        if (downstream_status_ & kWaitStatusReading)
            event |= kPollIn;
        if (upstream_status_ & kWaitStatusWriting)
            event |= kPollOut;
        event_loop_->Modify(remote_socket_, event);
    }
}

bool TCPRelayHandler::WriteToSock(vector<char>& data, SOCKET s)
{
    if (data.empty() || s == INVALID_SOCKET)
        return true;
    bool uncomplete = false;
    int ret = BufferSend(s, &data[0], data.size());
    if (ret == -1)
    {
        if (!SocketIsBlock(s))
        {
            this->Destroy();
            return false;
        }
        else
        {
            uncomplete = true;
        }
    }
    else if (ret >= 0 && (size_t)ret < data.size())
    {
        uncomplete = true;
    }
    if (ret >= 0)
    {
        data.erase(data.begin(), data.begin() + ret);
    }
    if (ret > 0 && s == local_socket_)
        send_data_size += ret;
    if (uncomplete)
    {
        if (s == local_socket_)
        {
            this->data_write_to_local_.insert(data_write_to_local_.end(), data.begin(), data.end());
            UpdateStream(kStreamDown, kWaitStatusWriting);
        }
        else if (s == remote_socket_)
        {
            this->data_write_to_remote_.insert(data_write_to_remote_.end(), data.begin(), data.end());
            UpdateStream(kStreamUp, kWaitStatusWriting);
        }
    }
    else
    {
        if (s == local_socket_)
        {
            UpdateStream(kStreamDown, kWaitStatusReading);
        }
        else if (s == remote_socket_)
        {
            UpdateStream(kStreamUp, kWaitStatusReading);
        }
    }
    return true;
}

void TCPRelayHandler::HandleStageConnecting(vector<char>& data)
{
    if (!is_local_)
    {
        data_write_to_remote_.insert(data_write_to_remote_.end(), data.begin(), data.end());
        return;
    }
    //TODO encrypt
    data_write_to_remote_.insert(data_write_to_remote_.end(), data.begin(), data.end());

}

void TCPRelayHandler::HandleStageAddr(vector<char>& data)
{
    if (is_local_)
    {
        uint8_t cmd = data[1];
        if (cmd == kCmdUdpAssociate)
        {
            LOGI << "UDP associate\n";
            char response_data[10] = {0x05, 0x00, 0x00, 0x01};
            unsigned long ipaddr;
            inet_pton(AF_INET, local_address_.c_str(), &ipaddr);
            memcpy(&response_data[4], &ipaddr, 4);
            memcpy(&response_data[8], &local_port_, 2);
            vector<char> response(&response_data[0], &response_data[10]);
            WriteToSock(response, local_socket_);
            stage_ = kStageUdpAssoc;
            //just wait for the client to disconnect
            return;
        }
        else if (cmd == kCmdConnect)
        {
            //just trim VER CMD RSV
            data.erase(data.begin(), data.begin() + 3);
        }
        else
        {
            LOGW << "unknown command " << cmd << "\n";
            this->Destroy();
            return;
        }
    }
    Sock5Header header_result;
    if (!ParseHeader(data, &header_result))
    {
        LOGW << "unknown header \n";
        this->Destroy();
        return;
    }
    LOGI << "connecting " << header_result.remote_addr << ":" << header_result.remote_port << "\n";
    UpdateStream(kStreamUp, kWaitStatusWriting);
    stage_ = kStageDns;

    if (is_local_)
    {
        //jump over socks5 response
        char response_data[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10 };
        vector<char> response(&response_data[0], &response_data[10]);
        if (!WriteToSock(response, local_socket_))
            return;
        data_write_to_remote_.insert(
            data_write_to_remote_.end(),
            data.begin(),
            data.end());
        //dns resolve
        dns_resolver_->Resolve(this->remote_address_, this);
    }
    else
    {
        if (data.size() > header_result.header_length)
        {
            data_write_to_remote_.insert(
                data_write_to_remote_.end(),
                data.begin() + header_result.header_length,
                data.end());
        }
        this->remote_address_ = header_result.remote_addr;
        this->remote_port_ = header_result.remote_port;
        dns_resolver_->Resolve(header_result.remote_addr, this);
    }
}

SOCKET TCPRelayHandler::CreateRemoteSocket(string ip, int port)
{
    addrinfo hints;
    addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    stringstream ss;
    ss << port;
    int ret = getaddrinfo(ip.c_str(), ss.str().c_str(), &hints, &result);
    if (result == NULL)
    {
        LOGW << "getaddrinfo failed for " << ip << ":" << port << "\n";
        return INVALID_SOCKET;
    }
    remote_socket_ = socket(result[0].ai_family, result[0].ai_socktype, result[0].ai_protocol);
    SetNoBlocking(remote_socket_);
    server_->AddHandler(remote_socket_, this);
    freeaddrinfo(result);
    return remote_socket_;
}

void TCPRelayHandler::HandleStageStream(vector<char>& data)
{
    if (is_local_)
    {
        //TODO encrypt
        WriteToSock(data, remote_socket_);
    }
    else
    {
        WriteToSock(data, remote_socket_);
    }
}

void TCPRelayHandler::CheckAuthMethod(vector<char>& data)
{
    // VER, NMETHODS, and at least 1 METHODS
    if (data.size() < 3)
    {
        LOGE << "method selection header too short\n";
        throw BadSocksHeader();
    }
    char socks_version = data[0];
    char nmethods = data[1];
    if (socks_version != 5)
    {
        LOGE << "unsupported SOCKS protocol version " << (int)socks_version << "\n";
        throw BadSocksHeader();
    }
    if (nmethods < 1 || data.size() != nmethods + 2)
    {
        LOGE << "NMETHODS and number of METHODS mismatch\n";
        throw BadSocksHeader();
    }
    bool noauth_exist = false;
    for (size_t i = 2; i < data.size(); i++)
    {
        if (data[i] == kMethodNoauth)
        {
            noauth_exist = true;
            break;
        }
    }
    if (!noauth_exist)
    {
        LOGE << "none of SOCKS METHOD\'s "
             "requested by client is supported'\n";
        throw NoAcceptableMethods();
    }
}

void TCPRelayHandler::HandleStageInit(vector<char>& data)
{
    try
    {
        CheckAuthMethod(data);
    }
    catch (const BadSocksHeader)
    {
        this->Destroy();
    }
    catch (const NoAcceptableMethods)
    {
        char data1[2] = { (char)0x05, (char)0xff };
        vector<char> response(&data[0], &data[2]);
        WriteToSock(response, local_socket_);
        if(!IsDestroyed())
            this->Destroy();
    }
    char data2[2] = { (char)0x05, (char)0x00 };
    vector<char> response(&data2[0], &data2[2]);
    if(WriteToSock(response, local_socket_))
        stage_ = kStageAddr;
}

void TCPRelayHandler::OnLocalRead()
{
    // handle all local read events and dispatch them to methods for
    // each stage
    if (local_socket_ == INVALID_SOCKET)
    {
        return;
    }
    bool is_local = this->is_local_;
    int buf_size;
    if (is_local)
        buf_size = kUpStreamBufSize;
    else
        buf_size = kDownStreamBufSize;
    vector<char> data(buf_size);
    int ret = BufferRecv(local_socket_, &data[0], buf_size);
    if (ret == -1)
    {
        if (SocketIsBlock(local_socket_))
        {
            return;
        }
    }
    if (ret <= 0)
    {
        this->Destroy();
        return;
    }
    data.resize(max(0, ret));
    if (!is_local)
    {
        //TODO data = self._cryptor.decrypt(data)
    }
    if (stage_ == kStageStream)
    {
        HandleStageStream(data);
        return;
    }
    else if (is_local && stage_ == kStageInit)
    {
        // jump over socks5 init
        HandleStageInit(data);
    }
    else if (stage_ == kStageConnecting)
    {
        HandleStageConnecting(data);
    }
    else if ((is_local && stage_ == kStageAddr) ||
             (!is_local && stage_ == kStageInit))
    {
        HandleStageAddr(data);
    }
}

void TCPRelayHandler::OnRemoteRead()
{
    // handle all remote read events
    int buf_size = 0;
    if (is_local_)
        buf_size = kUpStreamBufSize;
    else
        buf_size = kDownStreamBufSize;
    vector<char> data(buf_size);
    int ret = BufferRecv(remote_socket_, &data[0], buf_size);
    if (ret == -1)
    {
        if (SocketIsBlock(remote_socket_))
        {
            return;
        }
    }
    if (ret <= 0)
    {
        this->Destroy();
        return;
    }
    data.resize(max(ret, 0));
    /*
    if (is_local)
    data = self._cryptor.decrypt(data);
    else
    data = self._cryptor.encrypt(data);
    */
    recv_data_size += ret;
    WriteToSock(data, local_socket_);
}

void TCPRelayHandler::OnLocalWrite()
{
    // handle local writable event
    if (!data_write_to_local_.empty())
    {
        auto data = data_write_to_local_;
        data_write_to_local_.clear();
        WriteToSock(data, local_socket_);
    }
    else
    {
        UpdateStream(kStreamDown, kWaitStatusReading);
    }
}

void TCPRelayHandler::OnRemoteWrite()
{
    // handle remote writable event
    stage_ = kStageStream;
    if (!data_write_to_remote_.empty())
    {
        auto data = data_write_to_remote_;
        data_write_to_remote_.clear();
        WriteToSock(data, remote_socket_);
    }
    else
    {
        UpdateStream(kStreamUp, kWaitStatusReading);
    }
}

void TCPRelayHandler::OnLocalError()
{
    LOGW << "got local error\n";
    this->Destroy();
}

void TCPRelayHandler::OnRemoteError()
{
    LOGW << "got remote error\n";
    this->Destroy();
}

void TCPRelayHandler::HandleEvent(SOCKET s, int event)
{
    // order is important
    if (s == remote_socket_)
    {
        if (event & kPollErr)
        {
            OnRemoteError();
        }
        if (!IsDestroyed() &&
                (event & (kPollIn | kPollHup)))
        {
            OnRemoteRead();
        }
        if (!IsDestroyed() && (event & kPollOut))
        {
            OnRemoteWrite();
        }
    }
    else if (s == local_socket_)
    {
        if (event & kPollErr)
        {
            OnLocalError();
        }
        if (!IsDestroyed() &&
                (event & (kPollIn | kPollHup)))
        {
            OnLocalRead();
        }
        if (!IsDestroyed() && (event & kPollOut))
        {
            OnLocalWrite();
        }
    }
    else
        LOGW << "unknown socket\n";
    if (IsDestroyed())
    {
        //free memory when it mark destroyed
        delete this;
    }
}

void TCPRelayHandler::DNSResolved(string hostname, string ip, string err)
{
    if (!err.empty())
    {
        LOGW << err << " when handling connection\n";
        Destroy();
    }
    if (ip.empty())
    {
        LOGW << "parse " << hostname << " result is empty!\n";
        Destroy();
    }
    if (IsDestroyed())
    {
        delete this;
        return;
    }
    stage_ = kStageConnecting;
    string remote_addr = ip;
    sockaddr_in client_service;
    int remote_port = this->remote_port_;
    client_service.sin_family = AF_INET;
    inet_pton(AF_INET, remote_addr.c_str(), &client_service.sin_addr.s_addr);
    client_service.sin_port = htons(remote_port);
    remote_socket_ = CreateRemoteSocket(remote_addr, remote_port);
    int ret = connect(remote_socket_, (sockaddr*)&client_service, sizeof(client_service));
    if (ret == -1)
    {
        if (!SocketIsBlock(remote_socket_))
        {
            LOGE << "connect failed:" << ret << " " << GetSocketErrorCode() << "\n";
            this->Destroy();
        }
    }
    if (IsDestroyed())
    {
        delete this;
        return;
    }
    event_loop_->Add(remote_socket_, kPollErr | kPollOut, server_);
    stage_ = kStageConnecting;
    UpdateStream(kStreamUp, kWaitStatusReadWriting);
    UpdateStream(kStreamDown, kWaitStatusReading);
}

bool TCPRelayHandler::IsDestroyed()
{
    return stage_ == kStageDestroyed;
}

void TCPRelayHandler::Destroy()
{
    //mark as destroy
    if (IsDestroyed())
    {
        // this couldn't happen
        LOGW << "already destroyed\n";
        return;
    }
    stage_ = kStageDestroyed;
}

TCPRelayHandler::~TCPRelayHandler()
{
    // destroy the handler and release any resources
    // promises:
    // 1. destroy won't make another destroy() call inside
    // 2. destroy releases resources so it prevents future call to destroy
    // 3. destroy won't raise any exceptions
    // if any of the promises are broken, it indicates a bug has been
    // introduced! mostly likely memory leaks, etc
    stage_ = kStageDestroyed;
    if(is_local_ && recv_data_size != send_data_size - 12)
        LOGW << "receive and send the size is not equal:" << send_data_size << "  " << recv_data_size << "\n";
    if (!is_local_ && recv_data_size != send_data_size)
        LOGW << "receive and send the size is not equal:" << send_data_size << "  " << recv_data_size << "\n";
    LOGI << "destroy: " << remote_address_ << ":" << remote_port_ << "\n";
    if (remote_socket_ != INVALID_SOCKET)
    {
        event_loop_->Remove(remote_socket_);
        server_->RemoveHandler(remote_socket_);
        CloseSocket(remote_socket_);
        remote_socket_ = INVALID_SOCKET;
    }
    if (local_socket_ != INVALID_SOCKET)
    {
        event_loop_->Remove(local_socket_);
        server_->RemoveHandler(local_socket_);
        CloseSocket(local_socket_);
        local_socket_ = INVALID_SOCKET;
    }
    dns_resolver_->RemoveCallback(this);
}

bool TCPRelay::Init()
{
    string listen_addr;
    int listen_port;
    if (is_local_)
    {
        listen_addr = config_->GetStr("local_address");
        listen_port = config_->GetInt("local_port");
    }
    else
    {
        listen_addr = config_->GetStr("server_address");
        listen_port = config_->GetInt("server_port");
    }
    this->listen_port_ = listen_port;
    //create socket
    struct sockaddr_in service;
    SOCKET server_socket;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, listen_addr.c_str(), &service.sin_addr.s_addr);
    service.sin_port = htons(listen_port);

    if (INVALID_SOCKET ==
            (server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
       )
    {
        LOGE << "create socket failed" << GetSocketErrorCode() << "\n";
        return false;
    }
    SetNoBlocking(server_socket);

    SetReUseAddr(server_socket);

    if (-1 == bind(server_socket,
                   (sockaddr *)&service,
                   sizeof(service)
                  ))
    {
        CloseSocket(server_socket);
        LOGE << "bind socket failed" << GetSocketErrorCode() << "\n";
        return false;
    }

    if (-1 == listen(server_socket, SOMAXCONN))
    {
        CloseSocket(server_socket);
        LOGE << "listen socket failed" << GetSocketErrorCode() << "\n";
        return false;
    }
    this->server_socket_ = server_socket;
    return true;
}

TCPRelay::TCPRelay(Config * config, DNSResolve* dns_resolve, bool is_local):
    config_(config),
    is_local_(is_local),
    is_closed_(false),
    event_loop_(NULL),
    dns_resolver_(dns_resolve),
    server_socket_(INVALID_SOCKET),
    listen_port_(0)
{
}

bool TCPRelay::AddToLoop(EventLoop * event_loop)
{
    if (event_loop_)
    {
        LOGW << "already add to loop\n";
        return false;
    }
    if (is_closed_)
    {
        LOGW << "already closed\n";
        return false;
    }
    event_loop_ = event_loop;
    event_loop_->Add(server_socket_, kPollIn | kPollErr, this);
    return true;
}

void TCPRelay::AddHandler(SOCKET s, ISockNotify * handler)
{
    if (socket_handler_.count(s) > 0)
    {
        LOGW << "this socket has bind a handler,it may cause memory leak\n";
    }
    socket_handler_[s] = handler;
}

void TCPRelay::RemoveHandler(SOCKET s)
{
    socket_handler_.erase(s);
}

void TCPRelay::HandleEvent(SOCKET s, int event)
{
    if (s == INVALID_SOCKET)
    {
        LOGW << "invalid socket\n";
        return;
    }
    if (s == server_socket_)
    {
        if (event & kPollErr)
        {
            event_loop_->Stop();
            return;
        }
        SOCKET new_socket = accept(server_socket_, NULL, NULL);
        if (new_socket != INVALID_SOCKET)
        {
            new TCPRelayHandler(this, event_loop_, dns_resolver_, new_socket, config_, is_local_);
        }
    }
    else
    {
        if (socket_handler_.count(s) > 0)
        {
            socket_handler_[s]->HandleEvent(s, event);
        }
    }
}

void TCPRelay::Close()
{
    LOGI << "TCP close\n";
    is_closed_ = true;
    if (event_loop_)
    {
        event_loop_->Remove(server_socket_);
    }
    if(server_socket_ != INVALID_SOCKET)
        CloseSocket(server_socket_);
    for (auto& iter : socket_handler_)
    {
        delete iter.second;
    }
}
