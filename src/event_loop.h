#ifndef _EVENT_LOOP_H_
#define _EVENT_LOOP_H_

//select mode
class SelectLoop
{
public:
    SelectLoop();
    ~SelectLoop() {};
    int Poll(map<SOCKET, int>& result, int timeout);
    void Register(SOCKET s, int mode);
    void UnRegister(SOCKET s);
    void Modify(SOCKET s, int mode);
    void Close();
private:
    set<SOCKET> r_sock_set_;
    set<SOCKET> w_sock_set_;
    set<SOCKET> x_sock_set_;
};

#ifndef _WIN32
//epoll mode
class EpollLoop
{
    const static int kEpollSize = 1024;
    const static int kMaxEpollSize = 102400;
public:
    EpollLoop()
    {
        epfd_ = epoll_create(kMaxEpollSize);
    }
    ~EpollLoop() {}
    int Poll(map<SOCKET, int>& result, int timeout)
    {
        if (timeout < 0)
        {
            timeout = 1000;
        }
        int ret = 0;
        do
        {
            int nfds = epoll_wait(epfd_, events, kEpollSize, timeout);
            if (-1 == nfds)
            {
                ret = -1;
                break;
            }
            for (int i = 0; i < nfds; ++i)
            {
                int mode = 0;
                if (events[i].events & EPOLLIN)
                    mode |= kPollIn;
                if (events[i].events & EPOLLOUT)
                    mode |= kPollOut;
                result[events[i].data.fd] = mode;
            }
        }
        while (0);
        return ret;
    }
    void Register(SOCKET s, int mode)
    {
        sock_mode_[s] = mode;
        epoll_event ev;
        ev.events = 0;
        ev.data.fd = s;
        if (mode & kPollIn)
        {
            ev.events |= EPOLLIN;
        }
        if (mode & kPollOut)
        {
            ev.events |= EPOLLOUT;
        }
        epoll_ctl(epfd_, EPOLL_CTL_ADD, s, &ev);
    }
    void UnRegister(SOCKET s)
    {
        int mode = sock_mode_[s];
        epoll_event ev;
        ev.events = 0;
        ev.data.fd = s;
        if (mode & kPollIn)
        {
            ev.events |= EPOLLIN;
        }
        if (mode & kPollOut)
        {
            ev.events |= EPOLLOUT;
        }
        epoll_ctl(epfd_, EPOLL_CTL_DEL, s, &ev);
    }
    void Modify(SOCKET s, int mode)
    {
        UnRegister(s);
        Register(s, mode);
    }
    void Close()
    {
        close(epfd_);
    }
private:
    int epfd_;
    map<SOCKET, int> sock_mode_;
    epoll_event events[kEpollSize];
};

#endif

//event loop,
class EventLoop
{
    typedef map<SOCKET, ISockNotify*> SocketHandleMap;
public:
    EventLoop();
    ~EventLoop();
    void Run();
    void AddPeriodic(IPeriodicNotify * cb);
    void RemovePeriodic(IPeriodicNotify * cb);
    void Remove(SOCKET s);
    void Add(SOCKET s, int mode, ISockNotify* handler);
    void Modify(SOCKET s, int mode);
    void Stop();
private:
    int Poll(map<SOCKET, int>& result, int timeout = 1);

#ifdef _WIN32
    SelectLoop* loop_impl_;
#else
    EpollLoop* loop_impl_;
#endif
    SocketHandleMap socket_handler_;
    set<IPeriodicNotify*> periodic_callbacks_;
    int64_t last_time_;
    bool stopping_;
};

#endif