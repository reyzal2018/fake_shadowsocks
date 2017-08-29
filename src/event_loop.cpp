#include "common.h"
#include "event_loop.h"
#include "tcp_relay.h"

const int kTimeoutPrecision = 10;

struct win_fd_set
{
    unsigned int fd_count;
    SOCKET fd_array[1];
};

#define FD_SET_ALLOC_SIZE(n) ((sizeof(struct win_fd_set) + ((n)-1)*sizeof(SOCKET)))

SelectLoop::SelectLoop()
{

}

int SelectLoop::Poll(map<SOCKET, int>& result, int timeout)
{
    win_fd_set* r_fds = (win_fd_set*)malloc(FD_SET_ALLOC_SIZE(r_sock_set_.size()));
    win_fd_set* w_fds = (win_fd_set*)malloc(FD_SET_ALLOC_SIZE(w_sock_set_.size()));
    win_fd_set* x_fds = (win_fd_set*)malloc(FD_SET_ALLOC_SIZE(x_sock_set_.size()));
    int ret = 0;
    int count = 0;
    for (auto& iter : r_sock_set_)
    {
        r_fds->fd_array[count++] = iter;
    }
    r_fds->fd_count = count;
    count = 0;
    for (auto& iter : w_sock_set_)
    {
        w_fds->fd_array[count++] = iter;
    }
    w_fds->fd_count = count;
    count = 0;
    for (auto& iter : x_sock_set_)
    {
        x_fds->fd_array[count++] = iter;
    }
    x_fds->fd_count = count;

    timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    do
    {
        if (r_fds->fd_count == 0 && w_fds->fd_count == 0 && x_fds->fd_count == 0)
        {
            break;
        }
        int err = select(0, reinterpret_cast<fd_set*>(r_fds), reinterpret_cast<fd_set*>(w_fds),
                         reinterpret_cast<fd_set*>(x_fds), &tv);
        if (-1 == err)
        {
            ret = -1;
            break;
        }
        for (size_t i = 0; i < r_fds->fd_count; i++)
        {
            result[r_fds->fd_array[i]] |= kPollIn;
        }
        for (size_t i = 0; i < w_fds->fd_count; i++)
        {
            result[w_fds->fd_array[i]] |= kPollOut;
        }
        for (size_t i = 0; i < x_fds->fd_count; i++)
        {
            result[x_fds->fd_array[i]] |= kPollErr;
        }
    }
    while (0);
    free(r_fds);
    free(w_fds);
    free(x_fds);
    return ret;
}

void SelectLoop::Register(SOCKET s, int mode)
{
    if (mode & kPollIn)
        r_sock_set_.insert(s);
    if (mode & kPollOut)
        w_sock_set_.insert(s);
    if (mode & kPollErr)
        x_sock_set_.insert(s);
}

void SelectLoop::UnRegister(SOCKET s)
{
    if (r_sock_set_.find(s) != r_sock_set_.end())
    {
        r_sock_set_.erase(s);
    }
    if (w_sock_set_.find(s) != w_sock_set_.end())
    {
        w_sock_set_.erase(s);
    }
    if (x_sock_set_.find(s) != x_sock_set_.end())
    {
        x_sock_set_.erase(s);
    }
}

void SelectLoop::Modify(SOCKET s, int mode)
{
    UnRegister(s);
    Register(s, mode);
}

void SelectLoop::Close()
{

}

EventLoop::EventLoop()
{
#ifdef _WIN32
    loop_impl_ = new SelectLoop();
#else
    loop_impl_ = new EpollLoop();
#endif
    stopping_ = false;
    last_time_ = GetTimeStamp();
    LOGI << "EventLoop initialize completed\n";
}

EventLoop::~EventLoop()
{
    if (this->loop_impl_)
        this->loop_impl_->Close();
}

int EventLoop::Poll(map<SOCKET, int>& result, int timeout)
{
    return loop_impl_->Poll(result, timeout);
}

void EventLoop::Add(SOCKET s, int mode, ISockNotify * handler)
{
    socket_handler_[s] = handler;
    loop_impl_->Register(s, mode);
}

void EventLoop::Remove(SOCKET s)
{
    socket_handler_.erase(s);
    loop_impl_->UnRegister(s);
}

void EventLoop::Modify(SOCKET s, int mode)
{
    loop_impl_->Modify(s, mode);
}

void EventLoop::Stop()
{
    stopping_ = true;
}

void EventLoop::Run()
{
    map<SOCKET, int> events;
    while (!stopping_)
    {
        events.clear();
        int ret = Poll(events, kTimeoutPrecision);
        if (ret == -1)
        {
            LOGE << "Poll error\n";
            break;
        }
        if (GetTimeStamp() - last_time_ >= kTimeoutPrecision * 1000)
        {
            for (auto& cb : periodic_callbacks_)
                cb->HandlePeriodic();
            last_time_ = GetTimeStamp();
        }
        for (auto& iter : events)
        {
            if (!stopping_ && socket_handler_.count(iter.first) > 0)
            {
                if (socket_handler_[iter.first] != NULL)
                    socket_handler_[iter.first]->HandleEvent(iter.first, iter.second);
            }
        }
    }
}

void EventLoop::AddPeriodic(IPeriodicNotify* cb)
{
    periodic_callbacks_.insert(cb);
}

void EventLoop::RemovePeriodic(IPeriodicNotify* cb)
{
    periodic_callbacks_.erase(cb);
}

