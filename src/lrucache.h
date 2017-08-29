#ifndef _LRUCACHE_H_
#define _LRUCACHE_H_

#include <unordered_map>
#include <deque>

template<typename _Tkey, typename _TVal>
class LRUCache
{
public:
    LRUCache(float timeout)
    {
        //timeout is second,timeout_ is millisecond
        this->timeout_ = (int)(timeout * 1000);
    };
    _TVal& operator[](_Tkey key)
    {
        int64_t t = GetTimeStamp();
        this->key_to_last_times[key] = t;
        this->time_to_keys_[t].push_back(key);
        this->last_visits_.push_back(t);
        return this->store_[key];
    }
    void Sweep()
    {
        int64_t now = GetTimeStamp();
        int count = 0;
        while (last_visits_.size() > 0)
        {
            int64_t least = last_visits_.front();
            if (now - least <= timeout_)
            {
                break;
            }
            for (auto& key : time_to_keys_[least])
            {
                last_visits_.pop_front();
                if (store_.count(key) > 0)
                {
                    if (now - key_to_last_times[key] > this->timeout_)
                    {
                        store_.erase(key);
                        key_to_last_times.erase(key);
                        ++count;
                    }
                }
            }
            time_to_keys_.erase(least);
        }
        if (count > 0)
        {
            LOGI << "clear " << count << " cache";
        }
    }
    int Count(_Tkey key)
    {
        return store_.count(key);
    }
private:
    int timeout_;
    unordered_map<_Tkey, _TVal> store_;
    map<int64_t, list<_Tkey>> time_to_keys_;
    unordered_map<_Tkey, int64_t> key_to_last_times;
    deque<int64_t> last_visits_;
};

#endif