#include "common.h"
#include "lrucache.h"

void TestLRUCache()
{
    LRUCache<string, int> c(300);
    c["a"] = 1;
    assert(c["a"] == 1);
    FsSleep(500);
    c.Sweep();
    assert(c.Count("a") == 0);

    c["a"] = 2;
    c["b"] = 3;
    FsSleep(200);
    c.Sweep();
    assert(c["a"] == 2);
    assert(c["b"] == 3);

    FsSleep(200);
    c.Sweep();
    int s = c["b"];
    FsSleep(200);
    c.Sweep();
    assert(c.Count("a") == 0);
    assert(c["b"] == 3);

    FsSleep(500);
    c.Sweep();
    assert(c.Count("a") == 0);
    assert(c.Count("b") == 0);
}
