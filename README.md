Fake_Shadowsocks
===========

用C++实现的类似shadowsocks的网络混淆代理软件。
shadowsocks相关资料请看https://github.com/shadowsocks/shadowsocks

# 测试编译环境
* Visual Studio 2015
* GNU 5.5.0

# 编译教程
```
mkdir build
cd build
cmake ..
Linux使用make进行编译，Windows使用VS打开解决方案文件进行编译
```

# 使用教程
+ 服务端
```
fssocks server --server -p 8881 -s 0.0.0.0
或
fssocks --server --server-port 8881 --server-address 0.0.0.0
```

+ 客户端
```
fssocks --client -p 8881 -l 1081 -s 127.0.0.1 -b 127.0.0.1
或
fssocks --client --server-port 8881 --server-address 127.0.0.1 --local-port 1081 --local-address 127.0.0.1
```

# 其他说明
使用C++开发的网络混淆代理软件，主要用于学习其实现原理，代码很多部分都未经优化。
对网络代理感兴趣的可以继续关注我的[reverse_proxy](https://github.com/ReyzalX/reverse_proxy)项目，用于内网B访问内网A，可以用于外部访问内网A资源等。

