# 为OpenWrt所写
程序完全由 [`PrinnyK`](https://github.com/PrinnyK)编写。   
为Openwrt实现安腾`BAS`认证支持

# 特性
* 自动获取活跃的IP和MAC作为运行所需的参数
	- 若失败则报错，你需要自己 `vi esp_config.json` 填上你的ip和mac
* 自动连接(包含掉线重连和上线失败重连)
* 没有下线功能(对！你没听错！没有下线功能，只要`sh stop.sh`之后过几分钟自然就会掉线)

# 程序依赖
* OpenWrt 15.01(低版本并没测试)
* Python 
* 如若import json报错则你需要再`Python-codecs`这个模块
* 如若import hashlib报错则你需要再安装`python-openssl`这个模块

# 使用前(请务必仔细阅读)
* 安装OpenWrt 15在你的路由器上(推荐路由器Flash 16M、至少8M，少于8M的请硬改或关闭浏览器)
* 安装Python(各种路由器不一样，自己百度)
* 安装python-codecs和python-openssl

```
opkg update && opkg install python-codecs python-openssl
```

# 开始
`***代表目录`
```
cd ***
sh start.sh
```

# 杀死进程
```
cd ***
sh stop.sh
```

# 配置文件说明
```
{	
	"password": "123456", 
	"user": "liu", 
	"ip": "",  #可以留空 
	"mac": "",  #可以留空
	"delay": "0"  #延迟上线，等待再次分配ip，可关闭
}
```
最好用 `vim`打开
# 输出调试信息
```
python /***/edu_supplicant_py
```
如果报错或者不能认证请移步`issues`反馈