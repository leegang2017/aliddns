# aliddns

主要作用是查询华为路由器TC7102里面的接口，获取连接设备的ipv6地址，并且更新到阿里云域名对应的解析域名上，以实现用外网直接访问设备
### 使用方式
首先打开脚本修改下列参数
```py
aliddnsipv6_ak = "aliddnsipv6_ak"
aliddnsipv6_sk = "aliddnsipv6_sk"
routerIp = "192.168.10.1"
password = "password"
aliDomains = [
{
    "HostName": "HS-AFS-MAGE20-XXXX",
    "RR": "nas",
    "DomainName": "xxx.top",
    "Type": "AAAA"
},
```
 `aliddnsipv6_ak ` 以及 `aliddnsipv6_sk` ，获取方式见阿里云文档 [https://help.aliyun.com/document_detail/34414.html](https://help.aliyun.com/document_detail/34414.html)

#### 参数说明
1. routerIp: 华为路由器的ip
1. password: 华为路由器的登录密码
1. aliDomains: 这里可以设置多个设备
   1. HostName: 连接设备的host名字，可以在路由器里面找到
   1. RR: 要设置的主机名，你要设置的域名前缀
   1. DomainName：域名 ，在阿里云购买的域名  例如 www.baidu.com ，www为RR，baidu.com 为DomainName
   1. Type：类型，IPv6 为 AAAA


运行方式 `python3 aliddns_huawei_router.py`

#### 配合linux，如coreelec使用

把aliddns_huawei_router.py上传到linux里面，可以用winscp，比如路径为`/storage/data/aliddns_huawei_router.py`

打开ssh终端，执行 `crontab -e`
添加如下例子,意思是每小时第3分钟执行一次
```
3 * * * * python3 /storage/data/aliddns_huawei_router.py
```
#### 参考
https://github.com/TreviD/aliddns
https://blog.csdn.net/u014516174/article/details/116891133
https://post.smzdm.com/p/aqndw6op/