#!/usr/bin/python3

import base64
import hmac
import json
import urllib.request
from urllib.parse import quote
from urllib import error
from urllib.parse import urlencode
from _sha1 import sha1
import time
from datetime import datetime,timezone
import ssl
import http.cookiejar
import random
import string
import hashlib


def random_str(len):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for x in range(len))

def salt_password(password, salt, iter_times):
    return hashlib.pbkdf2_hmac('sha256', password, salt, iter_times)


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
]


def getLoginHtml():
    request = urllib.request.Request(url=f"http://{routerIp}/html/index.html")
    response = urllib.request.urlopen(request)
    #输出所有
    return response.read()
    # print(response.read())

def getLogin_nonce(login_post_data):
    return callRouter(f"http://{routerIp}/api/system/user_login_nonce", login_post_data)

def getLogin_proof(login_post_data):
    return callRouter(f"http://{routerIp}/api/system/user_login_proof", login_post_data)

def callRouter(url, login_post_data):
    request_header = {
        "Content-Type": "application/json;charset=utf-8",
        'User-Agent':
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_16) AppleWebKit/605.1.15 (KHTML, like Gecko) MicroMessenger/2.3.26(0x12031a10) MacWechat Chrome/39.0.2171.95 Safari/537.36 NetType/WIFI WindowsWechat MicroMessenger/2.3.26(0x12031a10) MacWechat NetType/WIFI WindowsWechat",
    }
    data = json.dumps(login_post_data)
    data = bytes(data, 'utf8')

    print(data)
    request = urllib.request.Request(url, data, request_header)
    response = urllib.request.urlopen(request)
    #输出所有
    return response.read()

def login():
    firstNonce = random_str(32)
    
    login_post_data = {
        'csrf': {'csrf_param': "L462CrJXl8KNHuKUmrZs0E989OHMv5lt", 'csrf_token': "Bt4OeBnJK0YUmrEu8VWXmly5SZf9I6zE"},
        'data': {'username': 'admin', 'firstnonce': firstNonce},
    }
    result = getLogin_nonce(login_post_data)

    firstNonceJson = json.loads(result)
    print(firstNonceJson)

    login_post_data['csrf']['csrf_param'] = firstNonceJson['csrf_param']
    login_post_data['csrf']['csrf_token'] = firstNonceJson['csrf_token']
    result = getLogin_nonce(login_post_data)
    secondNonceJson = json.loads(result)
    print(secondNonceJson)

    salt = bytes.fromhex(secondNonceJson['salt']) 
    finalNonce = secondNonceJson['servernonce']
    authMsg = firstNonce + ',' + finalNonce + ',' + finalNonce
    iterations_rece = int(secondNonceJson['iterations'])
    passwd = password.encode()  #str to bytes
 
    saltPassword = salt_password(passwd, salt, iterations_rece)  # 加盐算法不同语言命名有差异hashlib.pbkdf2_hmac
    mac = hmac.new(b'Client Key', saltPassword, hashlib.sha256)  #b'Client Key'作key，msg加密
    clientKey = mac.digest()
    storeKey = hashlib.sha256(clientKey).digest()
    mac = hmac.new(bytes(authMsg, encoding='utf-8'), storeKey, hashlib.sha256)
    clientSignature = mac.digest()
    clientKey = bytearray(clientKey)
    for i in range(len(clientKey)):
        clientKey[i] = clientKey[i] ^ clientSignature[i]
    clientProof = bytes(clientKey)

    finalPostData = {
        "data": {
            "clientproof": clientProof.hex(),
            "finalnonce": finalNonce
        },
        "csrf": {
            "csrf_param": secondNonceJson['csrf_param'],
            "csrf_token": secondNonceJson['csrf_token']
        }
    }
    print('finalPostData ', finalPostData)
    result = getLogin_proof(finalPostData)
    proofJson = json.loads(result)
    print(proofJson)


def getNasIpv6(hostName):
    url = f"http://{routerIp}/api/system/HostInfo"
    # request = urllib.request.Request(url)
    response = urllib.request.urlopen(url)
    result = response.read()
    #输出所有
    proofJson = json.loads(result)
    Ipv6Addrs = ''
    for device in proofJson:
        if(device['HostName'] == hostName):
            Ipv6Addrs = device['Ipv6Addrs']
            break
    
    for ip in Ipv6Addrs:
        if(ip['Ipv6Addr'].startswith('fe80')):
            continue
        else:
            Ipv6Addrs = ip['Ipv6Addr']
            break
    return Ipv6Addrs



def getSignature(params):
    list = []
    for key in params:
        # print(key)
        list.append(percentEncode(key) + "=" + percentEncode(str(params[key])))
    list.sort()
    CanonicalizedQueryString = '&'.join(list)
    # print("strlist:" + CanonicalizedQueryString)
    StringToSign = 'GET' + '&' + percentEncode("/") + "&" + percentEncode(CanonicalizedQueryString)
    # print("StringToSign:" + StringToSign)
    h = hmac.new(bytes(aliddnsipv6_sk + "&", encoding="utf8"),
                 bytes(StringToSign, encoding="utf8"), sha1)
    signature = base64.encodebytes(h.digest()).strip()
    signature = str(signature, encoding="utf8")
    # print(signature)
    return signature

def get_record_info(SubDomain, DomainName, Type):
    params = {
        'Format': 'JSON',
        'Version': '2015-01-09',
        'AccessKeyId': aliddnsipv6_ak,
        'SignatureMethod': 'HMAC-SHA1',
        'SignatureNonce': '',
        'SignatureVersion': '1.0',
        'Timestamp': '',
        'Action': 'DescribeSubDomainRecords'
    }
    params['DomainName'] = DomainName
    params['SubDomain'] = SubDomain + "." + DomainName
    params['Type'] = Type
    timestamp = time.time()
    # formatTime = time.strftime(
    # "%Y-%m-%dT%H:%M:%SZ", time.localtime(time.time() - 8 * 60 * 60))
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    formatTime=utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    params['Timestamp'] = formatTime
    params['SignatureNonce'] = timestamp

    Signature = getSignature(params)
    params['Signature'] = Signature
    list = []
    for key in params:
        list.append(percentEncode(key) + "=" + percentEncode(str(params[key])))
    list.sort()
    paramStr = "&".join(list)
    url = "https://alidns.aliyuncs.com/?" + paramStr
    # print("url:" + url)
    try:
        print("查询域名信息：" + SubDomain + " " + DomainName + " " + Type)
        context = ssl._create_unverified_context()
        jsonStr = urllib.request.urlopen(
            url, context=context).read().decode("utf8")
        print("查询结束，查询结果：" + jsonStr)
        return json.loads(jsonStr)
    except error.HTTPError as e:
        print(e)
        print("查询域名信息失败：" + e.read().decode("utf8"))


def add_domain_record(DomainName, RR, Type, Value):
    print("start add domain record")
    params = {
        'Format': 'JSON',
        'Version': '2015-01-09',
        'AccessKeyId': aliddnsipv6_ak,
        'SignatureMethod': 'HMAC-SHA1',
        'SignatureNonce': '',
        'SignatureVersion': '1.0',
        'Timestamp': '',
        'Action': 'AddDomainRecord'
    }
    params['DomainName'] = DomainName
    params['RR'] = RR
    params['Type'] = Type
    params['Value'] = Value

    timestamp = time.time()
    # formatTime = time.strftime(
    # "%Y-%m-%dT%H:%M:%SZ", time.localtime(time.time() - 8 * 60 * 60))
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    formatTime=utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    # formatTime = formatTime.replace(":", "%3A")
    params['Timestamp'] = formatTime
    params['SignatureNonce'] = timestamp

    Signature = getSignature(params)
    params['Signature'] = Signature
    list = []
    for key in params:
        list.append(percentEncode(key) + "=" + percentEncode(str(params[key])))
    list.sort()
    paramStr = "&".join(list)
    url = "https://alidns.aliyuncs.com/?" + paramStr
    # print("url:" + url)
    try:
        print("添加 " + RR + " " + DomainName + " " + Type + " " + Value)
        context = ssl._create_unverified_context()
        jsonStr = urllib.request.urlopen(
            url, context=context).read().decode("utf8")
        print("添加成功")
        return json.loads(jsonStr)
    except error.HTTPError as e:
        print(e)
        print("添加失败：" + e.read().decode("utf8"))


def update_domain_record(RecordId, RR, Value, Type):
    print("start update domain record")
    params = {
        'Format': 'JSON',
        'Version': '2015-01-09',
        'AccessKeyId': aliddnsipv6_ak,
        'SignatureMethod': 'HMAC-SHA1',
        'SignatureNonce': '',
        'SignatureVersion': '1.0',
        'Timestamp': '',
        'Action': 'UpdateDomainRecord'
    }
    params['RecordId'] = RecordId
    params['RR'] = RR
    params['Type'] = Type
    params['Value'] = Value

    timestamp = time.time()
    # formatTime = time.strftime(
    # "%Y-%m-%dT%H:%M:%SZ", time.localtime(time.time() - 8 * 60 * 60))
    utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    formatTime=utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    params['Timestamp'] = formatTime
    params['SignatureNonce'] = timestamp

    Signature = getSignature(params)
    params['Signature'] = Signature
    list = []
    for key in params:
        list.append(percentEncode(key) + "=" + percentEncode(str(params[key])))
    list.sort()
    paramStr = "&".join(list)
    url = "https://alidns.aliyuncs.com/?" + paramStr
    # print("url:" + url)
    try:
        print("更新 " + RR + " " + " " + Type + " " + Value)
        context = ssl._create_unverified_context()
        jsonStr = urllib.request.urlopen(
            url, context=context).read().decode("utf8")
        print("更新成功")
        return json.loads(jsonStr)
    except error.HTTPError as e:
        print(e)
        print("更新失败：" + e.read().decode("utf8"))


def percentEncode(str):
    res = quote(str, 'utf8')
    res = res.replace('+', '%20')
    res = res.replace('*', '%2A')
    res = res.replace('%7E', '~')
    return res


if __name__ == '__main__':
    #使用http.cookiejar.CookieJar()创建CookieJar对象
    cjar=http.cookiejar.CookieJar()
    #使用HTTPCookieProcessor创建cookie处理器，并以其为参数构建opener对象
    cookie=urllib.request.HTTPCookieProcessor(cjar)
    opener=urllib.request.build_opener(cookie)
    # 将opener安装为全局
    urllib.request.install_opener(opener)

    getLoginHtml()
    login()

    for aliDomain in aliDomains:
        HostName = aliDomain["HostName"]
        RR = aliDomain["RR"]
        DomainName = aliDomain["DomainName"]
        Type = aliDomain["Type"]
        ip = getNasIpv6(HostName)
        print('ipv6', ip)

        recordListInfo = get_record_info(RR, DomainName, Type)

        if recordListInfo['TotalCount'] == 0:
            print("记录不存在，添加记录")
            add_domain_record(DomainName, RR, Type, ip)
        else:
            records = recordListInfo["DomainRecords"]["Record"]
            hasFind = "false"
            for record in records:
                if record['RR'] == RR and record['DomainName'] == DomainName and record['Type'] == Type:
                    hasFind = "true"
                    if record['Value'] == ip:
                        print("ip 一致，无需更新")
                    else:
                        print("更新域名")
                        update_domain_record(record['RecordId'], RR, ip, Type)
            if not hasFind:
                print("记录不存在，添加记录")
                add_domain_record(DomainName, RR, Type, ip)