import sys
import threading
import traceback

import requests, time, re, rsa, json, base64
from urllib import parse

s = requests.Session()
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0"

username = ""
password = ""
PUSH_TOKEN = ""
BOT_TOKEN = ""
CHAT_ID = ""

# if username == "" or password == "":
#     username = input("账号：")
#     password = input("密码：")

if sys.stdin.isatty():  # 检查是否在交互式终端运行 (例如本地执行)
    if username == "" or password == "":
        username = input("账号：")
        password = input("密码：")
    PUSH_TOKEN = input("PUSH_TOKEN (optional):")  # 如果是交互式，则提示输入PUSH_TOKEN
    BOT_TOKEN = input("BOT_TOKEN (optional):")
    CHAT_ID = input("CHAT_ID (optional):")
else:  # 如果不是交互式 (例如GitHub Actions)
    # 从stdin读取，假设run.yml中输入的顺序是固定的
    username = sys.stdin.readline().strip()
    password = sys.stdin.readline().strip()
    PUSH_TOKEN = sys.stdin.readline().strip()
    BOT_TOKEN = sys.stdin.readline().strip()
    CHAT_ID = sys.stdin.readline().strip()

g_conf = {}


def loadRsaKey():
    global g_conf
    r = s.post(
        "https://open.e.189.cn/api/logbox/config/encryptConf.do", {"appId": "cloud"}
    ).json()
    g_conf["pubKey"] = r["data"]["pubKey"]


def loadAppConf(r):
    global g_conf
    g_conf["lt"] = re.findall(r"lt=([a-zA-Z0-9]+)", r.url)[0]
    g_conf["reqId"] = re.findall(r"reqId=([a-zA-Z0-9]+)", r.url)[0]

    r = s.post(
        "https://open.e.189.cn/api/logbox/oauth2/appConf.do",
        data={
            "version": "2.0",
            "appKey": "cloud",
        },
        headers={
            "referer": f"https://open.e.189.cn/api/logbox/separate/web/index.html?appId=cloud&lt={g_conf['lt']}&reqId={g_conf['reqId']}",
            "lt": g_conf["lt"],
            "reqid": g_conf["reqId"],
            "origin": "https://open.e.189.cn",
            "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6",
        },
    ).json()
    g_conf.update(r["data"])


def send_checkin(i):
    rand = str(round(time.time() * 1000))
    surl = f"https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K"
    url = f"https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
    url2 = f"https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6",
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        # ss = requests.Session()  # 每个线程独立的 Session
        response = s.get(surl, headers=headers)
        # print(f"线程{i} 返回状态码: {response.status_code}")
        netdiskBonus = response.json()["netdiskBonus"]
        if response.json()["isSign"] == "false":
            print(f"签到成功！获得{netdiskBonus}M空间")
        else:
            print(f"今天已经签到过了，获得{netdiskBonus}M空间")
    except Exception as e:
        print(f"线程{i} 出错: {e}")


def main():
    login(username, password)
    # rand = str(round(time.time() * 1000))
    # surl = f"https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K"
    # url = f"https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
    # url2 = f"https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN"
    # headers = {
    #     "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6",
    #     "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
    #     "Host": "m.cloud.189.cn",
    #     "Accept-Encoding": "gzip, deflate",
    # }

    threads = []
    thread_count = 5  # 并发数

    for i in range(thread_count):
        t = threading.Thread(target=send_checkin, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("所有请求发送完毕")

    # 抽奖 已经失效
    # lott(url, headers)
    # lott(url2, headers)


BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")


def int2char(a):
    return BI_RM[a]


b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = b64map.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(string):
    rsa_key = (
        f"-----BEGIN PUBLIC KEY-----\n{g_conf['pubKey']}\n-----END PUBLIC KEY-----"
    )
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex(
        (base64.b64encode(rsa.encrypt(f"{string}".encode(), pubkey))).decode()
    )
    return result


def calculate_md5_sign(params):
    return hashlib.md5("&".join(sorted(params.split("&"))).encode("utf-8")).hexdigest()


def tryGet(l, index, default=""):
    if len(l) >= index + 1:
        return l[index]
    else:
        return default


def login(username, password):
    url = "https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action"
    r = s.get(url)
    # captchaToken = tryGet(re.findall(r"captchaToken' value='(.+?)'", r.text), 0)
    # lt = tryGet(re.findall(r'lt = "(.+?)"', r.text), 0)
    # returnUrl = tryGet(re.findall(r"returnUrl = '(.+?)'", r.text), 0)
    # paramId = tryGet(re.findall(r'paramId = "(.+?)"', r.text), 0)
    loadAppConf(r)
    user = username
    loadRsaKey()
    username = rsa_encode(username)
    password = rsa_encode(password)
    url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    headers = {
        "User-Agent": ua,
        "Referer": "https://open.e.189.cn/",
        "lt": g_conf["lt"],
        "REQID": g_conf["reqId"],
    }
    data = {
        "appKey": "cloud",
        "accountType": "01",
        "version": "2.0",
        "userName": f"{{NRP}}{username}",
        "password": f"{{NRP}}{password}",
        "validateCode": "",
        "captchaToken": "",
        "returnUrl": g_conf["returnUrl"],
        "mailSuffix": g_conf["mailSuffix"],
        "paramId": g_conf["paramId"],
        "dynamicCheck": "FALSE",
        "clientType": "1",
        "cb_SaveName": "0",
        "isOauth2": False,
    }
    r = s.post(url, data=data, headers=headers, timeout=6)
    print(f"{user[0:2]}* **** **{user[9:11]} :", end=" ")
    if r.json()["result"] == 0:
        print(r.json()["msg"])
    else:
        raise Exception(r.json()["msg"])
    redirect_url = r.json()["toUrl"]
    r = s.get(redirect_url)
    return s


def lott(url, headers):
    response = s.get(url, headers=headers)
    respJson = response.json()

    if "errorCode" in respJson:
        print("抽奖错误：" + response.text)
    else:
        if "description" in respJson:
            print("抽奖获得 " + respJson["description"])
        else:
            print("抽奖异常：" + response.text())


# 消息推送微信pushplus：需要1元实名认证费用
def send_wx_msg(title, content):
    if PUSH_TOKEN is None or PUSH_TOKEN == "":
        print("PUSH_TOKEN未设置，跳过微信推送。")
        return
    url = 'http://www.pushplus.plus/send'
    r = requests.get(url, params={'token': PUSH_TOKEN,
                                  'title': title,
                                  'content': content})
    print(f'微信推送结果：{r.status_code, r.text}')


# 推送tg消息
def send_telegram_message(message):
    if not BOT_TOKEN or not CHAT_ID or BOT_TOKEN == "" or CHAT_ID == "":
        print('没有配置tg机器人，无法推送')
        return
    tg_url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": message
    }
    response = requests.post(tg_url, json=data)
    if response.status_code == 200:
        print("tg消息推送成功!")
    else:
        print("Failed to send message. Status code:", response.status_code)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        traceback.print_exc()
        send_wx_msg('天翼签到报错', f'请检查,{username} {e}')
        send_telegram_message(f'天翼签到报错,请检查 {username}{e}')
