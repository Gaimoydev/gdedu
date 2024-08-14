import re
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import random
from bs4 import BeautifulSoup

def GetAeskey(session):
    url = "https://gl.gdedu.gov.cn/uc/wcms/login.htm"
    response = session.get(url)
    html_content = response.text

    # 使用正则表达式提取aesKey的值
    aes_key_pattern = re.compile(r'var aesKey = "(.*?)";')
    matches = aes_key_pattern.findall(html_content)

    # 提取到的aesKey值
    if matches:
        aes_key = matches[0]
        print("提取到的aesKey值为:", aes_key)
        return aes_key
    else:
        print("未找到aesKey值")
        return None

def GetEncryptedBase64(username, password, aes_key):
    cipher = AES.new(aes_key.encode(), AES.MODE_ECB)
    padded_plaintext = pad(password.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypted_base64 = base64.b64encode(ciphertext).decode()
    return encrypted_base64

def Login(username, password):
    session = requests.Session()
    aes_key = GetAeskey(session)
    if aes_key:
        encrypted_base64 = GetEncryptedBase64(username, password, aes_key)
        if encrypted_base64:
            login_url = "https://gl.gdedu.gov.cn/uc/j_hh_security_check"
            data = {
                "relayUrl": "+",
                "j_username": username,
                "j_password": encrypted_base64,
                "verify": ""
            }

            headers = {
                "Referer": "https://gl.gdedu.gov.cn/uc/wcms/login.htm",
            }

            response = session.post(login_url, data=data, headers=headers)
            if response.status_code == 200:
                print("登录成功！")
                GetJSESSIONID(session, username, password)
            elif response.status_code == 500:
                print("@a", "登录速度过快!")
            else:
                print("@a", f"未知错误 登录失败! 状态码:{response.status_code} 请求后内容:{response.text}")
    else:
        print("@a", f"无法获取aes_key，请检查网络连接或网页结构是否发生变化。")

def GetJSESSIONID(session, username, password):
    data = {
        "SAMLRequest": "https://czzp.gdedu.gov.cn:443/czzhszpj/UserAction",
        "bind": "0",
        "appId": "erop",
        "relayUrl": "L2N6emhzenBqLw==",
        "logOutUrl": "https://czzp.gdedu.gov.cn:443/czzhszpj/j_hh_security_logout",
        "device": "",
        "code": ""
    }

    url = "https://gl.gdedu.gov.cn/uc/DoSamlSso"
    response = session.post(url, data=data)
    if response.status_code == 200:
        print("获取JSESSIONID成功！")
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        try:
            saml_response_value = soup.find('input', {'name': 'SAMLResponse'}).get('value')
            UserAction(session, saml_response_value)
        except AttributeError:
            print("@a", f"登录失败，请检查用户名和密码是否正确! 这是你输入的账号密码: {username} | {password}")
        UserAction(session,saml_response_value)
    else:
        print("@a", f"未知错误 登录失败! 状态码:{response.status_code} 请求后内容:{response.text}")

def UserAction(session, SAMLResponse):
    url = "https://czzp.gdedu.gov.cn/czzhszpj/"
    response = session.post(url)
    jsCookie = response.cookies

    UserActionurl = "https://czzp.gdedu.gov.cn/czzhszpj/UserAction"

    data = {
        "SAMLResponse": SAMLResponse,
        "appId": "erop",
        "device": "",
        "logOutUrl": "https://czzp.gdedu.gov.cn:443/czzhszpj/j_hh_security_logout",
        "code": "",
        "relayUrl": "L2N6emhzenBqLw==",
        "bind": "0"
    }
    try:
        response = session.post(UserActionurl, cookies=jsCookie, data=data, allow_redirects=False)
        UserActionCookie = response.cookies
        redirect_url = response.headers.get('Location')
        redirect_response = session.get(redirect_url, cookies=UserActionCookie, allow_redirects=False)
        openstack_cookie = redirect_response.cookies
        openstack_cookie_insert = openstack_cookie.get('openstack_cookie_insert')
        UserActionCookie.set('openstack_cookie_insert', openstack_cookie_insert)
        GetHHCSRFToken(session, UserActionCookie)
    except Exception as e:
        print("@a", f"未知错误! {e}")

def GetHHCSRFToken(session, UserActionCookie):
    # 发送 GET 请求
    url = 'https://czzp.gdedu.gov.cn/czzhszpj/'
    response = session.get(url)
    try:
        # 解析 HTML
        soup = BeautifulSoup(response.text, 'html.parser')

        # 提取 HHCSRFToken
        script_tag = soup.find('script', string=lambda x: 'HHCSRFToken' in str(x))
        if script_tag:
            hhcsrf_token = script_tag.text.split('"')[1]
            print("[Debug] " + "HHCSRFToken:", hhcsrf_token)
            GetUserInfo(session, UserActionCookie, hhcsrf_token)
        else:
            print("HHCSRFToken not found.")
    except Exception as e:
        print("@a", f"未知错误! {e}")

def GetUserInfo(session, cookie, token):
    url = "https://czzp.gdedu.gov.cn/czzhszpj/web/common/head.do"
    headers = {
        "HHCSRFToken": token,
    }
    data = {"method": "queryUserXx"}

    response = session.post(url, headers=headers, data=data, cookies=cookie)
    try:
        if response.status_code == 200:
            json_data = response.json()
            yhxx = json_data.get("yhxx", {})
            xsJbxxId = yhxx.get("xsJbxxId")
            jtzz = yhxx.get("jtzz")
            xxmc = yhxx.get("xxmc")
            bjmc = yhxx.get("bjmc")
            print("学生id:", xsJbxxId)
            print("家庭住址:", jtzz)
            print("学校名称:", xxmc)
            print("班级名称:", bjmc)
            xsCltbIndex(session, cookie, xsJbxxId, token)
        else:
            print("请求失败，状态码:", response.status_code)
    except Exception as e:
        print("@a", f"未知错误! 状态码:{response.status_code} 请求后内容:{response.text}")

def pyxsCsbg(session, cookie, xsJbxxId, token, bjmc):
    pinyu = RandomPingyu()

    url = "https://czzp.gdedu.gov.cn/czzhszpj/web/csbg/xsCsbg.do?method=save"
    Checkurl = "https://czzp.gdedu.gov.cn/czzhszpj/web/csbg/xsCsbg.do"
    headers = {
        "Hhcsrftoken": token,
    }
    data = {
        "xscsbg": pinyu,
        "xsJbxxId": xsJbxxId,
        "bgfl": "0",
    }
    Checkdata = {
        "method": "queryCsbgByXsJbxxId",
        "xsJbxxId": xsJbxxId,
        "bgfl": "0",
    }
    try:
        response = session.post(url, data=data, headers=headers, cookies=cookie)
        if response.status_code == 200:
            if response.text == '"1"':
                response = session.post(Checkurl, data=Checkdata, headers=headers, cookies=cookie)
                json_data = response.json()
                Donepy = json_data.get("xscsbg")
                xm = json_data.get("xm")
                if Donepy:
                    print("@a", f"提交成功! \n·学生姓名:{xm} \n·班级为:{bjmc} \n·本次评语为:{pinyu} ")
                    xsCltbIndex(session, cookie, xsJbxxId, token)
                else:
                    print("@a", f"提交失败!")
    except Exception as e:
        print("@a", f"未知错误! 状态码:{response.status_code} 请求后内容:{response.text}")

def xsCltbIndex(session, cookie, xsJbxxId, token):

    url = "https://czzp.gdedu.gov.cn/czzhszpj/web/formsNav/xsCltbIndex.do"
    headers = {
        "Hhcsrftoken": token,
    }
    data = {
        "method": "saveXsTbtj",
        "xsJbxxId": xsJbxxId,
    }
    try:
        response = session.post(url, data=data, headers=headers, cookies=cookie)
        if response.status_code == 200:
            if response.text == '"1"':
                print("@a", f"档案确认成功!")
    except Exception as e:
        print("@a", f"未知错误! 状态码:{response.status_code} 请求后内容:{response.text}")

def RandomPingyu():
    essay1 = """我是一名中学生，平时的一言一行我都能按照《中学生日常行为规范》的要求去做，对学校的规章制度能够严格遵守，课余时间外出，能够遵守公共秩序及交通法规，对公共设施能够爱护，外出坐车我会主动给有需要的人让座或帮助他们。在劳动课上也从不偷懒。
在家里，经常帮助家长做家务，比如洗碗筷，擦地，修理一些简单毛病的电器，家里的电脑中病毒后从作系统等，父母工作忙，不在家时，可以做一些简单的饭菜，帮助表弟表妹学习，爸爸工作忙，家里的力气活，都是我帮妈妈干。
在学校和同学相处能够以诚相待，信守承诺，平时不管学习多忙，只要同学求我帮忙的事，我都会答应他们。比如他们组织的特色班会，需要我客串的，或需要我帮忙找的材料，我都会认真准备。
    """

    # 篇2
    essay2 = """在思想方面我能严格遵守学校纪律，有较强的集体荣誉感，乐于助人，关心同学，与同学相处融洽
如果是社会工作方面我会积极参与各项有益活动，培养了较强的策划、组织、协调、管理和创新能力以及吃苦耐劳的精神。
学习方面我以“勤奋务实、永争第一”作为自己的座佑铭。现实生活中我也以此来鞭策自己，学习态度严肃认真，学习目的明确。每个学期，我都能制定出科学、合理的学习计划，周密地安排时间，从不偏科。因此，我在上初中以来的每次考试中都能取得理想的成绩。
自我评价为人诚恳，乐观开朗，富拼搏精神，能吃苦耐劳。工作积极主动、认真踏实，有强烈的责任心和团队合作精神; 有较强的学习和适应新环境的能力，求知欲望强烈;进取心强，乐于助人，爱交际，人际关系好。
    """

    # 篇3
    essay3 = """我一直秉持着遵纪守法的原则，尊敬师长、热心助人、与同学相处融洽，这是我作为一个学生应该具备的基本素养。我深知团体荣誉感的重要性，因此努力为班级和学校做出积极的贡献。作为一名团员，我不仅在思想上不断提高自己，更注重遵守社会公德，积极投身各项实践活动，并关心国家大事，这是作为一名公民应尽的责任。在团组织的正确引导下，我努力锻炼自己，不断提高思想觉悟，以更好地为社会做出贡献。
我的性格活泼开朗，这使我能够积极参加各种有益的活动。我喜欢与同学们交流互动，在团队中发挥自己的特长，共同完成各项任务。我相信通过这样的积极参与，不仅能够锻炼自己的能力，更能够促进团队的凝聚力，为班级和学校营造更加和谐、活跃的氛围。
在未来的学习和成长过程中，我将继续保持良好的品行和习惯，努力发挥自己的优势，为实现个人价值和社会进步贡献自己的力量。
    """

    # 篇4
    essay4 = """本人，热爱祖国，遵纪守法，以自己是一个中国人而感到自豪，祖国的每一点变化，都牵动着我的心，香港回归的日子，神舟五号发射的日子，申奥成功的日子，都是我最难忘，最让我激动的日子，我与每一位热爱祖国的中国人一样，为那一时刻的到来而欢呼雀跃。
我从小养成了一个习惯。每当在电视里看到国旗升起地时候，就情不自禁地起立敬礼。曾经当过学校护旗手，也一直是我自豪与荣耀的经历。当国旗升起，国歌奏响后，我的内心就充满了自豪感，每天的新闻联播是我必看的内容。
学习之余，坐在车里，观看家乡的夜景，是让我最放松的一件事，这几年家乡的变化太大了，立交桥，景观大道，休闲广场，人们的生活环境越来越好了，我热爱祖国，热爱家乡，一定努力学习，争取为祖国与家乡的发展多做一份贡献。
    """

    # 随机选择一篇文章并输出
    selected_essay = random.choice([essay1, essay2, essay3, essay4])
    print(selected_essay.strip())
    return selected_essay.strip()

def Checker():
    try:
        czzp = requests.get("https://czzp.gdedu.gov.cn/", timeout=3)
        gl = requests.get("https://gl.gdedu.gov.cn/", timeout=3)
        if czzp.status_code == 200 and gl.status_code == 200:
            return True
        else:
            print("@a", f"综合平台目前处于无法访问状态! 请稍后再试")
            return False
    except Exception:
        print("@a", f"超时! 综合平台目前处于无法访问状态! 请稍后再试")
        return False

def main(username, password):
    check = Checker()
    if check:
        Login(username, password)

if __name__=="__main__":
    username = input("用户名: ")
    password = input("密码: ")
    main(username, password)
