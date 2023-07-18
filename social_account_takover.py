# -*- coding: utf-8 -*-
'''
 @author : Captain0X
 @time : 2023/1/5 12:54
 #脚本逻辑参考:https://github.com/utkusen/socialhunter/blob/main/main.go
 谷歌關鍵詞:intext:twitter.com site:hellosign.com
 fofa:body="tiktok.com/@" && domain="dropbox.com"
 '''
import re
import threading
import time
from urllib.parse import urlparse
import requests
import warnings
warnings.filterwarnings('ignore')


unique_link = []


def output_msg(*args, color="green"):
    msg = "".join([f"{_}"for _ in args])
    if color == "red":
        template = f'\033[1;31m[{time.strftime("%Y-%m-%d %H:%M:%S")}]{msg}\033[0m'
    else:
        template = f'\033[1;32m[{time.strftime("%Y-%m-%d %H:%M:%S")}]{msg}\033[0m'
    print(template)


def get_thd_num(thd_keyword):
    '''根据线程名关键词获取线程数'''
    thd_pool = []
    for td in threading.enumerate():
        cur_api = td.getName()
        if cur_api.startswith(thd_keyword):
            thd_pool.append(cur_api)
    output_msg(
        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] current thd is  {thd_pool} thd_num is {len(thd_pool)}")
    return thd_pool


def send_req(idx, url, headers=None, use_replit=True):
    # File operations (such as logging) can block the
    # event loop: run them in a thread pool.
    try:
        output_msg("正在爬取:", url)
        if not headers:
            headers = {
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.221 Safari/537.36 SE 2.X MetaSr 1.0'}
            headers = {'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
                       'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'document',
                       'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'none', 'sec-fetch-user': '?1',
                       'upgrade-insecure-requests': '1',
                       'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}

            resp = requests.get(url, headers=headers, timeout=80, verify=False,
                                # 设置小飞机代理
                                # proxies={"http": "http:127.0.0.1:10809",
                                #  "https": "https://127.0.0.1:10809"},
                                )
        print(resp.content)
        output_msg("爬取完成:", url)
        return resp
    except:
        return {}


def get_all_links(url, task_que):
    # https://x.redditinc.com/ 樣本
    # https://kb.acronis.com/
    if url == "finish":
        task_que.put(("finish", "finish", url))
    denyList = ["js", "jpg", "jpeg", "png", "gif", "bmp", "svg", "mp4", "webm", "mp3", "csv", "ogg", "wav", "flac",
                "aac", "wma", "wmv", "avi", "mpg", "mpeg", "mov", "mkv", "zip", "rar", "7z", "tar", "iso", "doc",
                "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "odp", "odg", "odf", "odb",
                "odc", "odm", "avi", "mpg", "mpeg", "mov", "mkv", "zip", "rar", "7z", "tar", "iso", "doc", "docx",
                "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "odp", "odg", "odf", "odb", "odc",
                "odm", "mp4", "webm", "mp3", "ogg", "wav", "flac", "aac", "wma", "wmv", "avi", "mpg", "mpeg", "mov",
                "mkv", "zip", "rar", "7z", "tar", "iso", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt",
                "rtf", "odt", "ods", "odp", "odg", "odf", "odb", "odc", "odm", "mp4", "webm", "mp3", "ogg", "wav",
                "flac", "aac", "wma", "wmv", "avi", "mpg", "mpeg", "mov", "mkv", "zip", "rar", "7z", "tar", "iso",
                "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt"]
    if url.split(".")[-1] in denyList:
        return
    if url in unique_link:
        return
    # gov白嫖党封杀
    if urlparse(url).netloc.endswith(".gov"):
        return
    unique_link.append(url)
    res_body = send_req(url, url)
    if not hasattr(res_body, "text"):
        return

    html = res_body.text
    print(html)
    links = re.findall("""["']https?:\/\/.*?['"]""", html)
    for link in links:
        link = re.sub("""['\"]""", "", link)
        # output_msg(link)
        link_host = urlparse(link).netloc
        if len(link) > 60 or re.findall("intent/tweet", link) or re.findall("twitter.com/share", link) or re.findall(
            "twitter.com/privacy", link) or re.findall("facebook.com/home", link) or re.findall(
                "instagram.com/p/", link) or re.findall('sharer/sharer.php', link):
            continue
        if link in unique_link:
            continue
        unique_link.append(link)
        task_que.put((link, link_host, url))
        # check_account_takover(link, link_host, url)

    # output_msg(html)


def check_twitter_user(username):
    '''推特用户需要从浏览器中复制推特的cookie'''
    api = f"https://api.twitter.com/graphql/hVhfo_TquFTmgL7gYwf91Q/UserByScreenName?variables=%7B%22screen_name%22%3A%22{username}%22%2C%22withSafetyModeUserFields%22%3Atrue%2C%22withSuperFollowsUserFields%22%3Atrue%7D&features=%7B%22responsive_web_twitter_blue_verified_badge_is_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D"
    headers = {'accept': '*/*', 'accept-encoding': 'gzip, deflate, br',
               'accept-language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
               'authorization': 'Bearer AAAAAAAAAAAI8xjhLTvJu4FA33AGWWjCpTnA',
               'cache-control': 'no-cache', 'content-type': 'application/json',
               'cookie': '_ga=GA1.2.2022108602.1578133858; remember_checked_on=1; guest_id_marketing=v1%3A160989111254248434; guest_id_ads=v1%3A160989111254248434; lang=zh-cn; _gid=GA1.2.299034402.1674529197; dnt=1; personalization_id="v1_5zROruDVi6R+V+sIn7hqYg=="; guest_id=v1%3A167498337570740111; _twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCL7TyvyFAToMY3NyZl9p%250AZCIlMGU1NzFjM2FmNzdkOTkzNDQ0OTNmOTcxNGVlZWI5ZGM6B2lkIiViOGIy%250AN2JhNTAzMWI0YjAyNDUzMWY1NjEzNTc0OTJmNg%253D%253D--abab13309670d6d2374a5691ab92ab34a4ea3f80; external_referer=padhuUp37zguL6FRibh2KjyphEsSyaM2|0|8e8t2xd8A2w%3D; gt=1619682955533910017; kdt=aEK47Gn43bCYyD0dzdOXULNncX1w2UFhIzcRxoII; auth_token=3a7b0164522ad967f2f5d5bf091b4039b3cf8831; twid=u%3D4246192519; att=1-QC2B6vF61vpCO6PF8Uxzjt9bdj799hm7NWXtQB6W; ct0=22bcca6d856183cd65916c6f4b77afb5f221a203a30218ffbc86b1d37046707e12c054bada8c8224ffe9c0e949bfeef8e13a429f37e854c927110e65d8dfc66b1b107dd156306bbc94cc6a6ce7441750',
               'origin': 'https://twitter.com', 'pragma': 'no-cache', 'referer': 'https://twitter.com/',
               'sec-ch-ua': '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
               'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
               'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site',
               'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
               'x-csrf-token': '22bc03a30218ffbc86b1d37046707e12c054bada8c8224ffe9c0e949bfeef8e13a429f37e854c927110e65d8dfc66b1b107dd156306bbc94cc6a6ce7441750',
               'x-twitter-active-user': 'yes', 'x-twitter-auth-type': 'OAuth2Session',
               'x-twitter-client-language': 'zh-cn'}
    resp = send_req("twitter", api, headers, use_replit=False)
    if hasattr(resp, "status_code"):
        if re.findall(username, str(resp.content), re.IGNORECASE):
            return False
        else:
            return True
    return "except"


def check_account_takover(task_que, scan_result_path):
    while True:
        link, link_host, url = task_que.get()
        if link == "finish":
            break
        if re.findall("facebook\.com", link_host):
            # facebook存在反爬的情况，建议降低速度
            time.sleep(3)
            # https://www.facebook.com/reddit
            # <title id="pageTitle">Facebook</title>
            resp = send_req(url, link)
            if hasattr(resp, "status_code"):
                if re.findall(b'>Facebook</title>', resp.content):
                    output_msg(link)
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('人工确认 source url->' + url +
                                '\ntarget:' + str(link) + '\n')
                    # 由於不確定，和反爬虫，乾脆人工檢查算了
        elif re.findall("tiktok\.com", link_host):
            # "https://www.tiktok.com/@jack11111111111111111111111111"
            # 返回404狀態碼基本就是
            if "@" in link:
                resp = send_req(url, link)
                if hasattr(resp, "status_code"):
                    if resp.status_code == 404:
                        output_msg("发现漏洞", link)
                        with open(scan_result_path,
                                  'a', encoding="utf-8") as f:
                            f.write('发现漏洞 source url->' + url +
                                    '\ntarget:' + str(link) + '\n')
            # output_msg(link)
        elif re.findall("instagram.com", link_host):
            # https://www.instagram.com/reddit/
            # output_msg(link)
            pass
            # with open(scan_result_path,
            #           'a', encoding="utf-8") as f:
            #     f.write('人工确认 source url->' + url + '\ntarget:' + str(link) + '\n')
        elif re.findall("twitter\.com", link_host):
            # https://twitter.com/dropbox
            # output_msg(""link)
            time.sleep(3)
            try:
                username = urlparse(link).path.split('/')[1]
                result = check_twitter_user(username)
                if isinstance(result, str):
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('人工确认 source url->' + url +
                                '\ntarget:' + str(link) + '\n')
                elif result:
                    output_msg("发现漏洞", link)
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('发现漏洞 source url->' + url +
                                '\ntarget:' + str(link) + '\n')
                # Something went wrong, but don’t fret
            except IndexError:
                pass

        elif re.findall("youtube\.com", link_host):
            if "user/" in link:
                resp = send_req(url, link)
                if hasattr(resp, "status_code"):
                    if resp.status_code == 404:
                        output_msg("发现漏洞:", link)
                        with open(scan_result_path,
                                  'a', encoding="utf-8") as f:
                            f.write('发现漏洞 source url->' + url +
                                    '\ntarget:' + str(link) + '\n')
                # https://www.youtube.com/user/dropbox
        elif re.findall("reddit\.com", link_host):
            # https://www.reddit.com/r/acronis/
            pass
        elif re.findall("linkedin\.com", link_host):
            # https://www.linkedin.com/company/acronis
            with open(scan_result_path,
                      'a', encoding="utf-8") as f:
                f.write('人工确认 source url->' + url +
                        '\ntarget:' + str(link) + '\n')
        elif re.findall("community\.spiceworks\.com", link_host):
            # https://community.spiceworks.com/pages/acronis
            resp = send_req(url, link)
            if hasattr(resp, "status_code"):
                if resp.status_code == 404:
                    output_msg("发现漏洞:", link)
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('发现漏洞 source url->' + url +
                                '\ntarget:' + str(link) + '\n')
        elif re.findall("pinterest\.com", link_host):
            # https://www.pinterest.com/wholefoods/
            # "httpStatus":404}
            resp = send_req(url, link)
            if hasattr(resp, "text"):
                if re.findall('"httpStatus":404}', resp.text):
                    output_msg("发现漏洞:", link)
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('发现漏洞 source url->' + url +
                                '\ntarget:' + str(link) + '\n')
        elif re.findall("twitch\.tv", link_host):
            # https://www.twitch.tv/aws
            with open(scan_result_path,
                      'a', encoding="utf-8") as f:
                f.write('人工确认 source url->' + url +
                        '\ntarget:' + str(link) + '\n')
        elif re.findall("medium\.com", link_host):
            # https://medium.com/bybit
            resp = send_req(url, link)
            if hasattr(resp, "text"):
                if re.findall('"httpStatus":404}', resp.text):
                    output_msg("发现漏洞:", link)
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('发现漏洞 source url->' + url +
                                '\ntarget:' + str(link) + '\n')
        elif re.findall("patreon\.com", link_host):
            # https://www.patreon.com/startentrepreneureonline
            resp = send_req(url, link)
            if hasattr(resp, "status_code"):
                if resp.status_code == 404:
                    output_msg("发现漏洞", link)
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('发现漏洞 source url->' + url +
                                '\ntarget:' + str(link) + '\n')

        elif re.findall("vk\.com", link_host):
            # https://vk.com/startentrepreneureonline111111111
            resp = send_req(url, link)
            if hasattr(resp, "status_code"):
                if resp.status_code == 404:
                    output_msg("发现漏洞", link)
                    with open(scan_result_path,
                              'a', encoding="utf-8") as f:
                        f.write('发现漏洞 source url->' + url +
                                '\ntarget:' + str(link) + '\n')


if __name__ == '__main__':
    banner = '''使用方法:
    1.在当前新建target.txt,把url放进去,一行一个url
    2.配置scan_result_path结果保存文件路径
    3.修改默认线程数,一般为5线程
    3.运行完毕后查看结果文件，大多数需要手工去确认是否存在漏洞，工具只是辅助
    by Captain0X
    '''
    print(banner)
    from queue import Queue
    task_que = Queue()
    # 扫描结果保存文件路径
    scan_result_path = "./social_account_takover/h1_hunter_result.txt"

    cd = threading.Thread(target=check_account_takover,
                          args=(task_que, scan_result_path))
    cd.start()
    # 任务文件路径
    task_path = "target.txt"

    # 默认线程数
    thd_num = 5
    with open(task_path, "r", encoding="utf-8")as f:
        urls = f.readlines()
    for idx, uri in enumerate(urls):
        url = uri.strip()

        if not url.startswith("http"):
            target = "https://" + url
        else:
            target = url
        parse_url = urlparse(target)
        netloc = parse_url.netloc
        if netloc:
            pid = threading.Thread(
                target=get_all_links, args=(target, task_que))
            thd_name = "hunter:" + target
            pid.setName(thd_name)
            pid.start()
            while True:
                thd_pool = get_thd_num("hunter")
                if len(thd_pool) < thd_num:
                    break
                time.sleep(0.3)

    while True:
        thd_pool = get_thd_num("hunter")
        if len(thd_pool) < 1:
            task_que.put(("finish", "", ""))
            break
        time.sleep(0.3)
    output_msg("扫描完成！")
