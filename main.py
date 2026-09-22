import json
import os
import sys
import time
import re
import threading
import contextlib
from io import BytesIO
from queue import Queue, Empty
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
from PIL import Image
from pypdf import PdfReader, PdfWriter, Transformation, PageObject
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# ===================== 全局配置与存储路径 =====================
def get_data_dir() -> str:
    """数据文件(cookie/账号/配置/日志)存放目录：
    优先用可执行文件所在目录（便携式）；不可写则回退到系统用户数据目录，兼容mac/win"""
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        probe = os.path.join(exe_dir, ".write_test")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return exe_dir
    except Exception:
        pass
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.path.expanduser("~")
    data_dir = os.path.join(base, "杂志PDF下载工具")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


DATA_DIR = get_data_dir()
ACCOUNT_STORE = os.path.join(DATA_DIR, "mag_account_store.json")
CONFIG_STORE = os.path.join(DATA_DIR, "mag_config_store.json")
COOKIE_STORE = os.path.join(DATA_DIR, "mag_cookies.json")
LOG_FILE = os.path.join(DATA_DIR, "mag_run.log")
TASK_STOP_EVENT = threading.Event()
LOG_QUEUE = Queue()  # 无maxsize，put_nowait不会阻塞后台线程
API_CALL_INTERVAL = 0.3  # 每次接口调用后的统一间隔(秒)，控制请求频率
DOWNLOAD_INTERVAL = 0.5  # 每张图片下载后的统一间隔(秒)，控制请求频率


def log_print(text: str):
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{t}] {text}"
    # 写入本地日志文件
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass
    LOG_QUEUE.put_nowait(msg)


def check_stop():
    if TASK_STOP_EVENT.is_set():
        raise RuntimeError("TaskStopped")


def safe_sleep(sec: float):
    if TASK_STOP_EVENT.wait(timeout=sec):
        raise RuntimeError("TaskStopped")


# ===================== 账号存储工具 =====================
def load_accounts():
    if not os.path.exists(ACCOUNT_STORE):
        return {}
    try:
        with open(ACCOUNT_STORE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_account(phone: str, pwd: str):
    if not phone.strip():
        return
    data = load_accounts()
    data[phone.strip()] = pwd.strip()
    with open(ACCOUNT_STORE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_last_config():
    if not os.path.exists(CONFIG_STORE):
        return {}
    try:
        with open(CONFIG_STORE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_last_config(cfg: dict):
    with open(CONFIG_STORE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


# ===================== Playwright 登录获取Cookie 模块 =====================
class BrowserConfig:
    VIEWPORT = {"width": 1920, "height": 1080}
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    )
    HOME_URL = "https://web.591adb.cn/hngymyzyxy.html"
    LOGIN_URL = "https://web.591adb.cn/login/hngymyzyxy.html"
    LOGIN_COOKIE_NAME = "hngymyzyxy_info"  # 登录会话cookie名，用于判断本地cookie是否过期
    REQ_HEADERS = {
        "User-Agent": USER_AGENT,
        "Referer": "https://web.591adb.cn/",
    }


def safe_goto(page, url, max_retries=3):
    for i in range(max_retries):
        check_stop()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            return True
        except Exception as e:
            log_print(f"导航尝试 {i+1}/{max_retries} 失败:{e}")
            safe_sleep(2)
    return False


def is_logged_in(page) -> bool:
    try:
        return (
            page.locator("a.edit-password").count() > 0
            or page.locator("a.logout").count() > 0
        )
    except Exception:
        return False


WAF_CAPTCHA_SELECTOR = (
    "#vc_captcha_box, .vc_captcha_box_theme, #captcha_container, .captcha_verify_bar--title"
)
# 火山引擎WAF安全检测页特征：页面返回HTTP 200且不含登录表单，只能靠内容识别
WAF_TEXT_MARKERS = ("安全检测", "TTGCaptcha", "waf-captcha-proxy")


def wait_for_manual_captcha(page, timeout: int = 120) -> bool:
    try:
        captcha = page.locator(WAF_CAPTCHA_SELECTOR)
        if captcha.count() == 0:
            log_print("未检测到滑动验证码")
            return True
        log_print("⚠️检测到滑动验证码，请手动在浏览器完成验证")
        deadline = time.time() + timeout
        while time.time() < deadline:
            check_stop()
            if captcha.count() == 0 or not captcha.first.is_visible():
                log_print("✅验证码验证通过")
                safe_sleep(1)
                return True
            safe_sleep(1)
        log_print("❌等待验证码超时")
        return False
    except Exception as e:
        log_print(f"验证码检测异常:{e}")
        return True


def is_waf_challenge(page) -> bool:
    """当前页面是否为站点前置的WAF安全检测页；
    读不到页面（正在跳转/被abort）时按“尚未就绪”处理，让调用方继续等"""
    try:
        if page.locator(WAF_CAPTCHA_SELECTOR).count() > 0:
            return True
        html = page.content()
    except Exception:
        return True
    return any(m in html for m in WAF_TEXT_MARKERS)


def has_login_form(page) -> bool:
    """登录表单是否已出现（判断真实页面已就绪，而不是WAF检测页）"""
    try:
        return page.locator("#phone_number").count() > 0
    except Exception:
        return False


def is_page_ready(page) -> bool:
    """页面是否已真正加载出内容。
    注意：WAF检测页通过后 successCb 会 location.reload()，reload 过渡期 DOM 为空，
    此时 page.content() 里既没有WAF特征、也没有正文，绝不能判成“检测已通过”，
    否则会在页面还没出来时就再次跳转，把加载中的页面打断，陷入空转"""
    try:
        if page.locator(WAF_CAPTCHA_SELECTOR).count() > 0:
            return False
        return bool(
            page.evaluate(
                "() => !!(document.body && document.body.innerText "
                "&& document.body.innerText.trim().length > 20)"
            )
        )
    except Exception:
        return False


def wait_page_ready(page, timeout: int = 180) -> bool:
    """等待页面真正就绪：WAF安全检测页、以及检测通过后的reload过渡期都算“未就绪”。
    检测到滑块时提示用户在浏览器窗口手动完成，程序只负责等待，不做任何自动绕过。
    就绪返回True；超时返回False（调用方自行决定后续）"""
    deadline = time.time() + timeout
    notified = False
    while time.time() < deadline:
        check_stop()
        if is_page_ready(page):
            if notified:
                log_print("✅站点安全检测已通过，页面已加载完成")
            return True
        if not notified and is_waf_challenge(page):
            log_print("⚠️站点安全检测（火山引擎WAF）拦截：请在已打开的浏览器窗口手动完成滑块验证，程序会自动等待")
            notified = True
        safe_sleep(1)
    log_print(f"⚠️等待页面加载就绪超时（{timeout}秒）")
    return False


def goto_quiet(page, url) -> bool:
    """跳转并吞掉异常：WAF检测页 successCb 里的 location.reload() 会和我们的goto抢导航，
    产生 ERR_ABORTED，属正常竞态，不该中断流程"""
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        return True
    except Exception as e:
        log_print(f"⚠️跳转 {url} 异常:{e}")
        return False


def click_login_button(page):
    login_btn = page.locator("a.top-login-btn")
    if login_btn.count() > 0:
        try:
            login_btn.first.click()
            safe_sleep(2)
        except Exception as e:
            log_print(f"点击登录按钮异常:{e}")


def ensure_on_login_page(page, timeout: int = 240) -> bool:
    """进入登录页：站点前置了WAF安全检测，且检测通过后页面还会reload，
    所以每次跳转后都要先等页面真正就绪，再看登录表单在不在"""
    log_print("进入登录页面")
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        check_stop()
        if has_login_form(page):
            log_print("成功进入登录页")
            return True
        attempt += 1
        if attempt > 1:
            log_print(f"第{attempt}次尝试进入登录页")
        # 奇数轮直接开登录页，偶数轮回首页点登录按钮（保留原有两条路径）
        if attempt % 2 == 1:
            goto_quiet(page, BrowserConfig.LOGIN_URL)
        else:
            goto_quiet(page, BrowserConfig.HOME_URL)
            click_login_button(page)
        wait_page_ready(page, timeout=90)
        if not has_login_form(page):
            try:
                log_print(f"   当前页面: {page.url} | 标题: {page.title()[:40]}")
            except Exception:
                pass
    log_print("❌等待进入登录页超时，始终未出现登录表单 #phone_number")
    return False


def load_saved_cookies():
    """读取本地保存的cookie，返回(账号, cookie列表)；无文件或损坏返回("", [])"""
    if not os.path.exists(COOKIE_STORE):
        return "", []
    try:
        with open(COOKIE_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("phone", ""), data.get("cookies") or []
    except Exception as e:
        log_print(f"⚠️读取本地cookie失败: {e}")
    return "", []


def save_cookies_to_file(phone: str, cookies: list):
    """登录成功后把cookie保存到本地"""
    try:
        payload = {
            "phone": phone.strip(),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cookies": cookies,
        }
        with open(COOKIE_STORE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        log_print(f"✅Cookie已保存到本地 {COOKIE_STORE}")
    except Exception as e:
        log_print(f"⚠️Cookie保存失败: {e}")


def build_session_from_cookies(cookies: list) -> requests.Session:
    """把cookie列表注入requests.Session"""
    session = requests.Session()
    session.headers.update(BrowserConfig.REQ_HEADERS)
    for ck in cookies:
        session.cookies.set(ck["name"], ck["value"], domain=ck.get("domain"), path=ck.get("path"))
    return session


def cookies_statically_expired(cookies: list) -> bool:
    """静态判断：关键登录cookie的expires是否已过；会话型cookie(expires=-1)交给动态探测"""
    now = time.time()
    for c in cookies:
        if c.get("name") != BrowserConfig.LOGIN_COOKIE_NAME:
            continue
        exp = c.get("expires")
        try:
            exp = float(exp)
        except (TypeError, ValueError):
            return True  # 字段异常，保守视为过期
        if exp < 0:
            return False  # 会话型cookie，存活时间由服务端决定，交给动态探测
        return exp <= now
    return False


def has_login_cookie(cookies: list) -> bool:
    """本地cookie里是否存在登录cookie；没有就说明是匿名会话，必须走登录"""
    return any(c.get("name") == BrowserConfig.LOGIN_COOKIE_NAME for c in cookies)


NO_LOGIN_MARKERS = ("请登录后再做操作", '"no_login"')


def is_no_login_response(text: str) -> bool:
    """站点改版后：reader等正文接口未登录时返回
    {"code":0,"msg":"请登录后再做操作","data":{"no_login":1}}，HTTP状态仍是200"""
    if not text:
        return False
    return any(m in text for m in NO_LOGIN_MARKERS)


def build_context_from_cookies(
    chrome_exe_path: str, cookies: list, headless: bool = False
) -> "BrowserHolder":
    """启动浏览器并注入cookie，返回holder；失败会抛异常。
    默认可见模式：站点前置了火山引擎WAF，实测无头浏览器过不了安全检测
    （检测页不会自动放行），只有可见浏览器能过一次检测后正常访问"""
    holder = BrowserHolder()
    try:
        holder.playwright = sync_playwright().start()
        launch_opt = {"headless": headless}
        resolved = resolve_chrome_path(chrome_exe_path)
        if resolved:
            launch_opt["executable_path"] = resolved
        else:
            launch_opt["channel"] = "chrome"
        holder.browser = holder.playwright.chromium.launch(**launch_opt)
        holder.context = holder.browser.new_context(
            viewport=BrowserConfig.VIEWPORT, user_agent=BrowserConfig.USER_AGENT
        )
        if cookies:
            pw_cookies = []
            for ck in cookies:
                item = {
                    "name": ck["name"],
                    "value": ck["value"],
                    "domain": (ck.get("domain") or "").lstrip("."),
                    "path": ck.get("path") or "/",
                }
                exp = ck.get("expires")
                try:
                    exp = float(exp)
                    if exp > 0:
                        item["expires"] = int(exp)
                except (TypeError, ValueError):
                    pass
                pw_cookies.append(item)
            holder.context.add_cookies(pw_cookies)
        return holder
    except Exception:
        holder.close()
        raise


def probe_api_available(holder, keyword: str = "") -> bool:
    """用浏览器通道请求搜索接口，能拿到正常JSON(code=1)才算通道可用。
    站点改版后 a.edit-password/a.logout 等登录态标记已消失，登录页还会把已认证的会话重定向回首页，
    所以不能再靠“登录标记”判断，只能看接口是否真的可用。
    ⚠️必须先让浏览器打开首页跑一次JS过掉WAF安全检测，否则接口拿回的是检测页"""
    page = None
    try:
        page = holder.context.new_page()
        goto_quiet(page, BrowserConfig.HOME_URL)
        if not wait_page_ready(page, timeout=90):
            log_print("⚠️浏览器通道：站点安全检测未通过，无法探测接口")
            return False
        ts = int(time.time() * 1000)
        url = (
            f"https://web.591adb.cn/search/hngymyzyxy.html?st=1&page_num=1"
            f"&keywords={requests.utils.quote(keyword or '期刊')}&withCount=1&ts={ts}"
        )
        headers = dict(BrowserConfig.REQ_HEADERS)
        headers.update(
            {"x-requested-with": "XMLHttpRequest", "sec-fetch-mode": "cors", "priority": "u=1,i"}
        )
        resp = holder.context.request.get(url, headers=headers, timeout=30000)
        text = resp.text()
        data = json.loads(text)
        if data.get("code") == 1:
            return True
        log_print(f"⚠️搜索接口返回异常: {str(data)[:200]}")
        return False
    except Exception as e:
        log_print(f"⚠️浏览器通道接口探测失败: {e}")
        return False
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass


def get_valid_session(chrome_exe_path: str, phone: str, password: str, keyword: str = ""):
    """获取(requests会话, 浏览器holder, prefer_pw恒为True)。
    站点已加火山引擎WAF安全检测，实测结论：
      - requests 被拦，返回检测页而非接口数据
      - 无头浏览器同样过不了检测，检测页不会自动放行
      - 只有可见浏览器能过一次检测，之后所有请求沿用该浏览器通道(context.request)
    站点改版后正文(reader)接口已强制登录：匿名请求返回 {"code":0,"data":{"no_login":1}}，
    而搜索接口匿名仍可用，所以不能再靠“搜索接口通”判断会话可用，必须确认有登录cookie"""
    saved_phone, saved = load_saved_cookies()
    use_saved = bool(saved) and saved_phone == phone.strip()
    if saved and not use_saved:
        log_print("⚠️本地cookie属于其他账号，忽略本地cookie")
        saved = []
        use_saved = False
    elif not saved:
        log_print("本地无保存的cookie，需要登录")
    elif cookies_statically_expired(saved):
        log_print("⚠️本地cookie的时间戳已过期，需要重新登录")

    # 只有本地存在有效登录cookie时，才允许跳过登录
    can_reuse = use_saved and has_login_cookie(saved) and not cookies_statically_expired(saved)
    holder = None
    if can_reuse:
        try:
            holder = build_context_from_cookies(chrome_exe_path, saved)
            if probe_api_available(holder, keyword):
                log_print("✅本地登录cookie有效，浏览器通道验证通过，开始爬取")
                return build_session_from_cookies(saved), holder, True
            log_print("⚠️本地登录cookie已失效，改为重新登录")
        except Exception as e:
            log_print(f"⚠️浏览器通道建立失败: {e}，改为登录")
        if holder is not None:
            holder.close()
            holder = None
    else:
        log_print("🚀正文接口需要登录态，开始登录")

    # 登录后直接沿用这个已登录、且已过WAF的浏览器通道：
    # 重开浏览器会再次触发WAF安全检测，白白让用户多滑一次滑块
    session, holder = login_and_get_session(chrome_exe_path, phone, password)
    if holder is not None:
        log_print("✅已登录，沿用当前浏览器通道开始爬取")
        return session, holder, True
    _, fresh = load_saved_cookies()
    log_print("⚠️登录浏览器通道不可用，改用保存的cookie新建通道")
    try:
        holder = build_context_from_cookies(chrome_exe_path, fresh)
        log_print("✅已启动浏览器通道，开始爬取")
    except Exception as e:
        log_print(f"⚠️登录后浏览器通道启动失败: {e}")
    return build_session_from_cookies(fresh), holder, True


class BrowserHolder:
    """保持Playwright浏览器在爬取期间存活，用于接口被WAF拦截时回退到浏览器通道；用完必须close()"""

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None

    def close(self):
        for obj in (self.context, self.browser):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
        if self.playwright is not None:
            try:
                self.playwright.stop()
            except Exception:
                pass


class ApiClient:
    """接口请求封装：优先requests；返回被拦截(非JSON/异常HTML)时自动切换Playwright浏览器通道"""

    def __init__(self, session: requests.Session = None, pw_context=None, prefer_pw: bool = False):
        self.session = session
        self.pw_context = pw_context
        self.use_pw = prefer_pw  # True=全程走浏览器通道（不尝试requests）
        if prefer_pw:
            log_print("接口请求直接使用浏览器通道（跳过requests）")

    @staticmethod
    def _looks_blocked(ct: str, body: str) -> bool:
        ct = (ct or "").lower()
        if "json" in ct or (body or "").lstrip().startswith("{"):
            return False
        # HTML只有阅读器的正常HTML(含slider-img)不算被拦
        return "slider-img" not in (body or "")

    def get_text(self, url, headers=None, timeout=30, retries=2) -> str:
        """对外统一入口：每次接口调用后固定间隔 API_CALL_INTERVAL，控制请求频率"""
        body = self._request_text(url, headers, timeout, retries)
        safe_sleep(API_CALL_INTERVAL)
        return body

    def _request_text(self, url, headers=None, timeout=30, retries=2) -> str:
        for attempt in range(retries + 1):
            check_stop()
            if not self.use_pw and self.session is not None:
                try:
                    resp = self.session.get(url, headers=headers, timeout=timeout)
                    body = resp.text
                    if not self._looks_blocked(resp.headers.get("content-type"), body):
                        return body
                    log_print(f"⚠️requests返回异常内容 status={resp.status_code}，疑似被WAF拦截，切换浏览器通道")
                    log_print(f"   响应片段: {(body or '')[:200]}")
                    self.use_pw = True
                except Exception as e:
                    log_print(f"⚠️requests请求异常:{e}，切换浏览器通道")
                    self.use_pw = True
            if self.pw_context is not None:
                try:
                    # 注意：Playwright的timeout单位是毫秒
                    resp = self.pw_context.request.get(url, headers=headers or {}, timeout=timeout * 1000)
                    body = resp.text()
                    if resp.ok and not self._looks_blocked(resp.headers.get("content-type"), body):
                        return body
                    log_print(f"⚠️浏览器通道响应异常 status={resp.status}，第{attempt + 1}/{retries + 1}次尝试")
                    log_print(f"   响应片段: {(body or '')[:200]}")
                except Exception as e:
                    log_print(f"⚠️浏览器通道请求异常:{e}，第{attempt + 1}/{retries + 1}次尝试")
            else:
                log_print(f"⚠️无浏览器通道可用，第{attempt + 1}/{retries + 1}次尝试")
            safe_sleep(2)
        return ""

    def get_bytes(self, url, timeout=30):
        """下载二进制内容，返回bytes或None；requests失败自动走浏览器通道"""
        if not self.use_pw and self.session is not None:
            try:
                resp = self.session.get(url, timeout=timeout)
                resp.raise_for_status()
                return resp.content
            except Exception:
                self.use_pw = True
        if self.pw_context is not None:
            try:
                # 注意：Playwright的timeout单位是毫秒
                resp = self.pw_context.request.get(url, timeout=timeout * 1000)
                if resp.ok:
                    return resp.body()
            except Exception as e:
                log_print(f"⚠️浏览器通道下载异常:{e}")
        return None


def resolve_chrome_path(chrome_exe_path: str) -> str:
    """解析可用的Chrome路径：优先用户指定的；无效时尝试系统常见安装路径（mac/win）；都不存在返回空串"""
    if chrome_exe_path and os.path.exists(chrome_exe_path):
        return chrome_exe_path
    candidates = []
    if sys.platform == "win32":
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]
    elif sys.platform == "darwin":
        candidates = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""


def login_and_get_session(chrome_exe_path: str, phone: str, password: str):
    """启动浏览器登录，返回(requests会话, 浏览器holder)；holder需在任务结束后close()"""
    holder = BrowserHolder()
    try:
        holder.playwright = sync_playwright().start()
        launch_opt = {"headless": False}
        resolved = resolve_chrome_path(chrome_exe_path)
        if resolved:
            launch_opt["executable_path"] = resolved
            if chrome_exe_path and os.path.normpath(chrome_exe_path) != os.path.normpath(resolved):
                log_print(f"⚠️指定的Chrome路径无效，自动使用: {resolved}")
            else:
                log_print(f"✅使用指定的Chrome: {resolved}")
        else:
            launch_opt["channel"] = "chrome"
            if chrome_exe_path:
                log_print(f"⚠️指定的Chrome路径不存在，改用系统Chrome: {chrome_exe_path}")
            else:
                log_print("未指定Chrome路径，使用系统Chrome")
        holder.browser = holder.playwright.chromium.launch(**launch_opt)
        holder.context = holder.browser.new_context(
            viewport=BrowserConfig.VIEWPORT, user_agent=BrowserConfig.USER_AGENT
        )
        page = holder.context.new_page()
        goto_quiet(page, BrowserConfig.HOME_URL)
        # 站点前置了WAF安全检测：先等页面（检测页 + 检测通过后的reload过渡期）真正就绪，
        # 再判断登录态，否则会把检测页/空白页误判成“未登录”
        wait_page_ready(page)
        if not wait_for_manual_captcha(page):
            raise Exception("验证码等待失败")
        if not is_logged_in(page):
            if not ensure_on_login_page(page):
                raise Exception("无法进入登录页面")
            if not wait_for_manual_captcha(page):
                raise Exception("登录页验证码失败")
            page.wait_for_selector("#phone_number", timeout=12000)
            log_print(f"输入账号:{phone}")
            page.fill("#phone_number", phone)
            safe_sleep(0.3)
            page.fill("#phone_pwd", password)
            safe_sleep(0.3)
            page.dispatch_event("#phone_number", "input")
            page.dispatch_event("#phone_pwd", "input")
            safe_sleep(0.5)
            login_submit = page.locator("input.phone_login_btn")
            if login_submit.count() > 0:
                log_print("点击登录按钮")
                try:
                    login_submit.click()
                    safe_sleep(3)
                except Exception as e:
                    log_print(f"点击登录异常:{e}")
            login_ok = False
            for _ in range(12):
                check_stop()
                if is_logged_in(page):
                    log_print("✅登录成功")
                    login_ok = True
                    break
                if (
                    page.locator(
                        "#captcha_container, .vc_captcha_box_theme"
                    ).count()
                    > 0
                ):
                    wait_for_manual_captcha(page, timeout=60)
                safe_sleep(3)
            if not login_ok:
                log_print("⚠️未检测登录成功标记，继续使用当前cookie尝试")
        safe_sleep(1)
        cookies = holder.context.cookies()
        save_cookies_to_file(phone, cookies)
        return build_session_from_cookies(cookies), holder
    except Exception:
        holder.close()
        raise


# ===================== 杂志爬取模块 =====================
def parse_search_html(html: str):
    pattern = r'data-href="\/magazine\/detail\/hngymyzyxy_(\d+)\.html\?_=\d+"'
    match = re.search(pattern, html)
    if not match:
        return None
    return {"resource_id": match.group(1)}


def parse_reader_response(resp_text: str):
    img_urls = []
    try:
        data = json.loads(resp_text)
        if data.get("error") == 0 and "data" in data:
            image_list = data["data"].get("image_list", [])
            for img in image_list:
                img = img.replace("\\", "")
                img_urls.append(img)
            return img_urls
    except json.JSONDecodeError:
        pass
    matches = re.findall(r'<img class="slider-img" src="([^"]*0001\.webp)"', resp_text)
    for m in matches:
        img_urls.append(m.replace("\\", ""))
    return img_urls


def download_image(url: str, save_path: str, client: ApiClient, max_retry=3, retry_interval=30):
    """带重试下载图片，失败间隔30秒，最多重试3次；requests失败自动走浏览器通道。
    每次下载后固定间隔 DOWNLOAD_INTERVAL，控制请求频率"""
    check_stop()
    for attempt in range(1, max_retry + 1):
        check_stop()
        try:
            data = client.get_bytes(url)
            if data is None:
                raise Exception("下载返回空内容")
            with open(save_path, "wb") as f:
                f.write(data)
            log_print(f"已下载 {os.path.basename(save_path)}")
            safe_sleep(DOWNLOAD_INTERVAL)
            return True
        except Exception as e:
            log_print(f"下载失败[{attempt}/{max_retry}] {url}: {e}")
            if attempt >= max_retry:
                log_print(f"❌该图片多次重试失败，跳过 {url}")
                return False
            safe_sleep(retry_interval)
    return False


def normalize_volume_keyword(part: str) -> str:
    """把 '9'、'9期'、'第9期' 统一为 '第9期'，其他写法原样保留（用于包含匹配）"""
    part = part.strip()
    m = re.match(r"^(?:第)?(\d+)(?:期)?$", part)
    if m:
        return f"第{m.group(1)}期"
    return part


def match_volume_rows(raw_year_blocks: list, target_year_set: set, target_volume_set: set) -> list:
    """按年份/期刊关键词过滤刊期列表；年份集合为空=全部年份，期刊关键词为空=全部期刊"""
    result = []
    for year_block in raw_year_blocks:
        item_year = year_block.get("item_year", "")
        item_list = year_block.get("item_list", [])
        if target_year_set:
            if item_year not in target_year_set:
                continue
        for row in item_list:
            volume = row.get("volume", "")
            if len(target_volume_set) > 0:
                if not any(tv in volume for tv in target_volume_set):
                    continue
            result.append(row)
    return result


def crawl_magazine_images(
    session: requests.Session,
    keyword: str,
    target_year: str,
    target_volume_name_text: str,
    save_root: str,
    pw_context=None,
    prefer_pw: bool = False,
):
    client = ApiClient(session, pw_context, prefer_pw=prefer_pw)
    ts = int(time.time() * 1000)
    search_url = (
        f"https://web.591adb.cn/search/hngymyzyxy.html?st=1&page_num=1"
        f"&keywords={requests.utils.quote(keyword)}&withCount=1&ts={ts}"
    )
    xml_headers = dict(BrowserConfig.REQ_HEADERS)
    xml_headers.update(
        {
            "x-requested-with": "XMLHttpRequest",
            "sec-fetch-mode": "cors",
            "priority": "u=1,i",
        }
    )
    log_print(f"请求搜索接口 {search_url}")
    search_text = client.get_text(search_url, headers=xml_headers)
    if not search_text:
        raise Exception("搜索接口请求失败（requests与浏览器通道均失败）")
    try:
        search_json = json.loads(search_text)
    except json.JSONDecodeError:
        raise Exception(f"搜索接口返回非JSON内容: {search_text[:200]}")
    if search_json.get("code") != 1:
        raise Exception(f"搜索接口返回失败: {search_json}")
    data_section = search_json.get("data", {})
    html_str = data_section.get("html", "")
    parse_res = parse_search_html(html_str)
    if not parse_res:
        raise Exception("解析不到resource_id")
    resource_id = parse_res["resource_id"]
    log_print(f"resource_id={resource_id}")
    corver_ts = int(time.time() * 1000)
    cover_url = f"https://web.591adb.cn/magazine/thumblist/hngymyzyxy_{resource_id}.html?p=1&_={corver_ts}"
    cover_text = client.get_text(cover_url, headers=xml_headers)
    if not cover_text:
        raise Exception("获取封面列表请求失败")
    try:
        cover_json = json.loads(cover_text)
    except json.JSONDecodeError:
        raise Exception(f"封面列表接口返回非JSON内容: {cover_text[:200]}")
    if cover_json.get("error") != 0:
        raise Exception("获取封面列表失败")
    item_info = cover_json.get("data", {}).get("item_info", {})
    magazine_id = item_info.get("magazine_id")
    past_ts = int(time.time() * 1000)
    past_url = f"https://web.591adb.cn/magazine/past/hngymyzyxy_{magazine_id}.html?_={past_ts}"
    past_text = client.get_text(past_url, headers=xml_headers)
    if not past_text:
        raise Exception("获取刊期列表请求失败")
    try:
        past_json = json.loads(past_text)
    except json.JSONDecodeError:
        raise Exception(f"刊期列表接口返回非JSON内容: {past_text[:200]}")
    if past_json.get("error") != 0:
        raise Exception("获取刊期列表失败")

    # 解析多年份：英文逗号分割
    target_year_set = set()
    if target_year and target_year.strip():
        for part in target_year.split(","):
            p = part.strip()
            if p:
                target_year_set.add(p)
    if target_year_set:
        log_print(f"目标年份:{sorted(target_year_set)}")

    # 解析多期：英文逗号分割
    target_volume_set = set()
    if target_volume_name_text and target_volume_name_text.strip():
        for part in target_volume_name_text.split(","):
            p = part.strip()
            if p:
                target_volume_set.add(normalize_volume_keyword(p))
    if target_volume_set:
        log_print(f"目标刊期关键词:{sorted(target_volume_set)}")
    if not target_year_set and not target_volume_set:
        log_print("未填写年份和期刊，将下载全部年份全部期刊")

    raw_year_blocks = past_json.get("data", [])
    article_info_list = match_volume_rows(raw_year_blocks, target_year_set, target_volume_set)
    if not article_info_list:
        log_print(f"⚠️没有匹配到任何刊期，target_year={target_year}, volumes={target_volume_name_text}")
        years_avail = [yb.get("item_year") for yb in raw_year_blocks]
        log_print(f"   站点可用年份: {years_avail}")
        for yb in raw_year_blocks:
            if yb.get("item_year") in target_year_set:
                vols = [r.get("volume") for r in yb.get("item_list", [])]
                log_print(f"   {yb.get('item_year')} 年可用期刊: {vols}")
        return

    for item_info in article_info_list:
        check_stop()
        item_id = item_info.get("item_id")
        resource_id_item = item_info.get("resource_id")
        volume = item_info.get("volume", "")
        log_print(f"找到刊期 {volume} item_id={item_id}")
        # 修复目录名称：原版 volume_resource_id_item_id（文件名部分清洗非法字符）
        save_dir = os.path.join(
            save_root,
            sanitize_filename_part(keyword),
            f"{sanitize_filename_part(volume)}_{resource_id_item}_{item_id}",
        )
        os.makedirs(save_dir, exist_ok=True)
        p = 1
        all_img = []
        while True:
            check_stop()
            reader_ts = int(time.time() * 1000)
            if p == 1:
                reader_url = f"https://web.591adb.cn/magazine/reader/hngymyzyxy_{item_id}.html?&p={p}&_={reader_ts}"
                reader_text = client.get_text(reader_url)
            else:
                reader_url = (
                    f"https://web.591adb.cn/magazine/reader/hngymyzyxy_{item_id}.html?"
                    f"item_id={item_id}&uf=0&p={p}&_={reader_ts}"
                )
                reader_text = client.get_text(reader_url, headers=xml_headers)
            img_list = parse_reader_response(reader_text)
            break_flag = False
            # =====修复广告判断逻辑，还原原版逻辑=====
            for i in range(len(img_list) - 1, -1, -1):
                img_row = img_list[i]
                if "readerad_big.jpg" in img_row:
                    log_print(f"[INFO]p={p}有广告页，移除该图片")
                    del img_list[i]
                    break_flag = True
            if not img_list:
                # 未登录/被WAF拦截时接口同样返回200，但内容里没有图片列表。
                # 必须显式报错，否则会静默变成“无可用图片”，白白跳过整期还不提示原因
                if is_no_login_response(reader_text):
                    raise Exception(
                        "阅读器接口要求登录（返回「请登录后再做操作」），请确认保存的账号密码是否正确"
                    )
                if not reader_text:
                    log_print(f"⚠️p={p}阅读器接口无有效响应（可能被WAF拦截），响应为空")
                log_print(f"p={p}无更多图片，结束分页")
                break
            all_img.extend(img_list)
            log_print(f"  >p={p} 获取到图片:{img_list}")
            if break_flag:
                break
            # =====还原原版 p +=2，重点！！=====
            p += 2
            safe_sleep(0.8)
        log_print(f"共获取 {len(all_img)} 张图片")
        local_paths = []
        for idx, img_url in enumerate(all_img):
            check_stop()
            ext = img_url.split(".")[-1]
            save_file = os.path.join(save_dir, f"{idx+1:03d}.{ext}")
            ok = download_image(img_url, save_file, client)
            if ok:
                local_paths.append(save_file)
        # 每下载完1期图片，立即把该期结果yield出去，由上层马上转PDF
        yield {"volume": volume, "dir": save_dir, "images": local_paths}


# ===================== PDF水印与加密模块 =====================
def image_to_pdf_bytes(image_path: str) -> BytesIO:
    check_stop()
    # 用with确保图片文件句柄立即释放：Windows下未释放的句柄会让后续删除该图片失败(PermissionError)
    with Image.open(image_path) as im:
        img = im.convert("RGB")
    buf = BytesIO()
    img.save(buf, format="PDF")
    buf.seek(0)
    return buf


def scale_page_to_size(src_page, target_w: float, target_h: float):
    src_w = float(src_page.mediabox.width)
    src_h = float(src_page.mediabox.height)
    scale = min(target_w / src_w, target_h / src_h)
    scaled_w = src_w * scale
    scaled_h = src_h * scale
    tx = (target_w - scaled_w) / 2
    ty = (target_h - scaled_h) / 2
    transform = Transformation().scale(sx=scale, sy=scale).translate(tx=tx, ty=ty)
    new_page = PageObject.create_blank_page(width=target_w, height=target_h)
    new_page.merge_transformed_page(src_page, transform)
    return new_page


def parse_watermark_pages(text: str) -> list:
    """解析水印页码文本，如 '1,80' -> [1, 80]，去重排序；格式错误抛异常"""
    if not text or not text.strip():
        raise Exception("已选择水印文件，水印页码不能为空，多页用英文逗号分隔")
    pages = []
    for s in text.split(","):
        s = s.strip()
        if not s:
            continue
        if not s.isdigit() or int(s) < 1:
            raise Exception(f"水印页码格式错误:{s},请输入大于0的数字，多页英文逗号隔开")
        pages.append(int(s))
    if not pages:
        raise Exception("已选择水印文件，水印页码不能为空，多页用英文逗号分隔")
    return sorted(set(pages))


def sanitize_filename_part(name: str) -> str:
    """去除文件名/目录名中的非法字符，防止写入失败"""
    return re.sub(r'[\\/:*?"<>|\r\n\t]', "_", name).strip()


def cleanup_downloaded_images(image_paths: list, img_dir: str):
    """删除已生成PDF的下载图片；该期目录若已空则一并删除（PDF生成失败时不调用，保证图片保留可重试）"""
    failed = 0
    for p in image_paths:
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception as e:
            failed += 1
            log_print(f"⚠️删除失败 {p}: {e}")
    try:
        if img_dir and os.path.isdir(img_dir) and not os.listdir(img_dir):
            os.rmdir(img_dir)
    except Exception as e:
        log_print(f"⚠️删除空目录失败 {img_dir}: {e}")
    if failed:
        log_print(f"⚠️本期有{failed}个下载文件未能删除，请手动清理: {img_dir}")
    else:
        log_print(f"🗑️已删除本期下载文件: {img_dir}")


def build_pdf(
    image_paths: list,
    output_pdf: str,
    watermark_pdf_path: str = None,
    watermark_page_nums: list = None,
    owner_password: str = "",
):
    """
    :param image_paths: 图片路径列表
    :param output_pdf: 输出pdf路径
    :param watermark_pdf_path: 水印pdf文件（可选，不传则无水印）
    :param watermark_page_nums: 要插入水印的页码，从1开始，如[3,5]，在该页码前插入独立水印页（可选）
    :param owner_password: 修改权限密码（可选，不传则不加密）
    """
    check_stop()
    writer = PdfWriter()
    if not image_paths:
        raise Exception("没有图片可生成PDF")
    first_buf = image_to_pdf_bytes(image_paths[0])
    first_reader = PdfReader(first_buf)
    first_page = first_reader.pages[0]
    target_w = float(first_page.mediabox.width)
    target_h = float(first_page.mediabox.height)
    log_print(f"PDF页面尺寸 {target_w:.1f} x {target_h:.1f} pt")

    wm_reader = None
    if watermark_pdf_path:
        wm_reader = PdfReader(watermark_pdf_path)

    def new_wm_page():
        # 每次插入生成独立水印页，避免多个位置共享同一页面对象
        return scale_page_to_size(wm_reader.pages[0], target_w, target_h)

    watermark_page_nums = watermark_page_nums or []
    for idx, img_path in enumerate(image_paths):
        check_stop()
        current_page_num = idx + 1
        if current_page_num in watermark_page_nums:
            writer.add_page(new_wm_page())
            log_print(f"📝在第{current_page_num}页位置前面插入水印页")
        if idx == 0:
            writer.add_page(first_page)  # 复用第一张图片的转换结果
        else:
            buf = image_to_pdf_bytes(img_path)
            r = PdfReader(buf)
            writer.add_page(r.pages[0])

    # 处理末尾追加水印
    total_real = len(image_paths)
    for wm_p in watermark_page_nums:
        check_stop()
        if wm_p > total_real:
            writer.add_page(new_wm_page())
            log_print(f"📝在末尾追加水印页，原请求页码{wm_p}")

    if owner_password:
        writer.encrypt(
            user_password="",
            owner_password=owner_password,
            use_128bit=True,
            permissions_flag=0,  # 禁止修改/复制/打印，与参考脚本一致
        )
        log_print("🔒已设置修改权限密码（禁止修改/复制/打印）")
    try:
        with open(output_pdf, "wb") as f:
            writer.write(f)
        log_print(f"✅输出PDF完成 {output_pdf} 总页数{len(writer.pages)}")
    except OSError as e:
        log_print(f"❌写入PDF失败，文件可能被占用 {output_pdf} , error:{e}")
        raise


# ===================== 后台任务主逻辑 =====================
def background_task(
    chrome_path,
    phone,
    password,
    book_name,
    year_str,
    issue_str,
    watermark_file,
    watermark_pages_text,
    pdf_owner_pwd,
    save_result_dir,
    del_after_pdf=False,
):
    holder = None
    try:
        TASK_STOP_EVENT.clear()
        save_account(phone, password)
        log_print(f"🚀开始执行任务，数据目录:{DATA_DIR}")
        log_print("🚀开始执行任务，准备登录会话")
        session, holder, prefer_pw = get_valid_session(chrome_path, phone, password, book_name)
        log_print("✅获取Cookie完成，开始爬取杂志图片")

        # 处理水印文件与页码（提前校验，避免下完图片才发现参数错误）
        wm_page_list = []
        if watermark_file:
            if not os.path.exists(watermark_file):
                log_print(f"⚠️水印文件不存在，本次不插入水印: {watermark_file}")
                watermark_file = ""
            else:
                wm_page_list = parse_watermark_pages(watermark_pages_text)
                log_print(f"水印插入页码:{wm_page_list}")
        if not watermark_file:
            log_print("未选择水印文件，将生成无水印PDF")
        if del_after_pdf:
            log_print("已勾选「生成pdf后删除下载文件」：每期PDF生成成功后删除该期下载的图片")

        # 每下载完1期图片，立即生成该期PDF
        item_count = 0
        for item in crawl_magazine_images(
            session=session,
            pw_context=holder.context if holder is not None else None,
            prefer_pw=prefer_pw,
            keyword=book_name,
            target_year=year_str,
            target_volume_name_text=issue_str,
            save_root=save_result_dir,
        ):
            item_count += 1
            check_stop()
            img_paths = item["images"]
            vol_name = item["volume"]
            out_pdf = os.path.join(
                save_result_dir,
                f"{sanitize_filename_part(book_name)}_{sanitize_filename_part(vol_name)}.pdf",
            )
            if not img_paths:
                log_print(f"⚠️刊期 {vol_name} 无可用图片，跳过生成PDF")
                continue
            try:
                build_pdf(
                    image_paths=img_paths,
                    output_pdf=out_pdf,
                    watermark_pdf_path=watermark_file or None,
                    watermark_page_nums=wm_page_list,
                    owner_password=pdf_owner_pwd,
                )
                log_print(f"📄刊期 {vol_name} PDF已生成，继续下一期")
                if del_after_pdf:
                    cleanup_downloaded_images(img_paths, item.get("dir", ""))
            except Exception as e:
                log_print(f"❌生成PDF失败 {vol_name}: {e}")
                import traceback
                log_print(traceback.format_exc())

        if item_count == 0:
            log_print("本次没有需要处理的刊期，任务结束")
            return
        log_print("🎉全部任务执行完成！")
    except RuntimeError as e:
        if str(e) == "TaskStopped":
            log_print("\n🛑任务被用户停止")
        else:
            log_print(f"\n❌任务异常 {e}")
            import traceback
            log_print(traceback.format_exc())
    except Exception as e:
        import traceback
        log_print(f"\n❌任务异常 {e}")
        log_print(traceback.format_exc())
    finally:
        # 任务结束后释放浏览器（登录通道的浏览器在爬取期间保持打开，供WAF回退使用）
        if holder is not None:
            holder.close()


# ===================== GUI主界面 =====================
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("杂志PDF下载工具")
        self.root.geometry("980x840")
        self.root.minsize(880, 720)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.running = False
        self.worker = None
        self.accounts = load_accounts()
        self.last_cfg = load_last_config()
        self._setup_styles()

        # ===== 顶部标题 =====
        head = ttk.Frame(root, padding=(16, 14, 16, 4))
        head.pack(fill=tk.X)
        ttk.Label(head, text="📖 杂志PDF下载工具", style="Title.TLabel").pack(side=tk.LEFT)

        # ===== 任务配置 =====
        task_box = ttk.LabelFrame(root, text=" 任务配置 ", padding=12)
        task_box.pack(fill=tk.X, padx=16, pady=(8, 6))
        task_box.columnconfigure(1, weight=1)
        task_box.columnconfigure(4, weight=1)

        self.phone_var = tk.StringVar()
        self.cb_phone = ttk.Combobox(task_box, textvariable=self.phone_var, width=26)
        self.cb_phone["values"] = list(self.accounts.keys())
        self.cb_phone.bind("<<ComboboxSelected>>", self.on_account_select)
        self.pwd_var = tk.StringVar()
        self.ent_pwd = ttk.Entry(task_box, textvariable=self.pwd_var, width=26, show="*")
        ttk.Label(task_box, text="账号 *").grid(row=0, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        self.cb_phone.grid(row=0, column=1, sticky=tk.EW, padx=(0, 24), pady=4)
        ttk.Label(task_box, text="密码 *").grid(row=0, column=3, sticky=tk.E, padx=(0, 8), pady=4)
        self.ent_pwd.grid(row=0, column=4, sticky=tk.EW, pady=4)

        self.bookname_var = tk.StringVar()
        ent_book = ttk.Entry(task_box, textvariable=self.bookname_var, width=26)
        self.year_var = tk.StringVar()
        ent_year = ttk.Entry(task_box, textvariable=self.year_var, width=26)
        ttk.Label(task_box, text="书名 *").grid(row=1, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        ent_book.grid(row=1, column=1, sticky=tk.EW, padx=(0, 24), pady=4)
        ttk.Label(task_box, text="年份").grid(row=1, column=3, sticky=tk.E, padx=(0, 8), pady=4)
        ent_year.grid(row=1, column=4, sticky=tk.EW, pady=4)

        self.issue_var = tk.StringVar()
        ent_issue = ttk.Entry(task_box, textvariable=self.issue_var, width=26)
        self.save_dir_var = tk.StringVar()
        ent_save = ttk.Entry(task_box, textvariable=self.save_dir_var, width=26)
        btn_save = ttk.Button(task_box, text="选择目录", command=self.select_save_dir)
        ttk.Label(task_box, text="期刊").grid(row=2, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        ent_issue.grid(row=2, column=1, sticky=tk.EW, padx=(0, 24), pady=4)
        ttk.Label(task_box, text="保存目录 *").grid(row=2, column=3, sticky=tk.E, padx=(0, 8), pady=4)
        ent_save.grid(row=2, column=4, sticky=tk.EW, padx=(0, 6), pady=4)
        btn_save.grid(row=2, column=5, pady=4)

        # ===== PDF 设置 =====
        pdf_box = ttk.LabelFrame(root, text=" PDF 设置（选填） ", padding=12)
        pdf_box.pack(fill=tk.X, padx=16, pady=6)
        pdf_box.columnconfigure(1, weight=1)
        pdf_box.columnconfigure(4, weight=1)

        self.watermark_file_var = tk.StringVar()
        ent_wm = ttk.Entry(pdf_box, textvariable=self.watermark_file_var, width=26)
        btn_wm = ttk.Button(pdf_box, text="选择文件", command=self.select_watermark_file)
        self.watermark_page_var = tk.StringVar()
        ent_wm_page = ttk.Entry(pdf_box, textvariable=self.watermark_page_var, width=26)
        ttk.Label(pdf_box, text="水印PDF文件").grid(row=0, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        ent_wm.grid(row=0, column=1, sticky=tk.EW, padx=(0, 6), pady=4)
        btn_wm.grid(row=0, column=2, padx=(0, 24), pady=4)
        ttk.Label(pdf_box, text="水印页码").grid(row=0, column=3, sticky=tk.E, padx=(0, 8), pady=4)
        ent_wm_page.grid(row=0, column=4, sticky=tk.EW, pady=4)

        self.pdf_pwd_var = tk.StringVar()
        ent_pdf_pwd = ttk.Entry(pdf_box, textvariable=self.pdf_pwd_var, width=26, show="*")
        self.chrome_path_var = tk.StringVar()
        ent_chrome = ttk.Entry(pdf_box, textvariable=self.chrome_path_var, width=26)
        btn_chrome = ttk.Button(pdf_box, text="选择Chrome", command=self.select_chrome)
        ttk.Label(pdf_box, text="权限密码").grid(row=1, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        ent_pdf_pwd.grid(row=1, column=1, sticky=tk.EW, padx=(0, 24), pady=4)
        ttk.Label(pdf_box, text="Chrome路径").grid(row=1, column=3, sticky=tk.E, padx=(0, 8), pady=4)
        ent_chrome.grid(row=1, column=4, sticky=tk.EW, padx=(0, 6), pady=4)
        btn_chrome.grid(row=1, column=5, pady=4)

        self.del_after_pdf_var = tk.BooleanVar(value=False)
        chk_del_after_pdf = ttk.Checkbutton(
            pdf_box, text="生成pdf后删除下载文件", variable=self.del_after_pdf_var
        )
        chk_del_after_pdf.grid(row=2, column=0, columnspan=6, sticky=tk.W, pady=(6, 2))

        # ===== 操作按钮 =====
        btn_frame = ttk.Frame(root, padding=(16, 10))
        btn_frame.pack(fill=tk.X)
        self.btn_start = ttk.Button(btn_frame, text="🚀 开始执行", command=self.start_task, width=16)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))
        self.btn_stop = ttk.Button(btn_frame, text="⏹ 停止", command=self.stop_task, state=tk.DISABLED, width=12)
        self.btn_stop.pack(side=tk.LEFT)

        # ===== 运行日志 =====
        log_head = ttk.Frame(root, padding=(16, 6, 16, 0))
        log_head.pack(fill=tk.X)
        ttk.Label(log_head, text="运行日志", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(log_head, text="清空日志", command=self.clear_log).pack(side=tk.RIGHT)
        self.log_text = scrolledtext.ScrolledText(root, height=24, wrap=tk.WORD, font=("Menlo", 11))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 14))

        self.restore_last_config()
        self.consume_log()

    def _setup_styles(self):
        style = ttk.Style()
        style.configure("Title.TLabel", font=("PingFang SC", 20, "bold"))
        style.configure("Section.TLabel", font=("PingFang SC", 13, "bold"))
        style.configure("Hint.TLabel", foreground="#8a8a8a", font=("PingFang SC", 10))

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def set_ui_running_state(self, is_running: bool):
        """只能主线程调用，更新按钮状态"""
        self.running = is_running
        if is_running:
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
        else:
            self.btn_start.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)

    def restore_last_config(self):
        cfg = self.last_cfg
        self.chrome_path_var.set(cfg.get("chrome_path", ""))
        self.save_dir_var.set(cfg.get("save_dir", ""))
        self.bookname_var.set(cfg.get("book_name", ""))
        self.year_var.set(cfg.get("year", ""))
        self.issue_var.set(cfg.get("issue", ""))
        self.watermark_file_var.set(cfg.get("watermark_file", ""))
        self.watermark_page_var.set(cfg.get("watermark_pages", ""))
        self.pdf_pwd_var.set(cfg.get("pdf_pwd", ""))
        self.del_after_pdf_var.set(bool(cfg.get("del_after_pdf", False)))

    def save_current_ui_config(self):
        cfg = {
            "chrome_path": self.chrome_path_var.get(),
            "save_dir": self.save_dir_var.get(),
            "book_name": self.bookname_var.get(),
            "year": self.year_var.get(),
            "issue": self.issue_var.get(),
            "watermark_file": self.watermark_file_var.get(),
            "watermark_pages": self.watermark_page_var.get(),
            "pdf_pwd": self.pdf_pwd_var.get(),
            "del_after_pdf": self.del_after_pdf_var.get(),
        }
        save_last_config(cfg)

    def on_account_select(self, event):
        acc = self.phone_var.get().strip()
        pwd = self.accounts.get(acc, "")
        self.pwd_var.set(pwd)

    def _initial_dir(self, path_value: str, fallback: str = "~") -> str:
        """从已填路径取初始目录（不存在则用fallback），兼容mac/win"""
        if path_value:
            d = os.path.dirname(path_value)
            if d and os.path.isdir(d):
                return d
        fb = os.path.expanduser(fallback)
        return fb if os.path.isdir(fb) else os.path.expanduser("~")

    def select_watermark_file(self):
        self.root.lift()  # 把主窗口提到前台，避免mac上对话框藏在后面
        fp = filedialog.askopenfilename(
            parent=self.root,
            title="选择水印PDF",
            initialdir=self._initial_dir(self.watermark_file_var.get()),
            filetypes=[("PDF文件", "*.pdf"), ("所有文件", "*.*")]
        )
        if fp:
            self.watermark_file_var.set(fp)

    def select_save_dir(self):
        self.root.lift()
        d = filedialog.askdirectory(
            parent=self.root,
            title="选择结果保存目录",
            initialdir=self._initial_dir(self.save_dir_var.get()),
        )
        if d:
            self.save_dir_var.set(d)

    def select_chrome(self):
        self.root.lift()
        if sys.platform == "win32":
            fp = filedialog.askopenfilename(
                parent=self.root,
                title="选择chrome.exe",
                initialdir=self._initial_dir(
                    self.chrome_path_var.get(), r"C:\Program Files\Google\Chrome\Application"
                ),
                filetypes=[("Chrome", "chrome.exe"), ("所有文件", "*.*")]
            )
        else:
            fp = filedialog.askopenfilename(
                parent=self.root,
                title="选择Chrome可执行程序",
                initialdir=self._initial_dir(self.chrome_path_var.get(), "/Applications"),
            )
        if fp:
            self.chrome_path_var.set(fp)

    def consume_log(self):
        try:
            while True:
                msg = LOG_QUEUE.get_nowait()
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
        except Empty:
            pass
        self.root.after(50, self.consume_log)

    def _worker_done_callback(self):
        """子线程结束后通过after调度到主线程更新UI"""
        self.root.after(0, lambda: self.set_ui_running_state(False))

    def start_task(self):
        if self.running:
            return
        phone = self.phone_var.get().strip()
        pwd = self.pwd_var.get().strip()
        book = self.bookname_var.get().strip()
        save_dir = self.save_dir_var.get().strip()
        wm_file = self.watermark_file_var.get().strip()
        wm_pages = self.watermark_page_var.get().strip()
        del_after_pdf = self.del_after_pdf_var.get()

        if not phone:
            messagebox.showerror("校验错误", "账号(手机号)不能为空")
            return
        if not pwd:
            messagebox.showerror("校验错误", "密码不能为空")
            return
        if not book:
            messagebox.showerror("校验错误", "书名不能为空")
            return
        if not save_dir:
            messagebox.showerror("校验错误", "结果保存目录不能为空")
            return
        # 水印文件不存在的情况不再硬拦，交给后台任务警告并降级为无水印PDF
        if wm_file:
            if not wm_pages:
                messagebox.showerror("校验错误", "已选择水印文件，水印页码不能为空")
                return
        else:
            if wm_pages:
                messagebox.showerror("校验错误", "未选择水印文件，不允许填写水印页码")
                return
        chrome_path = self.chrome_path_var.get().strip()
        if chrome_path and not os.path.exists(chrome_path):
            if not resolve_chrome_path(""):
                messagebox.showerror("校验错误", "指定的Chrome路径不存在，且未找到系统Chrome，请重新选择")
                return
            # 能找到系统默认Chrome：后台自动使用，并在日志中说明

        self.save_current_ui_config()
        self.set_ui_running_state(True)
        TASK_STOP_EVENT.clear()

        def work_wrapper():
            background_task(
                self.chrome_path_var.get().strip(),
                phone,
                pwd,
                book,
                self.year_var.get().strip(),
                self.issue_var.get().strip(),
                wm_file,
                wm_pages,
                self.pdf_pwd_var.get().strip(),
                save_dir,
                del_after_pdf,
            )
            self._worker_done_callback()

        self.worker = threading.Thread(target=work_wrapper, daemon=True)
        self.worker.start()

    def stop_task(self):
        TASK_STOP_EVENT.set()
        log_print("🛑发送停止信号")

    def on_close(self):
        TASK_STOP_EVENT.set()
        if self.running and self.worker is not None:
            log_print("等待后台任务退出...")
            self.root.after(500, self.root.destroy)
        else:
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
