"""main_v2.py —— 杂志PDF下载工具（v2：requests优先 + 浏览器通道兜底）

与 v1(main.py) 的差别：
1. 界面去掉「书名」输入框，改为粘贴「采集地址」，例如
   https://web.591adb.cn/magazine/detail/hngymyzyxy_1031982.html?_=1792144681
   程序从地址里取出站点id，请求一次缩略图接口换成 magazine_id，再用它取往期列表。
2. 界面只认粘贴进来的那一条 cookie（浏览器里复制整串粘进来），不登录。
   接口请求优先用 requests 直连；但站点WAF会拦requests并返回HTML挑战页
   （2026-10-18 实测：cookie 再新也一样），被拦时自动启动可见Chrome、
   注入这份cookie，之后所有接口请求都改由页面自己发XHR（与 v1 相同的过WAF方式）。
   会话被服务端提前失效时接口会返回「请登录」，程序会提示重新复制一份cookie。
3. 图片获取方式和 v1(main.py) 完全一致：调阅读器(reader)接口并带 uf=0，
   p=1,3,5… 每次+2，接口直接返回整页原图的地址(data.image_list)，
   逐张下载即可，不再下载瓦片拼页。
4. 下载图片、转PDF、水印、加密、删源文件等沿用 v1 的做法。
"""
import json
import os
import sys
import time
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from queue import Queue, Empty
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
from PIL import Image
from pypdf import PdfReader, PdfWriter, Transformation, PageObject
from playwright.sync_api import sync_playwright

# ===================== 全局配置与存储路径 =====================
def get_data_dir() -> str:
    """数据文件(cookie/账号/配置/日志)存放目录：
    优先用可执行文件所在目录（便携式）；不可写则回退到系统用户数据目录，兼容mac/win。
    环境变量 MAG_DATA_DIR 可强制指定——跑自测脚本时用它指向临时目录，
    免得测试把用户真实的 cookie/账号/配置/日志冲掉"""
    override = os.environ.get("MAG_DATA_DIR")
    if override:
        os.makedirs(override, exist_ok=True)
        return override
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
CONFIG_STORE = os.path.join(DATA_DIR, "mag_config_store.json")
LOG_FILE = os.path.join(DATA_DIR, "mag_run.log")
TASK_STOP_EVENT = threading.Event()
LOG_QUEUE = Queue()  # 无maxsize，put_nowait不会阻塞后台线程
# 接口限速：站点按请求量限流——2026-10-08 实测 0.1秒连发46个、2026-10-16 实测
# 50秒内约40个（≈48次/分）都会被WAF拦成 403/挑战页，且要等十几分钟才恢复。
# 不再每次请求后固定sleep，改用令牌桶：允许小突发，长期平均不超过 API_RATE_PER_MIN。
# 15次/分是实测安全值；想更快可以调大（如30），被拦后程序会自动降速。
# 图片在CDN(pic.591adb.cn)，和接口限速分开算，可以并发下载。
API_RATE_PER_MIN = 15.0  # 接口平均速率（次/分）
API_BURST = 3            # 令牌桶允许的短时突发请求数
API_BLOCK_COOLDOWN = 60  # 被WAF拦后至少冷却多少秒再发下一个接口请求
IMAGE_WORKERS = 4        # 整页原图并发下载数（CDN，不受接口限速约束）
MAX_THUMB_RETRY = 2  # 接口没拿到有效响应时，同一页最多再重试几次
READER_PAGE_STEP = 2  # 阅读器接口一次给2页，p每次加2（站点前端就是这么翻的）
MAX_READER_CALLS = 600  # 单期最多请求阅读器接口多少次（120页约60次，留足余量）
READER_BLOCK_WAIT = 90   # 疑似被限流（403）时等多久再试同一页
MAX_READER_BLOCK_RETRY = 3  # 被限流最多这样等几次，还是不行就按已收集到的继续
# 站点「翻到头」的表现（2026-10-16 实测确认）：
#   缩略图接口——合法JSON，但重复给一遍最后一页的图片
#   阅读器接口——同样重复给已经收集过的页
# 所以收尾逻辑就是「按文件名去重，接口返回的图片与已有页相同就结束」，不需要猜。


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


class TaskStopped(RuntimeError):
    """用户点了「停止」。所有 except Exception 都必须把它放行，
    否则会被当成普通错误吞掉——比如显示成“下载失败”并继续重试等待"""


def check_stop():
    if TASK_STOP_EVENT.is_set():
        raise TaskStopped("TaskStopped")


def safe_sleep(sec: float):
    if TASK_STOP_EVENT.wait(timeout=sec):
        raise TaskStopped("TaskStopped")


class RateLimiter:
    """令牌桶限速：允许短时突发，长期平均不超过 rate_per_min。
    请求不再固定sleep——桶里有令牌就立即发，没有才等到下一个令牌。
    被站点拦下时 penalize() 自动降速，连续成功后再慢慢恢复到配置的速率。"""

    def __init__(self, rate_per_min: float, burst: int = 3):
        self.base_rate = max(float(rate_per_min), 1.0) / 60.0  # 每秒令牌数
        self.rate = self.base_rate
        self.capacity = max(1, int(burst))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self.blocked_until = 0.0
        self.successes = 0
        self.lock = threading.Lock()

    def _refill(self, now: float):
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now

    def acquire(self):
        """取一个令牌；桶空或处于被拦冷却期时等待。用户点停止会抛 TaskStopped"""
        while True:
            with self.lock:
                now = time.monotonic()
                wait = self.blocked_until - now
                if wait <= 0:
                    self._refill(now)
                    if self.tokens >= 1.0:
                        self.tokens -= 1.0
                        return
                    wait = (1.0 - self.tokens) / max(self.rate, 1e-6)
            safe_sleep(wait)

    def penalize(self):
        """被站点真正限流（浏览器通道也被拦）：降速+清空令牌+冷却，避免继续撞墙。
        只降一半（有下限），连续成功后再恢复，避免一次误判把整期拖慢"""
        with self.lock:
            self.rate = max(self.rate * 0.5, self.base_rate * 0.5)
            self.tokens = 0.0
            self.updated = time.monotonic()
            self.blocked_until = self.updated + API_BLOCK_COOLDOWN
            self.successes = 0
            now_rate = self.rate * 60
        log_print(f"⚠️接口被限流，自动降速到 {now_rate:.1f} 次/分（基准 {self.base_rate * 60:.0f}）")

    def reward(self):
        """持续成功一段时间后小幅恢复，最多回到配置的基准速率"""
        with self.lock:
            self.successes += 1
            if self.successes >= 10 and self.rate < self.base_rate:
                self.rate = min(self.base_rate, self.rate * 1.5)
                self.successes = 0


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


# ===================== 界面粘贴的Cookie解析（v2新增） =====================
def dedupe_cookies(cookies: list) -> list:
    """同名cookie只留最后一个：浏览器里复制的整串cookie，同名以最后一个为准"""
    merged = {}
    for ck in cookies:
        merged[ck["name"]] = ck
    return list(merged.values())


def parse_cookie_input(text: str) -> list:
    """把界面粘贴的cookie文本解析成 [{"name","value","domain","path"}, ...]。
    支持三种写法：
      1. 浏览器devtools里复制的整条cookie字符串："a=b; c=d"（可带 Cookie: 前缀、可跨行）
      2. 本工具保存的 mag_cookies.json 格式（JSON数组，元素带name/value/domain/path）
      3. 包了一层的 {"cookies": [...]}
    ⚠️值一律原样保留：像 hngymyzyxy_info 的值里带 %2F、%3D%3D，站点认的就是这串原文，
    一旦解码反而登录不上。"""
    text = (text or "").strip()
    if not text:
        return []
    if text[0] in "[{":
        data = None
        try:
            data = json.loads(text)
        except Exception:
            data = None  # 不是JSON就当普通cookie字符串继续往下解析
        if isinstance(data, dict) and isinstance(data.get("cookies"), list):
            data = data["cookies"]
        if isinstance(data, list):
            out = []
            for ck in data:
                if isinstance(ck, dict) and str(ck.get("name") or "").strip():
                    out.append({
                        "name": str(ck["name"]).strip(),
                        "value": str(ck.get("value") or ""),
                        "domain": str(ck.get("domain") or "").lstrip("."),
                        "path": ck.get("path") or "/",
                    })
            if out:
                return dedupe_cookies(out)
    raw = text
    if raw.lower().startswith("cookie:"):
        raw = raw.split(":", 1)[1]
    # 换行也当分隔符：用户从devtools复制时常常是折行的
    raw = raw.replace("\r\n", ";").replace("\n", ";").replace("\r", ";")
    out = []
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if not name:
            continue
        out.append({"name": name, "value": value.strip(), "domain": "", "path": "/"})
    return dedupe_cookies(out)


def describe_cookies(cookies: list) -> str:
    """日志里只说数量和cookie名，不打印cookie值（值里带登录凭证，别写进日志文件）"""
    names = [c["name"] for c in cookies]
    shown = "、".join(names[:8]) + ("..." if len(names) > 8 else "")
    has_login = "有" if has_login_cookie(cookies) else "无"
    return f"{len(cookies)}个（{shown}；登录cookie {SiteConfig.LOGIN_COOKIE_NAME}:{has_login}）"

# ===================== 站点配置 =====================
class SiteConfig:
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    )
    VIEWPORT = {"width": 1920, "height": 1080}
    HOME_URL = "https://web.591adb.cn/hngymyzyxy.html"
    LOGIN_COOKIE_NAME = "hngymyzyxy_info"  # 登录会话cookie名，用来判断粘贴的cookie里有没有登录态
    REQ_HEADERS = {
        "User-Agent": USER_AGENT,
        "Referer": "https://web.591adb.cn/",
    }
    # 缩略图接口——一次返回18页的缩略图，p从1开始递增（用来拿总页数和页面清单）
    THUMBLIST_URL_TMPL = (
        "https://web.591adb.cn/magazine/thumblist/hngymyzyxy_{item_id}.html?p={p}&_={ts}"
    )
    # 阅读器接口——一次返回2页的**整页原图**地址，p从1开始每次+2。
    # 与 v1(main.py) 一致走 uf=0：image_list 里一页就是一张整图，不用再拼瓦片。
    # ⚠️p=1 与 p>1 的URL参数不同，站点前端就是这么发的，照抄才不会被打回（见 reader_url）
    READER_URL_TMPL = (
        "https://web.591adb.cn/magazine/reader/hngymyzyxy_{item_id}.html"
        "?item_id={item_id}&uf={uf}&p={p}&_={ts}"
    )
    READER_URL_P1_TMPL = (
        "https://web.591adb.cn/magazine/reader/hngymyzyxy_{item_id}.html?&p={p}&_={ts}"
    )
    READER_UF = 0
    # 往期（刊期）列表接口，要的是 magazine_id
    PAST_URL_TMPL = "https://web.591adb.cn/magazine/past/hngymyzyxy_{magazine_id}.html?_={ts}"


def build_session_from_cookies(cookies: list) -> requests.Session:
    """把cookie列表注入requests.Session"""
    session = requests.Session()
    session.headers.update(SiteConfig.REQ_HEADERS)
    for ck in cookies:
        session.cookies.set(ck["name"], ck["value"], domain=ck.get("domain"), path=ck.get("path"))
    return session


def has_login_cookie(cookies: list) -> bool:
    """本地cookie里是否存在登录cookie；没有就说明是匿名会话，必须走登录"""
    return any(c.get("name") == SiteConfig.LOGIN_COOKIE_NAME for c in cookies)


NO_LOGIN_MARKERS = ("请登录后再做操作", '"no_login"')
# 站点会在服务端提前让会话失效（cookie的过期时间还没到就已经不认了），
# 这时接口返回「请登录后再做操作」。没有浏览器就没法就地重登，只能让用户重新粘贴cookie
COOKIE_EXPIRED_MSG = (
    "接口要求登录（返回「请登录后再做操作」）：粘贴的Cookie已经失效了。"
    "请到浏览器里重新登录网站，复制一份新的cookie粘到界面上再跑"
)


# 登录页特征：站点会话失效时，接口会被重定向到登录页（HTTP 200 + HTML），
# 而不是返回 JSON。必须认出来，否则会被误报成「被WAF拦截」，让用户白等半小时
LOGIN_PAGE_MARKERS = ('id="phone_number"', "phone_pwd", "phone_login_btn", "captcha_container")


def looks_like_login_html(text: str) -> bool:
    s = text or ""
    return any(m in s for m in LOGIN_PAGE_MARKERS)


def html_title(text: str) -> str:
    """取HTML标题，只用于日志诊断"""
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""


def blocked_hint(text: str) -> str:
    """接口没返回JSON时补一句人能看懂的说明。
    2026-10-18 实测：登录失效时站点会把接口请求跳到登录页（200 + HTML），
    与「请求太密被WAF拦（403 + 访问被拦截）」要分开说，否则用户不知道该重登还是该等"""
    s = text or ""
    if looks_like_login_html(s):
        return ("（接口返回的是登录页，说明粘贴的Cookie已经失效："
                "请到浏览器重新登录网站，复制一份新的完整cookie粘到界面上再跑）")
    if "访问被拦截" in s or "403" in s or "<html" in s[:200].lower():
        return ("（接口返回的是网页而不是JSON：可能是Cookie失效被跳到了登录页，"
                "也可能是站点安全检测拦截。请先重新登录并复制新cookie；若刚复制过，"
                "等10~30分钟再试，期间别反复重跑——越试恢复越慢）")
    return ""


def is_no_login_response(text: str) -> bool:
    """站点改版后：reader等正文接口未登录时返回
    {"code":0,"msg":"请登录后再做操作","data":{"no_login":1}}，HTTP状态仍是200"""
    if not text:
        return False
    return any(m in text for m in NO_LOGIN_MARKERS)


# ===================== 浏览器通道（requests被WAF拦下时自动启用） =====================
# 2026-10-18 实测：站点WAF对纯requests直连返回的是 200 + HTML 的挑战页
# （约14KB，含 TTGCaptcha / waf-captcha-proxy / window.location.reload），
# cookie刚登录也一样过不去；只有浏览器页面自己发出的XHR才放行。
# 以下逻辑与 v1(main.py) 一致：可见Chrome + 页面内XHR，共用同一个浏览器过WAF。
WAF_CAPTCHA_SELECTOR = (
    "#vc_captcha_box, .vc_captcha_box_theme, #captcha_container, .captcha_verify_bar--title"
)
WAF_TEXT_MARKERS = ("安全检测", "TTGCaptcha", "waf-captcha-proxy")
WAF_MAX_CHALLENGES = 3  # 单次任务最多配合几次滑块，超过就停，避免越滑越弹
_waf_challenge_count = 0


class WafChallengeLimit(RuntimeError):
    """站点安全检测反复出现（滑完又弹）时的终止信号"""


def reset_waf_challenge_count():
    global _waf_challenge_count
    _waf_challenge_count = 0


def note_waf_challenge():
    global _waf_challenge_count
    _waf_challenge_count += 1
    if _waf_challenge_count > WAF_MAX_CHALLENGES:
        raise WafChallengeLimit(
            f"站点安全检测已连续出现{WAF_MAX_CHALLENGES}次，每次跳转都会重新弹出滑块验证。"
            "继续重试只会一直弹验证码，程序已停止。"
            "建议：关闭程序与浏览器窗口，等待10~30分钟后再试；期间不要反复启动，越试越容易被盯上"
        )


def is_waf_challenge(page, strict: bool = False) -> bool:
    """当前页面是否为站点前置的WAF安全检测页。
    读不到页面（正在跳转/被abort）时按“尚未就绪”处理，让调用方继续等；
    strict=True 时读不到就返回False，避免把跳转中的空白页误记成一次滑块"""
    try:
        if page.locator(WAF_CAPTCHA_SELECTOR).count() > 0:
            return True
        html = page.content()
    except Exception:
        return not strict
    return any(m in html for m in WAF_TEXT_MARKERS)


def is_page_ready(page) -> bool:
    """页面是否已真正加载出内容。
    WAF检测页通过后 successCb 会 location.reload()，reload 过渡期 DOM 为空，
    此时不能判成“检测已通过”，否则会在页面还没出来时就发请求，陷入空转"""
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
    """等待页面真正就绪：WAF检测页、以及检测通过后的reload过渡期都算“未就绪”。
    检测到滑块时提示用户在浏览器窗口手动完成，程序只等待，不做任何自动绕过"""
    deadline = time.time() + timeout
    notified = False
    while time.time() < deadline:
        check_stop()
        if is_page_ready(page):
            if notified:
                log_print("✅站点安全检测已通过，页面已加载完成")
            return True
        if not notified and is_waf_challenge(page, strict=True):
            note_waf_challenge()
            log_print(
                f"⚠️站点安全检测（火山引擎WAF）拦截：请在已打开的浏览器窗口手动完成滑块验证，"
                f"程序会自动等待（第{_waf_challenge_count}/{WAF_MAX_CHALLENGES}次）"
            )
            notified = True
        safe_sleep(1)
    log_print(f"⚠️等待页面加载就绪超时（{timeout}秒）")
    return False


def wait_page_settled(page, extra_sec: float = 3.0):
    """等页面自身JS和异步请求跑完再发接口请求——WAF通行凭证是页面里的JS种下的"""
    try:
        page.wait_for_load_state("networkidle", timeout=8000)
    except Exception:
        pass  # 站点有长轮询时永远等不到networkidle，兜底靠下面的固定等待
    safe_sleep(extra_sec)


def goto_quiet(page, url) -> bool:
    """跳转并吞掉异常：WAF检测页 successCb 里的 location.reload() 会和goto抢导航，
    产生 ERR_ABORTED，属正常竞态，不该中断流程"""
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        return True
    except Exception as e:
        log_print(f"⚠️跳转 {url} 异常:{e}")
        return False


# 用 XMLHttpRequest 而不是 fetch：站点WAF被惹到时会把XHR吊住不放（页面里弹滑块慢慢等），
# fetch 的 AbortController 会被站点脚本劫持、超时形同虚设；xhr.timeout 是浏览器原生超时
_FETCH_IN_PAGE_JS = """({url, headers, timeout}) => {
    return new Promise((resolve) => {
        const x = new XMLHttpRequest();
        let done = false;
        const finish = (o) => { if (!done) { done = true; resolve(o); } };
        try {
            x.open('GET', url, true);
            x.timeout = timeout;
            x.withCredentials = true;
            for (const k of Object.keys(headers || {})) {
                try { x.setRequestHeader(k, headers[k]); } catch (e) {}
            }
            x.onload = () => finish({status: x.status, body: x.responseText || ''});
            x.onerror = () => finish({status: 0, body: '网络错误'});
            x.ontimeout = () => finish({status: 0, body: '请求超时'});
            x.onabort = () => finish({status: 0, body: '请求被中止'});
            x.send();
        } catch (e) {
            finish({status: 0, body: String(e)});
        }
    });
}"""


def fetch_text_in_page(page, url: str, headers: dict = None, timeout: float = 30):
    """用页面自身的网络栈发接口请求，返回(status, 响应文本)。
    站点WAF会拒掉驱动进程发出的请求，只有页面自己发的才放行"""
    try:
        res = page.evaluate(
            _FETCH_IN_PAGE_JS,
            {"url": url, "headers": headers or {}, "timeout": int(timeout * 1000)},
        )
    except Exception as e:
        return 0, f"页面内请求异常: {e}"
    return int(res.get("status") or 0), res.get("body") or ""


class BrowserHolder:
    """保持浏览器在爬取期间存活；用完必须close()。按需启动，不启动就不占资源"""

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.work_page = None

    def close(self):
        for obj in (self.work_page, self.context, self.browser):
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


def resolve_chrome_path(chrome_exe_path: str = "") -> str:
    """解析可用的Chrome路径：优先用户指定的；无效时尝试系统常见安装路径（mac/win）"""
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


def inject_cookies(context, cookies: list):
    """把界面粘贴的cookie注入浏览器context。
    粘贴来的cookie没有domain，统一按站点主机注入；已过客户端有效期的往后续一天，
    让cookie照常发出去，由服务端决定认不认"""
    if not cookies:
        return
    now = time.time()
    revived = 0
    pw_cookies = []
    for ck in cookies:
        item = {
            "name": ck["name"],
            "value": ck["value"],
            "domain": (ck.get("domain") or "web.591adb.cn").lstrip("."),
            "path": ck.get("path") or "/",
        }
        exp = ck.get("expires")
        try:
            exp = float(exp)
            if exp > 0:
                if exp <= now:
                    exp = now + 86400
                    revived += 1
                item["expires"] = int(exp)
        except (TypeError, ValueError):
            pass
        pw_cookies.append(item)
    context.add_cookies(pw_cookies)
    if revived:
        log_print(f"⚠️有{revived}个cookie已过客户端有效期，仍按原值发送（服务端可能已让会话失效）")


def ensure_browser(holder: "BrowserHolder", cookies: list) -> bool:
    """按需启动可见Chrome并注入cookie；失败抛异常，由调用方决定是否继续用requests"""
    if holder is None:
        return False
    if holder.context is not None:
        return True
    log_print("🌐requests被站点WAF拦下，正在启动浏览器通道（窗口里若弹滑块请手动滑一下）")
    try:
        holder.playwright = sync_playwright().start()
        launch_opt = {"headless": False}
        resolved = resolve_chrome_path("")
        if resolved:
            launch_opt["executable_path"] = resolved
            log_print(f"✅使用Chrome: {resolved}")
        else:
            launch_opt["channel"] = "chrome"
        holder.browser = holder.playwright.chromium.launch(**launch_opt)
        holder.context = holder.browser.new_context(
            viewport=SiteConfig.VIEWPORT, user_agent=SiteConfig.USER_AGENT
        )
        inject_cookies(holder.context, cookies or [])
        return True
    except Exception:
        holder.close()
        raise


def ensure_work_page(holder):
    """取（或创建）一个停在站点首页的常驻页面，所有接口请求都由这个页面自己发。
    能复用就复用：重开页面=再跳转一次=站点可能再弹一次滑块"""
    if holder is None or holder.context is None:
        return None
    page = getattr(holder, "work_page", None)
    if page is not None:
        try:
            if not page.is_closed():
                return page
        except Exception:
            pass
    try:
        page = holder.context.new_page()
        holder.work_page = page
        goto_quiet(page, SiteConfig.HOME_URL)
        if not wait_page_ready(page):
            log_print("⚠️接口请求页面未能就绪，接口可能仍然失败")
        wait_page_settled(page)
        return page
    except WafChallengeLimit:
        raise
    except Exception as e:
        log_print(f"⚠️创建接口请求页面失败: {e}")
        return None


class ApiClient:
    """接口请求封装：优先requests直连；被WAF拦下时自动切到浏览器页面，由页面自己发XHR。
    2026-10-18 实测：即使cookie是刚登录的，requests直连仍会拿到 200 + HTML 的WAF挑战页，
    必须靠可见浏览器过一次检测后才能拿到JSON"""

    def __init__(
        self, session: requests.Session = None,
        holder: "BrowserHolder" = None, cookies: list = None,
        limiter: "RateLimiter" = None,
    ):
        self.session = session
        self.holder = holder
        self.cookies = cookies or []
        self.limiter = limiter or RateLimiter(API_RATE_PER_MIN, API_BURST)
        self.pw_page = None
        self._scratch_page = None  # 跨域图片下载用的备用页面（导航取字节，不受CORS限制）
        self._tls = threading.local()  # 图片并发下载时每个线程用自己的Session

    @staticmethod
    def _looks_blocked(ct: str, body: str) -> bool:
        """响应是不是被站点安全检测拦了：站点被拦时给的是HTML检测页，
        正常接口一律返回JSON。所以「Content-Type不是JSON、正文也不像JSON」就按被拦处理"""
        if "json" in (ct or "").lower():
            return False
        return not (body or "").lstrip().startswith(("{", "["))

    def _switch_to_pw(self) -> bool:
        """切到浏览器通道；没有可用的浏览器就继续留在requests上重试"""
        if self.pw_page is not None:
            return True
        try:
            if not ensure_browser(self.holder, self.cookies):
                return False
            page = ensure_work_page(self.holder)
            if page is None:
                return False
        except WafChallengeLimit:
            raise
        except Exception as e:
            log_print(f"⚠️启动浏览器通道失败: {e}")
            return False
        self.pw_page = page
        log_print("✅已切换浏览器通道：接口请求改由页面自己发出")
        return True

    def _scratch(self):
        """取一个用于下载的备用页面：跨域图片没法用页面内fetch（CORS读不到body），
        但让浏览器自己导航过去取字节不受CORS限制"""
        try:
            if self._scratch_page is not None and not self._scratch_page.is_closed():
                return self._scratch_page
        except Exception:
            pass
        if self.holder is None or self.holder.context is None:
            return None
        try:
            self._scratch_page = self.holder.context.new_page()
            return self._scratch_page
        except Exception as e:
            log_print(f"⚠️创建下载页面失败: {e}")
            return None

    def get_text(self, url, headers=None, timeout=30, retries=2) -> str:
        """对外统一入口：请求频率由 limiter 的令牌桶控制，不再每次固定sleep"""
        return self.get_text_status(url, headers, timeout, retries)[1]

    def get_text_status(self, url, headers=None, timeout=30, retries=2):
        """同 get_text，但同时返回HTTP状态码。
        缩略图接口翻页要用它区分「站点正常回答但没有更多图片」和「请求被拦/出错」。
        请求频率由 self.limiter 的令牌桶控制，不再每次固定sleep"""
        return self._request_text_ex(url, headers, timeout, retries)

    def _request_text_ex(self, url, headers=None, timeout=30, retries=2):
        status = 0
        for attempt in range(retries + 1):
            check_stop()
            self.limiter.acquire()  # 限速在令牌桶里做，不再每次请求后固定sleep
            # 已切到浏览器通道：所有请求都由常驻页面自己发，不再走requests
            if self.pw_page is not None:
                status, body = fetch_text_in_page(self.pw_page, url, headers, timeout)
                if status == 200 and body.strip() and not self._looks_blocked("", body):
                    self.limiter.reward()
                    return status, body
                if status == 0 and "超时" in (body or ""):
                    # 请求被站点吊住了：多半是页面里正挂着滑块，重试只会再挂一个请求
                    log_print("❌接口请求被站点挂起（浏览器窗口里多半正在弹滑块验证）")
                    return ""
                if looks_like_login_html(body):
                    log_print("⚠️浏览器通道返回的是登录页：粘贴的Cookie可能已失效")
                    return status, body
                if body and self._looks_blocked("", body):
                    # 页面自己发的请求也被拦：按限流处理，降速后交给上层重试
                    self.limiter.penalize()
                    log_print(f"⚠️浏览器通道被站点拦截 status={status}")
                    log_print(f"   响应片段: {(body or '')[:200]}")
                    return status, body
                log_print(f"⚠️浏览器通道响应异常 status={status}，第{attempt + 1}/{retries + 1}次尝试")
                log_print(f"   响应片段: {(body or '')[:200]}")
                if attempt < retries:
                    safe_sleep(2)
                continue
            if self.session is None:
                log_print("⚠️没有可用的会话（cookie没建起来），无法请求接口")
                return 0, ""
            try:
                resp = self.session.get(url, headers=headers, timeout=timeout)
                body = resp.text
                if not self._looks_blocked(resp.headers.get("content-type"), body):
                    self.limiter.reward()
                    return resp.status_code, body
                status = resp.status_code
                final_url = getattr(resp, "url", url)
                # 登录页特征可能在改版后消失，所以「最终地址落在 /login/」也算登录失效
                if looks_like_login_html(body) or "/login/" in (final_url or ""):
                    # 站点把请求跳到了登录页：这不是WAF，是cookie失效了。
                    # 重试多少次都是同一个登录页，直接交给上层按「cookie失效」报错
                    log_print(f"⚠️接口返回的是登录页（最终地址: {final_url}）")
                    log_print("   → 粘贴的Cookie已失效，请到浏览器重新登录后复制一份新的cookie")
                    return status, body
                log_print(f"⚠️requests返回的不是JSON status={resp.status_code}，切浏览器通道")
                log_print(
                    f"   最终地址: {final_url}  类型: {resp.headers.get('content-type', '')}"
                    f"  长度: {len(body or '')}字节"
                )
                title = html_title(body)
                if title:
                    log_print(f"   页面标题: {title}")
                # 注意：这里先不降速。requests被WAF挑战是「通道指纹」问题，
                # 切到浏览器页面通常就正常了；浏览器也拦了才是真的请求太密（见下面）
                if self._switch_to_pw():
                    # 换通道后立刻用页面把同一个URL再打一枪，别等下一轮重试
                    status, body = fetch_text_in_page(self.pw_page, url, headers, timeout)
                    if status == 200 and body.strip() and not self._looks_blocked("", body):
                        self.limiter.reward()
                        return status, body
                    if status == 0 and "超时" in (body or ""):
                        log_print("❌接口请求被站点挂起（浏览器窗口里多半正在弹滑块验证）")
                        return ""
                    if looks_like_login_html(body):
                        log_print("⚠️浏览器通道返回的是登录页：粘贴的Cookie可能已失效")
                        return status, body
                    # 页面通道也被拦：这才是真正的限流，降速后交给上层重试
                    self.limiter.penalize()
                    log_print(f"⚠️浏览器通道响应异常 status={status}")
                    log_print(f"   响应片段: {(body or '')[:200]}")
                    return status, body
                # 没有可用的浏览器通道，requests又被拦：按限流处理
                self.limiter.penalize()
                return status, body
            except (WafChallengeLimit, TaskStopped):
                raise
            except Exception as e:
                status = 0
                log_print(f"⚠️接口请求异常:{e}")
            if attempt < retries:
                log_print(f"   第{attempt + 1}/{retries + 1}次尝试失败，稍后重试")
            safe_sleep(2)
        return status, ""

    def _thread_session(self):
        """图片并发下载时每个线程用自己的Session——requests.Session不是线程安全的。
        没有cookie列表（离线测试/探测脚本）时退回共享session，由调用方保证串行"""
        if not self.cookies or self.session is None:
            return self.session
        sess = getattr(self._tls, "session", None)
        if sess is None:
            sess = build_session_from_cookies(self.cookies)
            self._tls.session = sess
        return sess

    def get_bytes(self, url, timeout=30, allow_browser=True):
        """下载整页原图，返回bytes或None。
        先requests；被拦/拿到HTML/异常时，再让浏览器导航取字节（跨域限制对导航不适用）。
        allow_browser=False 用于线程池worker：Playwright对象不能跨线程调用，
        失败的页由主线程稍后串行重试（见 crawl_magazine_images）"""
        sess = self._thread_session()
        if sess is not None:
            try:
                resp = sess.get(url, timeout=timeout)
                ct = (resp.headers.get("content-type") or "").lower()
                head = resp.content[:64].lstrip().lower()
                if resp.status_code == 200 and "html" not in ct and not head.startswith(b"<"):
                    return resp.content
                log_print(f"⚠️图片下载返回异常 status={resp.status_code} type={ct}")
            except Exception:
                pass
        if not allow_browser:
            return None
        log_print("   改用浏览器导航下载")
        page = self._scratch()
        if page is None:
            return None
        try:
            resp = page.goto(url, wait_until="load", timeout=timeout * 1000)
            if resp is None:
                log_print("⚠️浏览器导航下载失败：没有响应")
                return None
            if not resp.ok:
                log_print(f"⚠️浏览器导航下载失败 status={resp.status}")
                return None
            body = resp.body()
            ct = (resp.headers.get("content-type") or "").lower()
            if "html" in ct or body[:64].lstrip().lower().startswith(b"<"):
                log_print("⚠️浏览器导航下载拿到的是网页而不是图片，按失败处理")
                return None
            return body
        except Exception as e:
            log_print(f"⚠️浏览器导航下载异常:{e}")
            return None


# ===================== 采集地址解析（v2新增） =====================
SITE_ID_RE = re.compile(r"hngymyzyxy_(\d+)", re.IGNORECASE)
QUERY_ID_RE = re.compile(r"[?&](?:item_id|resource_id|magazine_id|id)=(\d+)", re.IGNORECASE)
PATH_ID_RE = re.compile(r"/(\d+)(?:\.html)?(?:[?#]|$)")


def parse_collect_address(text: str) -> dict:
    """从界面粘贴的采集地址里取出站点id，返回 {"id","kind","raw"}，取不到时 id 为空串。
    kind 是地址类型：
      past —— 往期(刊期)列表页，地址里的数字本来就是 magazine_id，直接就能用
      detail / thumblist / reader / number —— 给的是资源id，要先请求一次缩略图接口换成 magazine_id
    例：https://web.591adb.cn/magazine/detail/hngymyzyxy_1031982.html?_=1792144681 → 1031982"""
    raw = (text or "").strip()
    if not raw:
        return {"id": "", "kind": "", "raw": raw}
    if raw.isdigit():
        return {"id": raw, "kind": "number", "raw": raw}
    kind = ""
    for key, name in (
        ("/past/", "past"),
        ("/detail/", "detail"),
        ("/thumblist/", "thumblist"),
        ("/reader/", "reader"),
    ):
        if key in raw:
            kind = name
            break
    m = SITE_ID_RE.search(raw) or QUERY_ID_RE.search(raw) or PATH_ID_RE.search(raw)
    if not m:
        return {"id": "", "kind": kind, "raw": raw}
    return {"id": m.group(1), "kind": kind or "unknown", "raw": raw}

# ===================== 缩略图接口分页（v2新增） =====================
# 返回里这些名字的字段会被当成「页数/数量」候选打印到日志，方便判断能不能直接用总数收尾
PAGE_HINT_KEYS = (
    "total_page", "totalpage", "page_total", "page_count", "pagecount",
    "pages", "page_num", "pagenum", "img_count", "image_count", "total", "count",
)


def image_page_key(url: str) -> str:
    """图片指纹：取地址最后一段文件名（如 0001.webp）。
    站点给的图片地址前缀带着每次请求都会变的随机串（同一张图两次请求拿到的hash不同），
    拿整条URL比对是比不出重复的，只能按文件名比"""
    return re.split(r"[?#]", url or "", 1)[0].rsplit("/", 1)[-1]


def normalize_image_url(url: str) -> str:
    """规整缩略图接口给的图片地址：去掉JSON里的转义、补全协议头。
    如果以后发现 item_thumb_list 给的是缩略图（比如地址里带 /200/ 这种尺寸段），
    在这里按站点规律换成原图即可，其余逻辑都不用动"""
    url = (url or "").replace("\\", "").strip()
    if url.startswith("//"):
        return "https:" + url
    return url


# 站点给的图片地址字段名（实测 2026-10-16 是 thumb_image，其余是站点改版时的备选名）
THUMB_URL_KEYS = (
    "thumb_image", "thumb_img", "img", "img_url", "image", "image_url",
    "url", "src", "thumb", "thumb_url", "path", "pic",
)
IMAGE_URL_RE = re.compile(r"\.(?:jpg|jpeg|png|webp|gif|bmp)(?:\?|$)", re.IGNORECASE)


def extract_thumb_url(row) -> str:
    """item_thumb_list 里一项可能是字符串，也可能是对象
    （实测：{"thumb_image": "https://…/jpg/1.jpg", "page_number": 1}），两种都兼容"""
    if isinstance(row, str):
        return normalize_image_url(row)
    if isinstance(row, dict):
        for key in THUMB_URL_KEYS:
            v = row.get(key)
            if isinstance(v, str) and v.strip():
                return normalize_image_url(v)
        # 站点又改字段名时兜底：取第一个像图片地址的字符串值
        for v in row.values():
            if isinstance(v, str) and IMAGE_URL_RE.search(v):
                return normalize_image_url(v)
    return ""


def extract_magazine_name(item_info) -> str:
    """从 item_info 里取杂志名（取不到返回空串）。
    实测这个接口给的是 item_name（如「北京纪事」），volume 才是刊期（如「2026年10月第10期」）；
    其余几个是本工具兼容别处数据时用的备选字段名"""
    if not isinstance(item_info, dict):
        return ""
    for key in ("magazine_name", "magazine_title", "mag_title", "item_name", "name", "title"):
        v = item_info.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def parse_thumb_list_response(resp_text: str):
    """解析缩略图接口返回，返回 (图片地址列表, item_info, 错误说明, data原文)。
    ⚠️能解析出合法JSON时错误说明就是空的——哪怕 item_thumb_list 是空的，
    那也是站点的正常回答（很可能是「没有更多了」），不是错误，别把它当失败吞掉"""
    try:
        obj = json.loads(resp_text)
    except (json.JSONDecodeError, TypeError):
        return [], {}, f"返回不是JSON: {(resp_text or '')[:120]}", {}
    if not isinstance(obj, dict):
        return [], {}, f"返回结构异常: {(resp_text or '')[:120]}", {}
    if obj.get("error") not in (0, "0", None):
        msg = obj.get("msg") or obj.get("message") or ""
        return [], {}, f"接口返回 error={obj.get('error')} msg={msg}", {}
    payload = obj.get("data") or {}
    if not isinstance(payload, dict):
        return [], {}, f"data字段结构异常: {str(payload)[:120]}", {}
    item_info = payload.get("item_info") or {}
    raw_list = payload.get("item_thumb_list") or []
    urls = []
    if isinstance(raw_list, list):
        for row in raw_list:
            u = extract_thumb_url(row)
            if u:
                urls.append(u)
        if raw_list and not urls:
            log_print(f"⚠️item_thumb_list有{len(raw_list)}项但解析不出图片地址，样例: {str(raw_list[0])[:200]}")
    return urls, item_info, "", payload


def is_json_text(text: str) -> bool:
    """响应体是不是合法JSON。用它把「站点明确回答」和「空响应/被拦」分开：
    合法JSON（哪怕里面写着 error!=0、图片列表为空）都是站点在正常说话，不用重试；
    空响应、非JSON、非200 才可能是被WAF拦了，值得重试一会儿"""
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def log_page_hints(payload: dict):
    """把返回里像「总页数」的字段打到日志（每期只看第一页）。
    如果日志显示站点确实给了总页数，翻页结束条件就能改成用它判断，比猜「末页返回什么」更准"""
    hints = []

    def scan(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    scan(v, f"{prefix}{k}.")
                elif str(k).lower() in PAGE_HINT_KEYS and str(v).strip():
                    hints.append(f"{prefix}{k}={v}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:2]):
                scan(v, f"{prefix}[{i}].")

    try:
        scan(payload)
    except Exception:
        return
    if hints:
        log_print("   （返回里的页数/数量字段: " + ", ".join(hints[:10]) + "）")


def api_headers(referer: str = "") -> dict:
    """接口请求头：照站点前端发XHR的样子补齐（Accept/Origin/sec-fetch-*）。
    Referer 传实际采集地址比站点根路径更像浏览器；站点WAF对「请求像不像它自己的前端」很敏感"""
    headers = dict(SiteConfig.REQ_HEADERS)
    if referer:
        headers["Referer"] = referer
    headers.update(
        {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Origin": "https://web.591adb.cn",
            "x-requested-with": "XMLHttpRequest",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "sec-fetch-dest": "empty",
            "priority": "u=1,i",
        }
    )
    return headers


def thumb_list_url(item_id, p: int) -> str:
    return SiteConfig.THUMBLIST_URL_TMPL.format(
        item_id=item_id, p=p, ts=int(time.time() * 1000)
    )


def reader_url(item_id, p: int) -> str:
    """阅读器接口地址：p=1 与 p>1 的参数不同，照 v1(main.py) 和站点前端的样子拼"""
    ts = int(time.time() * 1000)
    if p == 1:
        return SiteConfig.READER_URL_P1_TMPL.format(item_id=item_id, p=p, ts=ts)
    return SiteConfig.READER_URL_TMPL.format(
        item_id=item_id, uf=SiteConfig.READER_UF, p=p, ts=ts
    )


def fetch_thumb_list_page(client, item_id, p: int, headers: dict):
    """取缩略图接口的一页，返回(状态码, 响应文本)。
    p从1开始递增，一次返回好几页的图片地址（data.item_thumb_list）"""
    return client.get_text_status(thumb_list_url(item_id, p), headers=headers)


def fetch_thumb_page_with_retry(client, item_id, p, headers):
    """请求一页；没拿到有效响应（空响应/非JSON/error!=0）就重试几轮，返回最后一次的(状态码, 文本)"""
    last_status, last_body = 0, ""
    for attempt in range(MAX_THUMB_RETRY + 1):
        check_stop()
        last_status, last_body = fetch_thumb_list_page(client, item_id, p, headers)
        # 站点给了明确回答（合法JSON，哪怕里面写着 error!=0 或图片列表为空）就不再重试，
        # 只有空响应/非JSON/非200这种可能是被拦的才值得再试
        if last_status == 200 and is_json_text(last_body):
            return last_status, last_body
        if is_no_login_response(last_body) or looks_like_login_html(last_body):
            # cookie里的登录态被服务端失效了。没有浏览器就没法就地重登，
            # 只能明确告诉用户去重新粘贴一份cookie（再重试也是一样的结果）
            return last_status, last_body
        if attempt < MAX_THUMB_RETRY:
            _, _, err, _ = parse_thumb_list_response(last_body)
            reason = err or f"HTTP {last_status}，响应{len(last_body or '')}字节"
            log_print(f"⚠️p={p} 第{attempt + 1}次没拿到有效响应（{reason}），重试")
            safe_sleep(3)
    return last_status, last_body


# ===================== 阅读器接口：收集整页原图地址 =====================
def is_ad_image_url(url: str) -> bool:
    """广告图：站点把 appAd/readerad_big.jpg 混在每页旁边，必须挑掉（v1 也这么干）"""
    return "readerad_big.jpg" in url or "/appAd/" in url


def fetch_reader_pages(client, item_id, p: int, headers: dict):
    """阅读器接口：一次返回2页的整页原图地址，返回 (图片地址列表, 错误说明)。
    错误说明非空表示这次响应不能用。
    ⚠️p 从1开始、每次+2（站点前端就这么翻：p=1给第1页，p=3给第2、3页）
    ⚠️与 v1(main.py) 一致走 uf=0：image_list 里一页就是一张整图，不是瓦片"""
    status, body = client.get_text_status(reader_url(item_id, p), headers=headers)
    if status != 200 or not (body or "").strip():
        return [], f"HTTP {status}，响应{len(body or '')}字节"
    if is_no_login_response(body):
        return [], "请登录后再做操作"
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        # 兜底：与 v1 一样，万一站点回的是阅读器HTML，从 slider-img 里抠地址
        html_urls = [
            m.replace("\\", "")
            for m in re.findall(
                r'<img class="slider-img" src="([^"]+\.(?:webp|jpg|jpeg|png))"', body or ""
            )
        ]
        if html_urls:
            return [u for u in html_urls if not is_ad_image_url(u)], ""
        return [], f"返回不是JSON: {(body or '')[:120]}"
    if obj.get("error") not in (0, "0", None):
        msg = obj.get("msg") or obj.get("message") or ""
        return [], f"接口返回 error={obj.get('error')} msg={msg}"
    rows = (obj.get("data") or {}).get("image_list") or []
    urls = []
    for row in rows:
        if isinstance(row, str):
            u = normalize_image_url(row)
        elif isinstance(row, dict):
            # 兜底：站点偶尔把一项包成对象（字段名见 THUMB_URL_KEYS）
            u = extract_thumb_url(row)
        elif isinstance(row, list):
            # uf=0 下不该出现瓦片数组；真出现了就明确报错，别拿残缺页凑PDF
            return [], "接口仍返回瓦片格式（image_list 是数组套数组），站点可能又改版了，请反馈开发者"
        else:
            continue
        if u and not is_ad_image_url(u):
            urls.append(u)
    return urls, ""


def walk_reader_pages(
    client, item_id, want_pages: int, headers: dict, on_new_page=None
) -> list:
    """按 p=1,3,5… 把这一期的整页原图地址收集齐，返回按页序排好的地址列表。
    want_pages 是期望页数(item_info.page_num)，只用来判断什么时候够了；
    真正停下来的依据是「接口返回的图片与已收集的相同（文件名重复）」——
    站点翻到头就是重复给已经有的页，这时立即退出循环。
    on_new_page(page_no, url)：每发现一个新页就回调一次，用于「边收集边下载」"""
    urls = []
    seen = set()
    block_retries = 0
    p = 1
    calls = 0
    while calls < MAX_READER_CALLS:
        check_stop()
        calls += 1
        rows, err = fetch_reader_pages(client, item_id, p, headers)
        if err:
            # 403「访问被拦截」/ 返回WAF挑战页 = 请求太密被限流了（不是没数据）。
            # 这时候丢掉后面的页最亏，停一会儿再试同一页；真等不回来才按已收集到的页继续
            if (
                "403" in err or "拦截" in err or "<html" in err.lower()
            ) and block_retries < MAX_READER_BLOCK_RETRY:
                block_retries += 1
                log_print(
                    f"⚠️疑似被站点限流（{err}），等{READER_BLOCK_WAIT}秒后重试 p={p}"
                    f"（第{block_retries}/{MAX_READER_BLOCK_RETRY}次）"
                )
                safe_sleep(READER_BLOCK_WAIT)
                calls -= 1  # 等待重试不算进熄火次数
                continue
            if not urls:
                raise Exception(
                    COOKIE_EXPIRED_MSG if "请登录" in err
                    else f"阅读器接口第1次请求就失败：{err} " + blocked_hint(err)
                )
            log_print(f"⚠️阅读器接口返回异常（{err}），按已收集到的{len(urls)}页继续")
            break
        block_retries = 0
        new_count = 0
        for u in rows:
            key = image_page_key(u)
            if not key or key in seen:
                continue
            seen.add(key)
            urls.append(u)
            new_count += 1
            if on_new_page is not None:
                on_new_page(len(urls), u)
        if new_count:
            log_print(f"  p={p} 收集到{new_count}页，累计{len(urls)}页")
        else:
            # 返回的图片地址/文件名全是已有的 → 站点翻到头了，立即退出
            log_print(f"  p={p} 返回的图片与已有页相同（文件名重复），判定已到末页，退出循环")
            break
        if want_pages and len(urls) >= want_pages:
            break
        p += READER_PAGE_STEP
    return urls


PAGE_IMAGE_EXTS = ("webp", "jpg", "jpeg", "png", "gif", "bmp")


def page_image_ext(url: str) -> str:
    """整页原图的扩展名（站点实测给 .webp）；认不出来就按 .jpg 存"""
    name = image_page_key(url)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext if ext in PAGE_IMAGE_EXTS else "jpg"


def download_page_image(client, page_no: int, url: str, out_dir: str, allow_browser=True):
    """下载一页的整页原图，返回文件路径；失败返回None。中途停止会抛 TaskStopped。
    allow_browser=False 时只走requests（线程池worker里不能碰Playwright）"""
    check_stop()
    out_path = os.path.join(out_dir, f"{page_no:04d}.{page_image_ext(url)}")
    for attempt in range(1, 4):
        check_stop()
        data = client.get_bytes(url, allow_browser=allow_browser)
        if data:
            with open(out_path, "wb") as f:
                f.write(data)
            return out_path
        log_print(f"⚠️第{page_no}页下载失败[{attempt}/3]：{url}")
        safe_sleep(2)
    log_print(f"❌第{page_no}页多次重试失败，跳过这一页")
    return None


def resolve_magazine_id(client, parsed: dict, headers: dict):
    """把采集地址里的id换成往期列表接口要的 magazine_id，返回 (magazine_id, magazine_name)。
    /past/ 地址里给的本来就是 magazine_id，直接用；
    其余（detail/thumblist/reader/纯数字）拿它请求一次缩略图接口，读 data.item_info.magazine_id"""
    the_id = parsed["id"]
    if parsed["kind"] == "past":
        log_print(f"采集地址按往期列表页解析：{the_id} 即 magazine_id")
        return the_id, ""
    log_print(f"采集地址里的id={the_id}（{parsed['kind']}），先用缩略图接口换成 magazine_id")
    status, body = fetch_thumb_page_with_retry(client, the_id, 1, headers)
    _, item_info, err, _ = parse_thumb_list_response(body)
    if is_no_login_response(body) or looks_like_login_html(body):
        raise Exception(
            COOKIE_EXPIRED_MSG
            + ("" if is_no_login_response(body) else "（缩略图接口返回的是登录页）")
        )
    if err:
        raise Exception(
            f"用采集地址里的id={the_id}请求缩略图接口失败：{err} "
            + (blocked_hint(body) or blocked_hint(err) or "（响应为空，请稍等10~30分钟再试）")
        )
    magazine_id = str(item_info.get("magazine_id") or "").strip()
    if not magazine_id:
        raise Exception(
            f"缩略图接口没有返回 magazine_id（id={the_id} 可能不是本站的杂志资源id）。"
            f"返回片段: {(body or '')[:200]}"
        )
    return magazine_id, extract_magazine_name(item_info)


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
    collect_addr: str,
    target_year: str,
    target_volume_name_text: str,
    save_root: str,
    holder: "BrowserHolder" = None,
    cookies: list = None,
):
    """拿到采集地址后：换成 magazine_id → 取往期列表 → 按年份/期数筛选 → 逐期取图。
    每一期分三步：
      ① 缩略图接口 p=1：拿这一期的总页数(item_info.page_num)和杂志名
      ② 阅读器接口按 p=1,3,5… 一页页收集（一次2页，uf=0，与 v1 一致）；
         接口返回的图片与已收集的相同（文件名重复）就判定到末页，退出循环
      ③ 逐张下载整页原图
    requests 被站点WAF拦下时，ApiClient 会自动切到 holder 里的浏览器页面发请求。
    每下完一期就yield出去，由上层立刻转PDF"""
    limiter = RateLimiter(API_RATE_PER_MIN, API_BURST)
    client = ApiClient(session, holder=holder, cookies=cookies, limiter=limiter)
    # Referer 用实际采集地址：站点WAF会看「请求是不是从对应页面发出来的」
    xml_headers = api_headers(collect_addr if collect_addr.startswith("http") else "")

    # ===== 1.采集地址 → magazine_id =====
    parsed = parse_collect_address(collect_addr)
    if not parsed["id"]:
        raise Exception(
            f"采集地址里解析不出站点id：{collect_addr}。"
            "请粘贴形如 https://web.591adb.cn/magazine/detail/hngymyzyxy_1031982.html 的地址"
        )
    magazine_id, magazine_name = resolve_magazine_id(client, parsed, xml_headers)
    log_print(f"magazine_id={magazine_id}" + (f" 杂志名:{magazine_name}" if magazine_name else ""))

    # ===== 2.往期(刊期)列表 =====
    past_url = SiteConfig.PAST_URL_TMPL.format(
        magazine_id=magazine_id, ts=int(time.time() * 1000)
    )
    log_print(f"请求刊期列表 {past_url}")
    past_text = client.get_text(past_url, headers=xml_headers)
    if not past_text:
        # 被拦了就直接收手。曾经试过「丢掉WAF凭证重开页面再打一枪」，结果是：
        # 用户刚滑过的那一页被我们跳走 → 站点立刻再弹一个滑块。站点一旦盯上这台机器，
        # 任何重新跳转都是在给用户找新的验证码
        raise Exception("获取刊期列表失败：接口无有效响应。" + blocked_hint(past_text))
    try:
        past_json = json.loads(past_text)
    except json.JSONDecodeError:
        if looks_like_login_html(past_text):
            raise Exception(COOKIE_EXPIRED_MSG + "（刊期列表接口返回的是登录页）")
        raise Exception(
            f"刊期列表接口返回非JSON内容: {past_text[:200]}" + blocked_hint(past_text)
        )
    if past_json.get("error") != 0:
        raise Exception(f"获取刊期列表失败: {str(past_json)[:200]}")

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

    # ===== 3.逐期取图 =====
    for article in article_info_list:
        check_stop()
        item_id = article.get("item_id")
        resource_id_item = article.get("resource_id")
        volume = article.get("volume", "")
        log_print(f"找到刊期 {volume} item_id={item_id}")

        # ① 缩略图接口只要第一页：拿总页数(item_info.page_num)和杂志名。
        #    不用它当图片源——它给的是 160×225 的缩略图（实测），印成PDF根本看不清字；
        #    真正的整页原图在阅读器接口那边（uf=0，与 v1 一致）
        status, body = fetch_thumb_page_with_retry(client, item_id, 1, xml_headers)
        thumbs, info, err, payload = parse_thumb_list_response(body)
        if is_no_login_response(body) or looks_like_login_html(body):
            raise Exception(
                COOKIE_EXPIRED_MSG
                + ("" if is_no_login_response(body) else "（缩略图接口返回的是登录页）")
            )
        if err or status != 200 or not (body or "").strip():
            detail = err or f"HTTP {status}，响应{len(body or '')}字节"
            raise Exception(f"读取该期页数失败（缩略图接口）：{detail} " + blocked_hint(body))
        name = extract_magazine_name(info)
        if name and not magazine_name:
            magazine_name = name
            log_print(f"（从接口取到杂志名:{magazine_name}）")
        log_print("   item_info字段: " + ", ".join(list(info.keys())[:20]))
        log_page_hints(payload)
        raw_page_num = str(info.get("page_num") or "").strip()
        want_pages = int(raw_page_num) if raw_page_num.isdigit() else 0
        log_print(
            f"该期共{want_pages}页" if want_pages
            else "接口没给总页数，将按「返回的图片与已有页相同」判断收集结束"
        )

        mag_dir_name = sanitize_filename_part(magazine_name or f"magazine_{magazine_id}")
        save_dir = os.path.join(
            save_root,
            mag_dir_name,
            f"{sanitize_filename_part(volume)}_{resource_id_item}_{item_id}",
        )
        os.makedirs(save_dir, exist_ok=True)

        # ②/③ 边收集边下载：阅读器每发现一页就丢进下载线程池。
        # 接口受令牌桶限速，等待的时间里图片已经在并发下载了（图片在CDN，和接口限速分开）
        page_results = {}
        futures = {}
        failed_pages = []

        def _download_one(page_no, url):
            return page_no, download_page_image(
                client, page_no, url, save_dir, allow_browser=False
            )

        with ThreadPoolExecutor(max_workers=IMAGE_WORKERS) as pool:
            def on_new_page(page_no, url):
                fut = pool.submit(_download_one, page_no, url)
                futures[fut] = (page_no, url)

            # 阅读器接口把每一页的整页原图地址收集齐（一次2页，和 v1 一样走 uf=0）。
            # 每个图片地址都带CDN签名，签名是「按图片路径」签的，改文件名就失效，
            # 所以没法只拿封面地址+文件名递增推出其他页，只能按接口返回的地址走。
            # page_count>0 时 want_pages=用户填的页数，收够就提前停（省掉末尾的空转轮次）
            page_urls = walk_reader_pages(
                client, item_id, want_pages, xml_headers, on_new_page=on_new_page
            )
            if not page_urls:
                raise Exception(f"刊期 {volume} 没有收集到任何页面图片（item_id={item_id}）")
            if want_pages and len(page_urls) != want_pages:
                log_print(f"⚠️接口说{want_pages}页，实际收集到{len(page_urls)}页")
                log_print(
                    "   若日志里出现过「疑似被站点限流」，就是被拦断的——隔十几分钟重跑这一期即可；"
                    "否则请把日志反馈给开发者"
                )
            log_print(f"   第1页地址样例: {page_urls[0]}")

            for fut in as_completed(futures):
                page_no, url = futures[fut]
                try:
                    _, path = fut.result()
                except TaskStopped:
                    raise
                except Exception as e:
                    log_print(f"❌第{page_no}页处理失败：{e}")
                    path = None
                if path:
                    page_results[page_no] = path
                    log_print(f"第{page_no}/{len(page_urls)}页 完成 {os.path.basename(path)}")
                else:
                    failed_pages.append((page_no, url))

        # 线程池里失败的页，回到主线程串行重试（这里可以用浏览器导航兜底）
        for page_no, url in sorted(failed_pages):
            check_stop()
            path = download_page_image(client, page_no, url, save_dir, allow_browser=True)
            if path:
                page_results[page_no] = path
                log_print(f"第{page_no}/{len(page_urls)}页 重试完成 {os.path.basename(path)}")
        local_paths = [page_results[k] for k in sorted(page_results)]
        log_print(f"共获取 {len(local_paths)} 页图片")
        # 每下完1期图片，立即把该期结果yield出去，由上层马上转PDF
        yield {
            "volume": volume,
            "dir": save_dir,
            "images": local_paths,
            "magazine_name": magazine_name,
        }

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
    cookie_text,
    collect_addr,
    year_str,
    issue_str,
    watermark_file,
    watermark_pages_text,
    pdf_owner_pwd,
    save_result_dir,
    del_after_pdf=False,
):
    holder = BrowserHolder()  # 按需启动：requests被WAF拦下才会真的开浏览器
    try:
        TASK_STOP_EVENT.clear()
        reset_waf_challenge_count()
        log_print(f"🚀开始执行任务，数据目录:{DATA_DIR}")
        log_print(f"采集地址:{collect_addr}")

        # 会话：先用界面粘贴的这份cookie走requests直连；
        # 站点WAF现在会拦requests（返回HTML挑战页），拦下后自动切浏览器页面发请求
        cookies = parse_cookie_input(cookie_text)
        if not cookies:
            raise Exception("没有可用的Cookie：请把浏览器里的cookie整条粘贴到界面上再执行")
        log_print(f"使用界面粘贴的Cookie：{describe_cookies(cookies)}")
        session = build_session_from_cookies(cookies)

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
            collect_addr=collect_addr,
            target_year=year_str,
            target_volume_name_text=issue_str,
            save_root=save_result_dir,
            holder=holder,
            cookies=cookies,
        ):
            item_count += 1
            check_stop()
            img_paths = item["images"]
            vol_name = item["volume"]
            # 杂志名从接口里取；取不到就用该期目录名兜底（magazine_<id>），保证PDF名和目录对得上
            mag_name = item.get("magazine_name") or os.path.basename(os.path.dirname(item["dir"]))
            out_pdf = os.path.join(
                save_result_dir,
                f"{sanitize_filename_part(mag_name)}_{sanitize_filename_part(vol_name)}.pdf",
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
    except WafChallengeLimit as e:
        # 站点安全检测无限弹滑块：这是给用户看的操作建议，不需要打印调用栈
        log_print(f"\n🛑{e}")
    except TaskStopped:
        log_print("\n🛑任务被用户停止")
    except RuntimeError as e:
        log_print(f"\n❌任务异常 {e}")
        import traceback
        log_print(traceback.format_exc())
    except Exception as e:
        import traceback
        log_print(f"\n❌任务异常 {e}")
        log_print(traceback.format_exc())
    finally:
        # 任务结束后释放浏览器（浏览器通道在爬取期间保持打开，供后续XHR使用）
        holder.close()

# ===================== GUI主界面 =====================
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("杂志PDF下载工具 v2")
        self.root.geometry("1020x940")
        self.root.minsize(900, 780)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.running = False
        self.worker = None
        self.worker_done_flag = False  # 子线程结束时置位，由主线程轮询后更新按钮状态
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

        # 采集地址：粘贴杂志地址，程序从地址里解析出 magazine_id 再去取年份/期数
        self.addr_var = tk.StringVar()
        ent_addr = ttk.Entry(task_box, textvariable=self.addr_var, width=26)
        self.year_var = tk.StringVar()
        ent_year = ttk.Entry(task_box, textvariable=self.year_var, width=26)
        ttk.Label(task_box, text="采集地址 *").grid(row=0, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        ent_addr.grid(row=0, column=1, sticky=tk.EW, padx=(0, 24), pady=4)
        ttk.Label(task_box, text="年份").grid(row=0, column=3, sticky=tk.E, padx=(0, 8), pady=4)
        ent_year.grid(row=0, column=4, sticky=tk.EW, pady=4)

        self.issue_var = tk.StringVar()
        ent_issue = ttk.Entry(task_box, textvariable=self.issue_var, width=26)
        self.save_dir_var = tk.StringVar()
        ent_save = ttk.Entry(task_box, textvariable=self.save_dir_var, width=26)
        btn_save = ttk.Button(task_box, text="选择目录", command=self.select_save_dir)
        ttk.Label(task_box, text="期刊").grid(row=1, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        ent_issue.grid(row=1, column=1, sticky=tk.EW, padx=(0, 24), pady=4)
        ttk.Label(task_box, text="保存目录 *").grid(row=1, column=3, sticky=tk.E, padx=(0, 8), pady=4)
        ent_save.grid(row=1, column=4, sticky=tk.EW, padx=(0, 6), pady=4)
        btn_save.grid(row=1, column=5, pady=4)

        # Cookie：粘贴浏览器里的cookie，接口请求优先用它直连
        ttk.Label(task_box, text="Cookie *").grid(row=2, column=0, sticky=tk.NE, padx=(0, 8), pady=(6, 4))
        self.cookie_text = tk.Text(
            task_box, height=3, wrap=tk.CHAR, font=("Menlo", 10), relief=tk.SUNKEN, borderwidth=1
        )
        self.cookie_text.grid(row=2, column=1, columnspan=5, sticky=tk.EW, pady=(6, 2))
        ttk.Label(
            task_box,
            text="粘贴浏览器里的整条cookie（形如 name=value; name2=value2）。"
                 "接口请求优先用它直连；被站点安全检测拦下时会自动打开Chrome，"
                 "用这份cookie由页面发请求（弹滑块时需手动滑一下）。"
                 "会话失效时日志会提示，重新登录网站复制一份新的再粘进来即可",
            style="Hint.TLabel",
        ).grid(row=3, column=1, columnspan=5, sticky=tk.W)

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
        ttk.Label(pdf_box, text="权限密码").grid(row=1, column=0, sticky=tk.E, padx=(0, 8), pady=4)
        ent_pdf_pwd.grid(row=1, column=1, sticky=tk.EW, padx=(0, 24), pady=4)

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
        self.save_dir_var.set(cfg.get("save_dir", ""))
        self.addr_var.set(cfg.get("collect_addr", ""))
        self.year_var.set(cfg.get("year", ""))
        self.issue_var.set(cfg.get("issue", ""))
        self.watermark_file_var.set(cfg.get("watermark_file", ""))
        self.watermark_page_var.set(cfg.get("watermark_pages", ""))
        self.pdf_pwd_var.set(cfg.get("pdf_pwd", ""))
        self.del_after_pdf_var.set(bool(cfg.get("del_after_pdf", False)))
        # 上次粘贴的cookie也一并恢复：站点会话失效时日志会说清，届时重新粘贴一份即可
        self.cookie_text.delete("1.0", tk.END)
        self.cookie_text.insert("1.0", cfg.get("cookie_text", ""))

    def save_current_ui_config(self):
        cfg = {
            "save_dir": self.save_dir_var.get(),
            "collect_addr": self.addr_var.get(),
            "year": self.year_var.get(),
            "issue": self.issue_var.get(),
            "watermark_file": self.watermark_file_var.get(),
            "watermark_pages": self.watermark_page_var.get(),
            "pdf_pwd": self.pdf_pwd_var.get(),
            "del_after_pdf": self.del_after_pdf_var.get(),
            "cookie_text": self.cookie_text.get("1.0", tk.END).strip(),
        }
        save_last_config(cfg)

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

    def consume_log(self):
        try:
            while True:
                msg = LOG_QUEUE.get_nowait()
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
        except Empty:
            pass
        # 子线程只置标志位，界面更新一律回到主线程做：Tkinter不是线程安全的，
        # 在子线程里直接调root.after，窗口一关就可能抛TclError
        if self.worker_done_flag:
            self.worker_done_flag = False
            self.set_ui_running_state(False)
        self.root.after(50, self.consume_log)

    def start_task(self):
        if self.running:
            return
        collect_addr = self.addr_var.get().strip()
        cookie_text = self.cookie_text.get("1.0", tk.END).strip()
        save_dir = self.save_dir_var.get().strip()
        wm_file = self.watermark_file_var.get().strip()
        wm_pages = self.watermark_page_var.get().strip()
        del_after_pdf = self.del_after_pdf_var.get()

        if not collect_addr:
            messagebox.showerror("校验错误", "采集地址不能为空")
            return
        if not parse_collect_address(collect_addr)["id"]:
            messagebox.showerror(
                "校验错误",
                "采集地址里解析不出站点ID\n\n请粘贴形如\n"
                "https://web.591adb.cn/magazine/detail/hngymyzyxy_1031982.html?_=1792144681\n的地址",
            )
            return
        if not cookie_text:
            messagebox.showerror("校验错误", "Cookie不能为空\n\n请到浏览器里复制整条cookie粘贴进来")
            return
        if not parse_cookie_input(cookie_text):
            messagebox.showerror(
                "校验错误",
                "Cookie解析不出内容\n\n请粘贴形如 name=value; name2=value2 的整条cookie",
            )
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
        # 所有参数在这里一次性取出，交给子线程使用：
        # 子线程读Tk变量既不是线程安全的，也可能读到用户运行中途改动的值
        year = self.year_var.get().strip()
        issue = self.issue_var.get().strip()
        pdf_pwd = self.pdf_pwd_var.get().strip()

        self.save_current_ui_config()
        self.set_ui_running_state(True)
        TASK_STOP_EVENT.clear()

        def work_wrapper():
            background_task(
                cookie_text,
                collect_addr,
                year,
                issue,
                wm_file,
                wm_pages,
                pdf_pwd,
                save_dir,
                del_after_pdf,
            )
            self.worker_done_flag = True

        self.worker = threading.Thread(target=work_wrapper, daemon=True)
        self.worker.start()

    def stop_task(self):
        TASK_STOP_EVENT.set()
        log_print("🛑发送停止信号")

    def on_close(self):
        TASK_STOP_EVENT.set()
        if self.running and self.worker is not None and self.worker.is_alive():
            log_print("等待后台任务退出...")
            # 等它把浏览器关掉、图片/PDF落盘完再退出，别留一个孤儿Chrome进程；
            # 但也不能无限等——后台卡住时窗口必须还能关掉
            self._close_deadline = time.time() + 15
            self.root.after(200, self._close_when_worker_stops)
        else:
            self.root.destroy()

    def _close_when_worker_stops(self):
        if not self.worker.is_alive() or time.time() > self._close_deadline:
            self.root.destroy()
            return
        self.root.after(200, self._close_when_worker_stops)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
