import hashlib
import logging
from typing import Dict, Tuple, Optional
from ..utils.logger import Logger

try:
    from pyncm.apis.login import GetCurrentLoginStatus, LoginRefreshToken, LoginViaCellphone
    from pyncm import CreateNewSession, GetCurrentSession
    PYNCM_AVAILABLE = True
except ImportError:
    PYNCM_AVAILABLE = False


class AuthService:
    def __init__(self, logger: Logger):
        self.logger = logger
        # pyncm 的 DEBUG 日志会包含登录请求中的密码摘要。
        logging.getLogger("pyncm.api").setLevel(logging.CRITICAL)
        
        if not PYNCM_AVAILABLE:
            self.logger.error("pyncm 库未安装，无法使用登录功能")
            raise ImportError("pyncm 库未安装，请执行 pip install pyncm")
    
    def _hash_password(self, password: str) -> str:
        """将明文密码转换为 MD5 哈希"""
        return hashlib.md5(password.encode()).hexdigest()

    def refresh(self, music_u: str, csrf: str) -> Tuple[bool, Optional[Dict[str, str]]]:
        """使用已有登录态续期；只有接口重新下发登录 Cookie 才视为成功。"""
        if not music_u or not csrf:
            return False, None

        try:
            session = CreateNewSession()
            session.cookies.set("MUSIC_U", music_u, domain=".music.163.com", path="/")
            session.cookies.set("__csrf", csrf, domain=".music.163.com", path="/")
            session.csrf_token = csrf

            issued_cookies = {}

            def collect_cookies(response, **kwargs):
                for cookie in response.cookies:
                    if cookie.name in ("MUSIC_U", "__csrf") and cookie.value and not cookie.is_expired():
                        issued_cookies[cookie.name] = cookie.value

            session.hooks["response"].append(collect_cookies)
            status = GetCurrentLoginStatus(session=session)
            account_id = (status.get("account") or {}).get("id") if isinstance(status, dict) else None
            if not account_id or status.get("code") != 200:
                self.logger.warning("已有Cookie未通过账号验证，无法续期")
                return False, None

            csrf = issued_cookies.get("__csrf") or csrf
            session.csrf_token = csrf
            # 只接受续期接口本次下发的登录Cookie，不使用验证请求已下发的值。
            issued_cookies.clear()
            # 响应正文的 code=200 本身不能证明服务器下发了新的登录 Cookie。
            result = LoginRefreshToken(session=session)
            if not isinstance(result, dict) or result.get("code") != 200 or not issued_cookies.get("MUSIC_U"):
                self.logger.warning("续期接口未重新下发有效的MUSIC_U，未确认续期成功")
                return False, None

            renewed_music_u = issued_cookies["MUSIC_U"]
            renewed_csrf = issued_cookies.get("__csrf") or csrf
            # 使用独立会话验证返回的Cookie，避免请求时仍混用旧Cookie。
            verification = CreateNewSession()
            verification.cookies.set("MUSIC_U", renewed_music_u, domain=".music.163.com", path="/")
            verification.cookies.set("__csrf", renewed_csrf, domain=".music.163.com", path="/")
            verification.csrf_token = renewed_csrf
            verified = GetCurrentLoginStatus(session=verification)
            verified_id = (verified.get("account") or {}).get("id") if isinstance(verified, dict) else None
            if not isinstance(verified, dict) or verified.get("code") != 200 or verified_id != account_id:
                self.logger.warning("续期后Cookie未通过同一账号验证")
                return False, None

            self.logger.info("已有会话续期成功，服务器重新下发的登录Cookie已通过账号验证")
            return True, {"Cookie_MUSIC_U": renewed_music_u, "Cookie___csrf": renewed_csrf}
        except Exception as e:
            self.logger.warning(f"已有会话续期失败（异常类型: {type(e).__name__}）")
            return False, None
        
    def login(self, phone: str, password: str = None, md5_password: str = None) -> Tuple[bool, Optional[Dict[str, str]]]:
        """
        通过手机号和密码登录获取 Cookie
        
        Args:
            phone: 手机号
            password: 明文密码（与md5_password二选一）
            md5_password: MD5加密后的密码（与password二选一）
            
        Returns:
            (成功状态, Cookie字典)
        """
        try:
            self.logger.info(f"尝试使用 pyncm 登录账号: {phone[:3]}****{phone[-4:]}")
            
            # 确定使用哪种密码
            if md5_password:
                password_hash = md5_password
                self.logger.debug("使用提供的MD5密码登录")
            elif password:
                password_hash = self._hash_password(password)
                self.logger.debug("使用明文密码（转换为MD5）登录")
            else:
                self.logger.error("未提供密码，无法登录")
                return False, None
            
            # 使用 pyncm 登录
            result = LoginViaCellphone(phone, passwordHash=password_hash, ctcode=86)
            
            # 检查登录结果
            if result.get("code") != 200:
                self.logger.error("密码登录未成功，未获取新的Cookie")
                return False, None
            
            # 获取当前会话
            session = GetCurrentSession()
            
            # 从会话的 cookies 中获取
            music_u_cookie = session.cookies.get('MUSIC_U')
            csrf_cookie = session.cookies.get('__csrf')
            
            if not music_u_cookie:
                self.logger.error("未能从会话中获取 MUSIC_U cookie")
                return False, None
                
            if not csrf_cookie:
                self.logger.error("未能从会话中获取 __csrf cookie")
                return False, None
            
            # 构建返回的 Cookie 字典
            cookie_dict = {
                "Cookie_MUSIC_U": music_u_cookie,
                "Cookie___csrf": csrf_cookie
            }
            
            self.logger.info("登录成功并获取Cookie")
            
            return True, cookie_dict
            
        except Exception as e:
            error_data = e.args[0] if e.args and isinstance(e.args[0], dict) else {}
            if error_data.get("code") == 8821:
                self.logger.error("网易云要求人工安全验证（8821），自动登录已停止")
            else:
                self.logger.error(f"pyncm 登录失败（异常类型: {type(e).__name__}）")
            return False, None
