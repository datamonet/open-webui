import logging
import uuid
import jwt
import base64
import hmac
import hashlib
import requests
import os


from datetime import datetime, timedelta
import pytz
from pytz import UTC
from typing import Optional, Union, List, Dict

from open_webui.models.users import Users, UserModel

from open_webui.constants import ERROR_MESSAGES
from open_webui.env import (
    WEBUI_SECRET_KEY,
    TRUSTED_SIGNATURE_KEY,
    STATIC_DIR,
    SRC_LOG_LEVELS,
)

from fastapi import BackgroundTasks, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext


logging.getLogger("passlib").setLevel(logging.ERROR)

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["OAUTH"])

SESSION_SECRET = WEBUI_SECRET_KEY
ALGORITHM = "HS256"

##############
# Auth Utils
##############

# This class is from takin.ai - handles user credits for API usage
class UserWithCredits(UserModel):
    extraCredits: float = 0
    subscriptionCredits: float = 0
    subscriptionPurchasedCredits: float = 0


def verify_signature(payload: str, signature: str) -> bool:
    """
    Verifies the HMAC signature of the received payload.
    """
    try:
        expected_signature = base64.b64encode(
            hmac.new(TRUSTED_SIGNATURE_KEY, payload.encode(), hashlib.sha256).digest()
        ).decode()

        # Compare securely to prevent timing attacks
        return hmac.compare_digest(expected_signature, signature)

    except Exception:
        return False


def override_static(path: str, content: str):
    # Ensure path is safe
    if "/" in path or ".." in path:
        log.error(f"Invalid path: {path}")
        return

    file_path = os.path.join(STATIC_DIR, path)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "wb") as f:
        f.write(base64.b64decode(content))  # Convert Base64 back to raw binary


def get_license_data(app, key):
    if key:
        try:
            res = requests.post(
                "https://api.openwebui.com/api/v1/license/",
                json={"key": key, "version": "1"},
                timeout=5,
            )

            if getattr(res, "ok", False):
                payload = getattr(res, "json", lambda: {})()
                for k, v in payload.items():
                    if k == "resources":
                        for p, c in v.items():
                            globals().get("override_static", lambda a, b: None)(p, c)
                    elif k == "count":
                        setattr(app.state, "USER_COUNT", v)
                    elif k == "name":
                        setattr(app.state, "WEBUI_NAME", v)
                    elif k == "metadata":
                        setattr(app.state, "LICENSE_METADATA", v)
                return True
            else:
                log.error(
                    f"License: retrieval issue: {getattr(res, 'text', 'unknown error')}"
                )
        except Exception as ex:
            log.exception(f"License: Uncaught Exception: {ex}")
    return False


bearer_security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return (
        pwd_context.verify(plain_password, hashed_password) if hashed_password else None
    )


def get_password_hash(password):
    return pwd_context.hash(password)
# takin code
use_secure_cookies = os.getenv("ENV") == "prod"
takin_cookie_name = '__Secure-authjs.session-token' if use_secure_cookies else "authjs.session-token"
# takin code：从请求中获取token
def get_token(request: Request) -> str:
    cookie = request.cookies.get(takin_cookie_name)
    return cookie

# takin code：删除用户token
def del_token(response: Response):
    response.delete_cookie(
        key=takin_cookie_name,
        path='/',
        domain='.takin.ai' if use_secure_cookies else None,
        secure=use_secure_cookies,
        httponly=True,
        samesite='lax'
    )
    return response
    
def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
        payload.update({"exp": expire})

    encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, SESSION_SECRET, algorithms=[ALGORITHM])
        return decoded
    except Exception:
        return None


def extract_token_from_auth_header(auth_header: str):
    return auth_header[len("Bearer ") :]


def create_api_key():
    key = str(uuid.uuid4()).replace("-", "")
    return f"sk-{key}"


def get_http_authorization_cred(auth_header: Optional[str]):
    if not auth_header:
        return None
    try:
        scheme, credentials = auth_header.split(" ")
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
    except Exception:
        return None


def get_current_user(
    request: Request,
    background_tasks: BackgroundTasks,
    auth_token: HTTPAuthorizationCredentials = Depends(bearer_security),
):
    """takin code：用户认证装饰器
    
    处理两种认证方式：
    1. Takin token: 包含完整的用户信息和积分信息
    2. WebUI token: 仅包含用户ID
    
    Args:
        request: FastAPI请求对象
        background_tasks: 后台任务队列
        auth_token: HTTP认证凭证
        
    Returns:
        UserWithCredits: 包含用户信息和积分信息的用户对象
        
    Raises:
        HTTPException: 当认证失败时
    """
    # 1. 获取tokens
    webui_token = None
    takin_token = get_token(request)  # 从cookie中获取takin token
    
    # 获取webui token的优先级：Authorization header > cookies
    if auth_token is not None:
        webui_token = auth_token.credentials
        
    if webui_token is None and "token" in request.cookies:
        webui_token = request.cookies.get("token")
    
    # 2. 验证takin用户信息
    takin_user = None
    if takin_token:
        response = requests.get(
            f'{os.getenv("PUBLIC_TAKIN_API_URL", "http://127.0.0.1:3000")}/api/external/user',
            headers={'Authorization': f'Bearer {takin_token}'}
        )
        if not response.ok:
            return None
        takin_user = response.json().get('data')
    
    # 3. 处理API key的特殊情况
    # auth by api key
    if webui_token is not None and webui_token.startswith("sk-"):
        if not request.state.enable_api_key:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED
            )

        if request.app.state.config.ENABLE_API_KEY_ENDPOINT_RESTRICTIONS:
            allowed_paths = [
                path.strip()
                for path in str(
                    request.app.state.config.API_KEY_ALLOWED_ENDPOINTS
                ).split(",")
            ]

            # Check if the request path matches any allowed endpoint.
            if not any(
                request.url.path == allowed
                or request.url.path.startswith(allowed + "/")
                for allowed in allowed_paths
            ):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED
                )

        return get_current_user_by_api_key(webui_token)
    
    # 4. token解析和用户验证
    try:
        user_data = None
        if takin_token:  # 优先使用takin token
            user_data = decode_token(takin_token)
            user = Users.get_user_by_email(user_data["email"])
        elif webui_token:  # 降级使用webui token
            user_data = decode_token(webui_token)
            user = Users.get_user_by_id(user_data["id"])
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No valid token provided"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format"
        )
    
    # 5. 验证用户是否存在
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN
        )
    
    # 6. 异步更新用户活动时间
    if background_tasks:
        background_tasks.add_task(Users.update_user_last_active_by_id, user.id)
    
    # 7. 更新用户头像并返回带积分信息的用户对象
    if takin_user:
        user.profile_image_url = takin_user.get("image", user.profile_image_url)
    
    return UserWithCredits(
        **user.model_dump(),
        extraCredits=takin_user.get("extraCredits", 0) if takin_user else 0,
        subscriptionCredits=takin_user.get("subscriptionCredits", 0) if takin_user else 0,
        subscriptionPurchasedCredits=takin_user.get("subscriptionPurchasedCredits", 0) if takin_user else 0
    )


def get_current_user_by_api_key(api_key: str):
    user = Users.get_user_by_api_key(api_key)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )
    else:
        Users.update_user_last_active_by_id(user.id)

    return user


def get_verified_user(user=Depends(get_current_user)):
    if user.role not in {"user", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


def get_admin_user(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user
