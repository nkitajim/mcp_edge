import json
import re
import requests
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastmcp import FastMCP, Context
import jwt
from jwt import PyJWKClient

# ========= 設定読込 =========
with open("config.json", "r") as f:
    CONFIG = json.load(f)

AUTH0_DOMAIN: str = CONFIG["auth0_domain"]
EDGE_CLIENT_ID: str = CONFIG["edge_client_id"]
EDGE_CLIENT_SECRET: str = CONFIG["edge_client_secret"]
TOOLS_CFG: Dict[str, Dict[str, str]] = CONFIG["tools"]

ISSUER = f"https://{AUTH0_DOMAIN}/"
JWKS_URL = f"{ISSUER}.well-known/jwks.json"
_jwks_client = PyJWKClient(JWKS_URL)

# ========= JWT 正式検証（audience 可変に対応） =========
def verify_edge_token(token: str, audience: str) -> Dict[str, Any]:
    """
    Auth0 JWT を正式検証:
    - RS256 署名を JWKS で検証
    - iss, aud, exp を検証
    """
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=ISSUER,
        )
        # exp は jwt.decode で検証済みだが念のため
        exp = payload.get("exp")
        if exp is None or datetime.fromtimestamp(exp, tz=timezone.utc) <= datetime.now(tz=timezone.utc):
            raise ValueError("Token expired")
        return payload
    except Exception as e:
        # FastMCP 側のエラー表示をわかりやすく
        raise RuntimeError(f"Auth failed for audience='{audience}': {e}")

# ========= STS / OBO: Edgeトークン → ツールAudienceのアクセストークン =========
def exchange_token_via_sts(edge_token: str, target_audience: str, scope: Optional[str] = None) -> str:
    """
    Auth0 のトークン交換 (JWT Bearer/OBO) を使用して、
    Edge 認証トークンをツール Audience のアクセストークンに再発行。
    """
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": EDGE_CLIENT_ID,
        "client_secret": EDGE_CLIENT_SECRET,
        "assertion": edge_token,
        "audience": target_audience,
    }
    if scope:
        data["scope"] = scope

    resp = requests.post(f"https://{AUTH0_DOMAIN}/oauth/token", data=data, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"STS token exchange failed for audience='{target_audience}': {resp.status_code} {resp.text}")
    return resp.json()["access_token"]

# ========= ユーティリティ =========
def _slugify_path(path: str) -> str:
    # /users/{id}/posts -> users_id_posts
    s = re.sub(r"[{}]+", "", path)
    s = re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_")
    return s or "root"

def _fill_path(path_template: str, path_params: Dict[str, Any]) -> str:
    # /pets/{petId} の {petId} を置換
    def repl(m):
        key = m.group(1)
        if key not in path_params:
            raise ValueError(f"Missing path param: {key}")
        return str(path_params[key])
    return re.sub(r"{([^}]+)}", repl, path_template)

# ========= MCP サーバ =========
mcp = FastMCP("edge-mcp")

def load_openapi_and_register_tools() -> None:
    """
    各 OpenAPI をロードし、operation ごとにツールを動的登録。
    - kwargs は使わず、明示的引数 (token, path_params, query, body, headers) を定義
    - audience はツールごとに固定し、検証＆STSも audience 毎に実施
    """
    for tool_name, cfg in TOOLS_CFG.items():
        openapi_url = cfg["openapi_url"]
        audience     = cfg["audience"]

        spec = requests.get(openapi_url, timeout=30).json()
        servers = spec.get("servers", [{"url": ""}])
        if not servers or not servers[0].get("url"):
            raise RuntimeError(f"[{tool_name}] OpenAPI servers[0].url が未設定です")
        base_url = servers[0]["url"].rstrip("/")

        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, op in methods.items():
                if not isinstance(op, dict):
                    continue
                operation_id = op.get("operationId")
                summary = op.get("summary") or op.get("description") or f"{method.upper()} {path}"
                # ツール名: <tool>.<operationId or method_path>
                tool_id_part = operation_id or f"{method}_{_slugify_path(path)}"
                tool_full_name = f"{tool_name}.{tool_id_part}"

                # クロージャ late-binding 回避のためデフォルト引数に束縛
                _method = method.upper()
                _path_tmpl = path
                _aud = audience
                _summary = summary
                _base_url = base_url

                @mcp.tool(name=tool_full_name, description=f"[aud={_aud}] {_summary}")
                def _tool(
                    context: Context,
                    token: str,
                    path_params: Optional[Dict[str, Any]] = None,
                    query: Optional[Dict[str, Any]] = None,
                    body: Optional[Dict[str, Any]] = None,
                    headers: Optional[Dict[str, str]] = None
                ):
                    """
                    自動生成ツール:
                    - token: EdgeのJWT（このツールのaudienceで検証）
                    - path_params: パスパラメータ {id} 等を埋める辞書
                    - query: ?a=1&b=2 のクエリ
                    - body: JSON ボディ（POST/PUT/PATCH 等）
                    - headers: 追加ヘッダ
                    """
                    # 1) ツール固有 audience で JWT を **検証**
                    verify_edge_token(token, _aud)

                    # 2) STS で ツールAudience 用 Access Token を **再発行**
                    tool_access_token = exchange_token_via_sts(token, _aud)

                    # 3) HTTP 呼び出し
                    url_path = _fill_path(_path_tmpl, path_params or {})
                    url = f"{_base_url}{url_path}"
                    req_headers = {"Authorization": f"Bearer {tool_access_token}", "Accept": "application/json"}
                    if body is not None:
                        req_headers.setdefault("Content-Type", "application/json")
                    if headers:
                        req_headers.update(headers)

                    resp = requests.request(
                        _method,
                        url,
                        params=(query or None),
                        json=(body if _method not in ("GET", "DELETE") else None),
                        headers=req_headers,
                        timeout=60
                    )

                    # 4) 結果を返却（JSON優先）
                    ct = resp.headers.get("Content-Type", "")
                    try:
                        data = resp.json() if "application/json" in ct else resp.text
                    except Exception:
                        data = resp.text

                    return {
                        "status": resp.status_code,
                        "url": url,
                        "method": _method,
                        "audience": _aud,
                        "response": data
                    }

# 起動時に OpenAPI を読み込んでツール登録
load_openapi_and_register_tools()

if __name__ == "__main__":
    mcp.run()

