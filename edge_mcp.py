import os, json, time, base64, hashlib
from typing import Any, Dict, Optional
import httpx, yaml
from cachetools import TTLCache
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# === Load config ===
with open("config.yaml", "r") as f:
    CFG = yaml.safe_load(f)

AUTH0_DOMAIN = CFG["auth0"]["domain"]
CLIENT_ID = os.getenv("AUTH0_CLIENT_ID", CFG["auth0"].get("client_id"))
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", CFG["auth0"].get("client_secret"))
USE_DPOP = CFG["auth0"].get("use_dpop", False)
TOKEN_TTL = int(CFG["auth0"].get("token_cache_ttl_sec", 120))

TOOLS = CFG["tools"]  # dict: {tool_name: {openapi, audience, scopes}}

mcp = FastMCP("edge-mcp")

# Simple in-memory registry for OpenAPI specs (per tool)
OPENAPIS: Dict[str, Dict[str, Any]] = {}

# Token cache: key=(aud, scopes tuple) -> token string (TTL)
TOKEN_CACHE = TTLCache(maxsize=256, ttl=TOKEN_TTL)

class DescribeInput(BaseModel):
    tool: str = Field(..., description="登録名（例: git, db）")
    openapi_url: Optional[str] = Field(None, description="明示URL。省略でconfig.yamlのtools.<tool>.openapi")

class InvokeInput(BaseModel):
    tool: str = Field(..., description="呼び出すツール名（configのキー）")
    # operationの指定は operationId があればそれ優先。無ければ path + method を使う
    operation_id: Optional[str] = Field(None, description="OpenAPIのoperationId")
    path: Optional[str] = Field(None, description="OpenAPIのパス（例: /repos/{owner}/{repo}/branches）")
    method: Optional[str] = Field(None, description="HTTPメソッド（GET/POST/PUT/DELETE...）")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="query/path パラメータ")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="追加ヘッダ（必要なら）")
    body: Optional[Any] = Field(None, description="リクエストボディ(JSON)")

def _hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:8]

async def fetch_openapi(url: str) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()

def pick_operation(spec: Dict[str, Any], operation_id: Optional[str], path: Optional[str], method: Optional[str]):
    if operation_id:
        # search by operationId
        for p, item in spec.get("paths", {}).items():
            for m, op in item.items():
                if isinstance(op, dict) and op.get("operationId") == operation_id:
                    return p, m.lower(), op
        raise ValueError(f"operationId={operation_id} が見つかりません")
    if path and method:
        op = spec.get("paths", {}).get(path, {}).get(method.lower())
        if not op:
            raise ValueError(f"{method} {path} が見つかりません")
        return path, method.lower(), op
    raise ValueError("operationId か（path+method）の指定が必要です")

async def get_tool_token(audience: str, scopes: Optional[list[str]]) -> str:
    scope_str = " ".join(scopes or [])
    cache_key = (audience, scope_str)
    tok = TOKEN_CACHE.get(cache_key)
    if tok:
        return tok

    token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "audience": audience,
    }
    if scope_str:
        payload["scope"] = scope_str

    headers = {"Content-Type": "application/json"}
    # ここでDPoPを使う場合は dpop ヘッダの生成を実装（省略可）
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(token_url, json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
        access_token = data["access_token"]
        # 短命前提だが、TTLCacheに格納
        TOKEN_CACHE[cache_key] = access_token
        return access_token

@mcp.tool(name="describe", description="OpenAPIを取得してツールを登録（内部レジストリ更新）")
async def describe(input: DescribeInput) -> dict:
    name = input.tool
    cfg = TOOLS.get(name)
    if not cfg:
        raise ValueError(f"tools.{name} が config.yaml にありません")

    url = input.openapi_url or cfg["openapi"]
    spec = await fetch_openapi(url)
    OPENAPIS[name] = spec

    # 主要エンドポイントのサマリを返す
    ops = []
    for p, item in spec.get("paths", {}).items():
        for m, op in item.items():
            if not isinstance(op, dict):
                continue
            ops.append({
                "operationId": op.get("operationId"),
                "method": m.upper(),
                "path": p,
                "summary": op.get("summary"),
            })
    return {"tool": name, "openapi_url": url, "operations": ops[:50], "count": len(ops)}

@mcp.tool(name="invoke_api", description="登録済みOpenAPIを使って任意の操作を呼び出す")
async def invoke_api(input: InvokeInput) -> dict:
    name = input.tool
    cfg = TOOLS.get(name)
    if not cfg:
        raise ValueError(f"tools.{name} が config.yaml にありません")
    spec = OPENAPIS.get(name)
    if not spec:
        raise ValueError(f"{name} は未登録です。先に describe を呼んでください")

    path, method, op = pick_operation(spec, input.operation_id, input.path, input.method)

    # パスパラメータを埋め込み
    real_path = path
    for k, v in (input.params or {}).items():
        placeholder = "{%s}" % k
        if placeholder in real_path:
            real_path = real_path.replace(placeholder, str(v))

    # ベースURLの決定（servers[0].url を使う簡易実装）
    servers = spec.get("servers", [])
    if not servers:
        raise ValueError("OpenAPIにservers定義がありません（base URL不明）")
    base_url = servers[0]["url"].rstrip("/")

    # Auth0からツール専用トークン取得
    token = await get_tool_token(cfg["audience"], cfg.get("scopes"))

    # リクエスト生成
    url = f"{base_url}{real_path}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    headers.update(input.headers or {})

    query = {}
    # query パラメータは path パラメータ以外を詰める（簡易）
    for k, v in (input.params or {}).items():
        if "{%s}" % k not in path:
            query[k] = v

    async with httpx.AsyncClient(timeout=30) as client:
        method_fn = getattr(client, method.lower())
        r = await method_fn(url, params=query or None,
                            json=input.body if method.lower() != "get" else None,
                            headers=headers)
        # 4xx/5xxをエラーにしつつレスポンスを返却
        content_type = r.headers.get("Content-Type", "")
        try:
            data = r.json()
        except Exception:
            data = r.text
        if r.is_error:
            return {"status": r.status_code, "error": True, "url": url, "response": data}
        return {"status": r.status_code, "url": url, "response": data}

if __name__ == "__main__":
    # stdio / SSE どちらでも起動可能（ホスト側に合わせて）
    mcp.run()
