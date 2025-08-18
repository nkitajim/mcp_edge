import json
import httpx
from fastapi import FastAPI, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from mcp.server.fastmcp import FastMCPServer
from mcp.server import tool
import inspect
from typing import Any, Dict

# =====================
# 設定
# =====================
AUTH0_DOMAIN = "your-tenant.auth0.com"
API_AUDIENCE = "https://your-api.example.com"
ALGORITHMS = ["RS256"]

OPENAPI_URL = "https://your-api.example.com/openapi.json"

# =====================
# 認証
# =====================
security = HTTPBearer()

async def get_token_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        jwks = httpx.get(jwks_url).json()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/",
            )
            return payload
    except JWTError as e:
        raise Exception("Invalid token") from e
    raise Exception("Authentication failed")

# =====================
# OpenAPI 読み込み & MCP ツール生成
# =====================
def load_openapi_schema() -> Dict[str, Any]:
    resp = httpx.get(OPENAPI_URL)
    resp.raise_for_status()
    return resp.json()

def create_tool_from_operation(path: str, method: str, operation: Dict[str, Any]):
    """operationId ごとに tool 関数を生成"""
    op_id = operation.get("operationId")
    summary = operation.get("summary", f"{method.upper()} {path}")
    parameters = operation.get("parameters", [])

    # パラメータ定義を pydantic のモデル化（ここでは簡易 dict → kwargs）
    async def dynamic_tool(**kwargs):
        async with httpx.AsyncClient() as client:
            url = OPENAPI_URL.replace("/openapi.json", path)
            headers = {"Authorization": f"Bearer {kwargs.pop('token', '')}"}
            response = await client.request(method.upper(), url, params=kwargs, headers=headers)
            return response.json()

    dynamic_tool.__name__ = op_id or f"{method}_{path}"
    dynamic_tool.__doc__ = summary

    return tool(name=op_id or f"{method}_{path}", desc=summary)(dynamic_tool)

# =====================
# MCP サーバ構築
# =====================
mcp = FastMCPServer("edge-mcp")

def register_openapi_tools():
    schema = load_openapi_schema()
    for path, path_item in schema.get("paths", {}).items():
        for method, operation in path_item.items():
            if not isinstance(operation, dict):
                continue
            try:
                t = create_tool_from_operation(path, method, operation)
                mcp.register_tool(t)
            except Exception as e:
                print(f"Failed to register tool for {method.upper()} {path}: {e}")

# =====================
# FastAPI + MCP 起動
# =====================
app = FastAPI()

@app.on_event("startup")
async def startup_event():
    register_openapi_tools()

# FastMCP 用エンドポイント
app.mount("/mcp", mcp.app)
