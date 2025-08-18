import os
import yaml
import httpx
from typing import Dict, Any
from fastapi import FastAPI, Depends, HTTPException
from mcp.server.fastmcp import FastMCPServer
from mcp.server.fastmcp.tools import tool
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from authlib.integrations.httpx_client import AsyncOAuth2Client

# =====================
# Load config
# =====================
with open("config.yaml", "r") as f:
    CFG = yaml.safe_load(f)

AUTH0_DOMAIN = CFG["auth0"]["domain"]
AUTH0_CLIENT_ID = CFG["auth0"]["client_id"]
AUTH0_CLIENT_SECRET = CFG["auth0"]["client_secret"]
EDGE_AUDIENCE = CFG["auth0"]["edge_audience"]

TOOLS_CFG = CFG["tools"]

security = HTTPBearer()

# =====================
# Auth0 JWT 検証（Edge Audience）
# =====================
async def get_user_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    # 本番では JWKS 検証を実装
    return token  # 簡易: token をそのまま返す

# =====================
# STS / OBO でツールAudience用トークン取得
# =====================
async def get_tool_token(user_token: str, tool_audience: str) -> str:
    async with AsyncOAuth2Client(
        client_id=AUTH0_CLIENT_ID,
        client_secret=AUTH0_CLIENT_SECRET,
    ) as client:
        resp = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "client_id": AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "assertion": user_token,
                "audience": tool_audience,
                "scope": "openid profile email",
            },
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail=f"STS failed: {resp.text}")
        return resp.json()["access_token"]

# =====================
# OpenAPI -> MCP Tool 動的生成
# =====================
async def register_openapi_tools(server: FastMCPServer):
    for tool_name, cfg in TOOLS_CFG.items():
        openapi_url = cfg["openapi"]
        audience = cfg["audience"]

        async with httpx.AsyncClient() as client:
            r = await client.get(openapi_url)
            r.raise_for_status()
            spec = r.json()

        for path, methods in spec.get("paths", {}).items():
            for method, operation in methods.items():
                if not isinstance(operation, dict):
                    continue
                op_id = operation.get("operationId", f"{method}_{path}")
                summary = operation.get("summary", f"{method.upper()} {path}")

                @tool(name=f"{tool_name}_{op_id}", description=summary)
                async def dynamic_tool(params: Dict[str, Any], token: str = Depends(get_user_token), _aud=audience, _path=path, _method=method):
                    # ツールAudience用の短命トークンをSTSで取得
                    tool_token = await get_tool_token(token, _aud)
                    headers = {"Authorization": f"Bearer {tool_token}"}
                    url = f"{spec['servers'][0]['url']}{_path}"
                    async with httpx.AsyncClient() as client:
                        resp = await client.request(_method.upper(), url, headers=headers, json=params)
                        try:
                            return resp.json()
                        except Exception:
                            return {"status": resp.status_code, "text": resp.text}

                server.register_tool(dynamic_tool)

# =====================
# MCP サーバ起動
# =====================
app = FastAPI()
mcp = FastMCPServer(app, title="Edge MCP")

@app.on_event("startup")
async def startup_event():
    await register_openapi_tools(mcp)

app.mount("/mcp", mcp.app)

