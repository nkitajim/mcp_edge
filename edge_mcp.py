import json
import httpx
import jwt
from fastapi import FastAPI, Depends, HTTPException
from mcp.server.fastmcp import FastMCPServer
from mcp.server.fastmcp.tools import tool
from mcp.server.auth import verify_jwt
from typing import Dict, Any
from authlib.integrations.httpx_client import AsyncOAuth2Client

AUTH0_DOMAIN = "your-tenant.auth0.com"
EDGE_AUDIENCE = "https://edge-api.yourcorp.com"
AUTH0_CLIENT_ID = "edge-client-id"
AUTH0_CLIENT_SECRET = "edge-client-secret"

# ツールごとにAudienceを定義
TOOL_AUDIENCES = {
    "hr_api": "https://hr-api.yourcorp.com",
    "crm_api": "https://crm-api.yourcorp.com",
}

# STS (on-behalf-of) フロー
async def get_tool_token(user_token: str, audience: str) -> str:
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
                "audience": audience,
                "assertion": user_token,
                "scope": "openid profile email",
            },
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="STS failed")
        return resp.json()["access_token"]

# OpenAPIからMCPツールを動的生成
async def register_openapi_tools(server: FastMCPServer, api_name: str, openapi_url: str):
    async with httpx.AsyncClient() as client:
        resp = await client.get(openapi_url)
        spec = resp.json()

    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            op_id = op.get("operationId", f"{method}_{path}")
            summary = op.get("summary", "no summary")

            @tool(name=f"{api_name}_{op_id}", description=summary)
            async def dynamic_tool(params: Dict[str, Any], token: str = Depends(verify_jwt)):
                # AudienceごとのSTSトークン発行
                tool_token = await get_tool_token(token, TOOL_AUDIENCES[api_name])

                headers = {"Authorization": f"Bearer {tool_token}"}
                async with httpx.AsyncClient() as client:
                    url = f"{spec['servers'][0]['url']}{path}"
                    resp = await client.request(method.upper(), url, headers=headers, json=params)
                    return resp.json()

            server.register_tool(dynamic_tool)

# MCP Server 初期化
app = FastAPI()
mcp = FastMCPServer(app, title="Edge MCP")

@app.on_event("startup")
async def startup_event():
    await register_openapi_tools(mcp, "hr_api", "https://hr-api.yourcorp.com/openapi.json")
    await register_openapi_tools(mcp, "crm_api", "https://crm-api.yourcorp.com/openapi.json")
