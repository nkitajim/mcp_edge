import yaml
import httpx
from typing import Dict, Any
from fastapi import FastAPI, Depends, HTTPException, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from authlib.integrations.httpx_client import AsyncOAuth2Client
from mcp.server.fastmcp import FastMCP

from jwt import PyJWKClient
from datetime import datetime

# =====================
# config
# =====================
with open("config.yaml", "r") as f:
    CFG = yaml.safe_load(f)

AUTH0_DOMAIN = CFG["auth0"]["domain"]
AUTH0_CLIENT_ID = CFG["auth0"]["client_id"]
AUTH0_CLIENT_SECRET = CFG["auth0"]["client_secret"]
EDGE_AUDIENCE = CFG["auth0"]["edge_audience"]
TOOLS_CFG = CFG["tools"]

# JWKS クライアントを作成
ISSUER = f"https://{AUTH0_DOMAIN}/"
jwks_url = f"{ISSUER}.well-known/jwks.json"
jwks_client = PyJWKClient(jwks_url)

security = HTTPBearer()

# =====================
# Edge Audience トークン検証
# =====================
async def verify_edge_token(token: str) -> dict:
    """
    Auth0 JWT トークンを正式に検証する
    - 署名検証
    - aud, iss チェック
    - exp チェック
    """
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=EDGE_AUDIENCE,
            issuer=ISSUER,
        )

        # 追加で必要なら role などをチェック
        if "sub" not in payload:
            raise HTTPException(status_code=401, detail="Invalid token: sub missing")

        # exp 自動検証されるが、念のため確認
        exp = payload.get("exp")
        if exp is None or datetime.utcfromtimestamp(exp) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Token expired")

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTClaimsError as e:
        raise HTTPException(status_code=401, detail=f"Invalid claims: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

# =====================
# STS/OBO でツール Audience 用トークン取得
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
async def register_openapi_tools(server: FastMCP):
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

                async def dynamic_tool(params: Dict[str, Any], token: str = Depends(get_user_token), _aud=audience, _path=path, _method=method, _spec=spec):
                    tool_token = await get_tool_token(token, _aud)
                    headers = {"Authorization": f"Bearer {tool_token}"}
                    url = f"{_spec['servers'][0]['url']}{_path}"
                    async with httpx.AsyncClient() as client:
                        resp = await client.request(_method.upper(), url, headers=headers, json=params)
                        try:
                            return resp.json()
                        except Exception:
                            return {"status": resp.status_code, "text": resp.text}

                # FastMCP に直接登録
                server.register_tool(dynamic_tool, name=f"{tool_name}_{op_id}", description=summary)

# =====================
# FastAPI + MCP
# =====================
app = FastAPI()
mcp = FastMCP(app, title="Edge MCP")  # ここで FastAPI app をラップする

@app.on_event("startup")
async def startup_event():
    await register_openapi_tools(mcp)

# ※ app.mount("/mcp", mcp.app) は不要
# MCP エンドポイントは自動で FastAPI app に組み込まれる
