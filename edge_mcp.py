import json
import time
import httpx
import jwt
from pathlib import Path
from fastmcp import FastMCP, Context

# === 認証関連（Auth0想定） ===
AUTH0_DOMAIN = "your-tenant.auth0.com"
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
STS_TOKEN_URL = f"https://{AUTH0_DOMAIN}/oauth/token"

# audienceごとにユーザー単位でトークンをキャッシュ
token_cache = {}  # {(user_id, audience): (token, exp)}

def get_token(user_id: str, audience: str) -> str:
    """ユーザーごとにAudience別Access Tokenを取得し、キャッシュ"""
    now = int(time.time())
    key = (user_id, audience)

    if key in token_cache:
        token, exp = token_cache[key]
        if exp > now + 60:  # 期限1分前なら再利用
            return token

    # STSで新しいトークンを取得
    resp = httpx.post(
        STS_TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "audience": audience,
        },
    )
    resp.raise_for_status()
    data = resp.json()
    token = data["access_token"]
    exp = now + data.get("expires_in", 3600)
    token_cache[key] = (token, exp)
    return token


# === MCPサーバ ===
mcp = FastMCP("edge-mcp")

# config.json: OpenAPI定義を複数読み込み
CONFIG_FILE = Path("config.json")

def load_openapi_and_register_tools():
    with open(CONFIG_FILE) as f:
        configs = json.load(f)

    for tool_cfg in configs["tools"]:
        url = tool_cfg["url"]
        audience = tool_cfg["audience"]

        # OpenAPI取得
        resp = httpx.get(url)
        resp.raise_for_status()
        spec = resp.json()

        for path, methods in spec["paths"].items():
            for method, op in methods.items():
                op_id = op.get("operationId") or f"{method}_{path}"
                desc = op.get("description", f"{method.upper()} {path}")

                # ツールを登録
                make_tool(op_id, url, path, method, audience, desc)


def make_tool(op_id: str, base_url: str, path: str, method: str, audience: str, description: str):
    @mcp.tool(name=op_id, description=description)
    def _tool(context: Context, user_id: str, **params):
        """ユーザーごとにAudience別トークンを発行してAPI呼び出し"""
        token = get_token(user_id, audience)
        headers = {"Authorization": f"Bearer {token}"}

        url = f"{base_url}{path}"
        resp = httpx.request(method.upper(), url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()


# === 起動 ===
if __name__ == "__main__":
    load_openapi_and_register_tools()
    mcp.run()
