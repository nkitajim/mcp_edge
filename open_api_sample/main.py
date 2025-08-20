import os
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt   # PyJWT
import httpx

from pydantic import BaseModel, Field

app = FastAPI(
    title="mcp edge api samples",
    version="1.0.0",
    openapi_tags=[
        {
            "name": "private",
            "description": "privateの操作を行う。",
        },
        {
            "name": "user",
            "description": "user名を取得する",
        },
    ],
)

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "dev-2gxxai0tg1h7p4vm.us.auth0.com")
API_AUDIENCE = os.getenv("API_AUDIENCE", "https://dev-2gxxai0tg1h7p4vm.us.auth0.com/api/v2/")
ALGORITHMS = ["RS256"]

security = HTTPBearer()
jwks_cache: Optional[dict] = None


async def get_jwks():
    global jwks_cache
    if jwks_cache is None:
        url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)
            resp.raise_for_status()
            jwks_cache = resp.json()
    return jwks_cache


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    jwks = await get_jwks()
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
    if not rsa_key:
        raise HTTPException(status_code=401, detail="Invalid header")

    try:
        payload = jwt.decode(
            token,
            jwt.algorithms.RSAAlgorithm.from_jwk(rsa_key),
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTClaimsError:
        raise HTTPException(status_code=401, detail="Incorrect claims")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation error: {e}")

    return payload


class User(BaseModel):
    name: str

@app.get("/auth_user/", summary="get auth user", description="return your auth user", tags=["user"])
async def get_auth_user(auth_user: dict = Depends(verify_token)):
    return auth_user

@app.get("/users/{user}", summary="get user", description="return user", tags=["user"], response_model=User)
async def get_user(user:str, auth_user: dict = Depends(verify_token)):
    return {"name": user}
