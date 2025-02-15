from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager
from app.Auth.dependency import zitadel_auth
from app.Config import Config
from app.Auth.router import Auth_Router
from app.middleware import register_middleware
import os
import uvicorn
import secrets


@asynccontextmanager
async def lifeSpan(app: FastAPI):
    await zitadel_auth.openid_config.load_config()
    yield

app = FastAPI(
    title="fastapi-zitadel-auth demo",
    lifespan=lifeSpan,
    swagger_ui_oauth2_redirect_url="/oauth2-redirect",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": Config.CLIENT_ID,
        "scopes": " ".join(  # defining the pre-selected scope ticks in the Swagger UI
            [
                "openid",
                "profile",
                "email",
                "urn:zitadel:iam:org:projects:roles",
                "urn:zitadel:iam:org:project:id:zitadel:aud",
            ]
        ),
    },
)

#register_middleware(app)
app.add_middleware(
    SessionMiddleware,
    secret_key=Config.SESSION_SECRET_KEY,
    session_cookie="sessionid",
    max_age=3600,  # Ensure session persists (1 hour)
    https_only=True,  # Set to True in production (HTTPS required)
    same_site="lax"  )


@app.get("/")
async def Home():
    return JSONResponse("Hello word")

app.include_router(Auth_Router, prefix="/v1")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)