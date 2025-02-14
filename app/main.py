from fastapi import FastAPI
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from app.Auth.dependency import zitadel_auth
from app.Config import Config
from app.Auth.router import Auth_Router
from app.middleware import register_middleware

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

register_middleware(app)

@app.get("/")
async def Home():
    return JSONResponse("Hello word")

app.include_router(Auth_Router, prefix="/api")