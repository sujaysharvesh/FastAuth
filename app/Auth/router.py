from fastapi import Depends, Request, Response, APIRouter, HTTPException, Security, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from app.Auth.dependency import Validate_is_admin_user, zitadel_auth
from typing import Annotated


# Configure OAuth2 with ZITADEL
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://your-zitadel-instance/oauth/v2/authorize",
    tokenUrl="https://your-zitadel-instance/oauth/v2/token"
)

Auth_Router = APIRouter()

@Auth_Router.post("/login")
async def login_with_zitadel(
    request: Request,
    code: Annotated[str, Depends(oauth2_scheme)]
):
    """
    Handle ZITADEL login flow
    """
    try:
        # Exchange authorization code for tokens
        token_response = await zitadel_auth.exchange_code_for_token(code)
        
        # Store tokens in session or return them
        request.session["access_token"] = token_response["access_token"]
        request.session["refresh_token"] = token_response["refresh_token"]
        
        return {
            "message": "Login successful",
            "access_token": token_response["access_token"],
            "token_type": token_response["token_type"],
            "expires_in": token_response["expires_in"]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed: " + str(e)
        )

@Auth_Router.get(
    "/protected/admin",
    summary="Protected endpoint, requires admin role",
    dependencies=[Security(Validate_is_admin_user)],
)
async def protected_for_admin(request: Request):
    user = request.state.user
    return {"message": "Hello world!", "user": user}

@Auth_Router.get(
    "/protected/scope",
    summary="Protected endpoint, requires a specific scope",
    dependencies=[Security(zitadel_auth, scopes=["scope1"])],
)
async def protected_by_scope(request: Request):
    user = request.state.user
    return {"message": "Hello world!", "user": user}
