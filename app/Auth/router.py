from fastapi import Depends, Request, Response, APIRouter, HTTPException, Security, status
from fastapi.responses import JSONResponse, RedirectResponse
from app.Auth.dependency import Validate_is_admin_user, zitadel_auth, _extract_access_token, validate_scope
from app.Config import Config
import pkce
import httpx
import logging

Auth_Router = APIRouter()
logger = logging.getLogger(__name__)

@Auth_Router.get("/callback")
async def callback(request: Request):
    try:
        # Extract the authorization code from the request query parameters
        code = request.query_params.get("code")
        print(code)
        if not code:
            raise HTTPException(status_code=400, detail="Authorization code is missing")

        # Retrieve the code_verifier from the session or secure store
        code_verifier = request.session.get("code_verifier")
        if not code_verifier:
            raise HTTPException(status_code=400, detail="Code verifier is missing")

        # Exchange the authorization code for tokens
        token_response = await _extract_access_token(request, code_verifier=code_verifier)

        if not token_response or "access_token" not in token_response:
            raise HTTPException(status_code=400, detail="Invalid token response from Zitadel")
        # Prepare the response
        response = RedirectResponse(url="/v1/current-user")
        
        # Set access token in a secure cookie
        response.set_cookie(
            key="access_token",
            value=token_response["access_token"],
            httponly=True,
            secure=True,  # Ensure this is True in production (HTTPS only)
            samesite="lax"
        )
        
        return response

    except HTTPException as e:
        logger.error("HTTPException: %s", e.detail)
        raise e
    except Exception as e:
        logger.error("Login failed: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed due to an internal error"
        )


@Auth_Router.get("/login")
async def login_redirect(request: Request): 
    
    # Generate PKCE code verifier and challenge
    code_verifier = pkce.generate_code_verifier(length=128)
    code_challenge = pkce.get_code_challenge(code_verifier)

    # Store the code_verifier in session (Ensure session middleware is configured)
    request.session["code_verifier"] = code_verifier
    # Construct the ZITADEL authorization URL
    zitadel_auth_url = (
        f"{Config.ZITADEL_AUTH_URL}"
        f"?client_id={Config.APP_CLIENT_ID}"
        f"&response_type=code"
        f"&scope=openid profile email"
        f"&redirect_uri={Config.PRE_LOGIN_REDIRECT_URI}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return RedirectResponse(url=zitadel_auth_url)

@Auth_Router.get("/logout")
async def logout_user(request: Request, response: Response):
    # Clear session data
    request.session.clear()

    # Delete cookies
    response.delete_cookie("code_verifier", path="/")
    response.delete_cookie("sessionid", path="/")
    response.delete_cookie("access_token", path="/")  

    # Zitadel End Session URL
    zitadel_logout_url = (
        "https://auth-i6b4am.us1.zitadel.cloud/oidc/v1/end_session"
        f"?client_id={Config.APP_CLIENT_ID}"
        f"&post_logout_redirect_uri={Config.POST_LOGIN_REDIRECT_URI}"  # Redirect after logout
    )

    return RedirectResponse(url=zitadel_logout_url)

@Auth_Router.get("/current-user")
async def get_current_user(request: Request):
    # Extract access token from cookies
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Make a request to Zitadel's userinfo endpoint
    async with httpx.AsyncClient() as client:
        response = await client.get(
            Config.ZITADEL_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    # Check if request was successful
    if response.status_code != 200:
        return RedirectResponse(url="/v1/login") 

    return JSONResponse(content=response.json())


@Auth_Router.get(
    "/protected/admin",
    summary="Protected endpoint, requires admin role",
    dependencies=[Security(Validate_is_admin_user)],
)
async def protected_for_admin(Request: Request):
    user = Request.state.user
    return {"message": "Welcome Admin", "user": user["preferred_username"]}


@Auth_Router.get("/protected/scope")
async def protected_by_scope(user: dict = Depends(validate_scope)):
    return {"message": "Hello world!", "user": user}

