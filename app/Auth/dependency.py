from pydantic import HttpUrl
from fastapi import Depends, Request, Security, HTTPException, Response
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import DefaultZitadelUser
from fastapi_zitadel_auth.exceptions import ForbiddenException
from app.Config import Config
import httpx


zitadel_auth = ZitadelAuth(
    issuer_url= Config.ZITADEL_HTTP_URL,
    project_id= Config.PROJECT_ID,
    app_client_id= Config.APP_CLIENT_ID,
    allowed_scopes={
        "openid": "OpenID Connect",
        "email": "Email",
        "profile": "Profile",
        "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
        "urn:zitadel:iam:org:projects:roles": "Roles",
    }
)


async def _extract_access_token(request: Request, code_verifier: str):
    # ZITADEL token endpoint
    token_url = f"{zitadel_auth.issuer_url}/oauth/v2/token"

    # Extract the authorization code from the request
    code = request.query_params.get("code")
    if not code:
        raise ValueError("Authorization code is missing")

    # Prepare the request payload
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": Config.APP_CLIENT_ID,
        "redirect_uri": Config.PRE_LOGIN_REDIRECT_URI,
        "code_verifier": code_verifier  # Include the code_verifier
    }
    # Send the request to ZITADEL
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=payload)
        response.raise_for_status()  # Raise an error for bad responses
        return response.json()


async def Validate_is_admin_user(request: Request):
    # Retrieve user info from session
    user_info = request.session.get("user")

    if not user_info:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Debug: Print user info
    print(f"User Info: {user_info}")

    # Extract roles
    roles = user_info.get("urn:zitadel:iam:org:project:roles", {})
    
    # Check if user has admin role
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="User is not an admin")

    # Store user info in request state for further use
    request.state.user = user_info
    return user_info

async def validate_scope(request: Request):
    user_info = request.session.get("user")

    if not user_info:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Debug: Print user info
    print(f"User Info: {user_info}")

    # Extract scopes from user roles
    user_scopes = user_info.get("urn:zitadel:iam:org:project:roles", {}).keys()
    
    if "scope1" not in user_scopes:
        raise HTTPException(status_code=403, detail="Missing required scope: scope1")

    return user_info