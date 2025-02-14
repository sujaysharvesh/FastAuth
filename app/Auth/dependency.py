from pydantic import HttpUrl
from fastapi import Depends
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import DefaultZitadelUser
from fastapi_zitadel_auth.exceptions import ForbiddenException
from app.Config import Config


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

async def Validate_is_admin_user(user: DefaultZitadelUser = Depends(zitadel_auth)) -> None:
    required_role = "admin"
    if required_role not in user.claims.project_roles.keys():
        raise ForbiddenException(f"User does not have role assigned: {required_role}")