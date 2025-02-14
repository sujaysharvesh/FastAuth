from fastapi import Depends, Request, Response, APIRouter, HTTPException, Security
from app.Auth.dependency import Validate_is_admin_user, zitadel_auth


Auth_Router = APIRouter()

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