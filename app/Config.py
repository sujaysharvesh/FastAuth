from pydantic_settings import BaseSettings

class Setting(BaseSettings):
    APP_CLIENT_ID : str
    PROJECT_ID : str
    ZITADEL_HTTP_URL: str
    CLIENT_ID : str
    PRE_LOGIN_REDIRECT_URI: str
    SESSION_SECRET_KEY: str
    ZITADEL_AUTH_URL: str
    ZITADEL_USERINFO_URL: str
    POST_LOGIN_REDIRECT_URI: str
    PORT: int
    
    
    class Config:
        env_file = ".env"
        extra = "ignore"
        

Config = Setting()
