from pydantic_settings import BaseSettings

class Setting(BaseSettings):
    APP_CLIENT_ID : str
    PROJECT_ID : str
    ZITADEL_HTTP_URL: str
    CLIENT_ID : str
    
    
    class Config:
        env_file = ".env"
        extra = "ignore"
        

Config = Setting()
