import os
from pydantic_settings import BaseSettings




class Settings(BaseSettings):
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:password@localhost:5432/miniauth")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key")  
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  
    API_KEY_SALT: str = os.getenv("API_KEY_SALT", "your-api-key-salt")
                  

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"



# Global settings instance
settings = Settings()