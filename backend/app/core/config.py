from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg2://threatlens:threatlens_dev_password@localhost:5432/threatlens"
    jwt_secret: str = "change-this-demo-secret"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 120
    upload_dir: str = "../storage"
    max_file_size_mb: int = 20
    cors_origins: str = "http://localhost:5173"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
