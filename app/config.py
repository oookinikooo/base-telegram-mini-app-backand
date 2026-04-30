from dotenv import find_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", env_file=find_dotenv())

    TOKEN: str
    SECRET_KEY: str


config = Settings()
