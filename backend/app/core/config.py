import os


class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://security:security_password@postgres:5432/security_saas",
    )


settings = Settings()