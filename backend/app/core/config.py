import os


class Settings:
    # ---------------------------------------------------------
    # Application
    # ---------------------------------------------------------

    APP_NAME: str = os.getenv(
        "APP_NAME",
        "Security SaaS API",
    )

    APP_VERSION: str = os.getenv(
        "APP_VERSION",
        "1.0.0",
    )

    ENVIRONMENT: str = os.getenv(
        "ENVIRONMENT",
        "development",
    )

    DEBUG: bool = os.getenv(
        "DEBUG",
        "false",
    ).lower() == "true"

    # ---------------------------------------------------------
    # Database
    # ---------------------------------------------------------

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://security:security_password@postgres:5432/security_saas",
    )

    # Row-Level Security (RLS) — defense-in-depth, preparation only.
    # When false (default), the RLS helper is a no-op and application
    # authorization remains authoritative. No table has RLS enabled yet.
    RLS_ENABLED: bool = os.getenv("RLS_ENABLED", "false").lower() == "true"

    # RBAC strict mode — when true, missing project membership is DENIED for all projects.
    # When false (default, transitional), projects without explicit memberships use org fallback
    # (member → analyst, org_admin → project_admin) for backward compat. New projects always
    # get explicit membership for creator and are strict when they have at least one explicit row.
    RBAC_STRICT_MODE: bool = os.getenv("RBAC_STRICT_MODE", "false").lower() == "true"

    # Audit logging — metadata size limit to prevent storage DoS
    AUDIT_METADATA_MAX_BYTES: int = int(os.getenv("AUDIT_METADATA_MAX_BYTES", "4096"))

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        "change-this-in-production",
    )

    JWT_ALGORITHM: str = os.getenv(
        "JWT_ALGORITHM",
        "HS256",
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv(
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            "60",
        )
    )

    AUTH_BOOTSTRAP_EMAIL: str = os.getenv(
        "AUTH_BOOTSTRAP_EMAIL",
        "",
    ).strip()

    AUTH_BOOTSTRAP_PASSWORD: str = os.getenv(
        "AUTH_BOOTSTRAP_PASSWORD",
        "",
    )

    AUTH_BOOTSTRAP_ORG_NAME: str = os.getenv(
        "AUTH_BOOTSTRAP_ORG_NAME",
        "Organization",
    ).strip() or "Organization"

    # ---------------------------------------------------------
    # Redis
    # ---------------------------------------------------------

    REDIS_URL: str = os.getenv(
        "REDIS_URL",
        "redis://redis:6379/0",
    )

    # ---------------------------------------------------------
    # RabbitMQ / Celery
    # ---------------------------------------------------------

    RABBITMQ_URL: str = os.getenv(
        "RABBITMQ_URL",
        "amqp://guest:guest@rabbitmq:5672//",
    )

    CELERY_BROKER_URL: str = os.getenv(
        "CELERY_BROKER_URL",
        RABBITMQ_URL,
    )

    CELERY_RESULT_BACKEND: str = os.getenv(
        "CELERY_RESULT_BACKEND",
        REDIS_URL,
    )

    # ---------------------------------------------------------
    # API / CORS
    # ---------------------------------------------------------

    FRONTEND_URL: str = os.getenv(
        "FRONTEND_URL",
        "http://localhost:3000",
    )

    # ---------------------------------------------------------
    # Docker
    # ---------------------------------------------------------

    DOCKER_HOST: str = os.getenv(
        "DOCKER_HOST",
        "tcp://docker-socket-proxy:2375",
    )

    # ---------------------------------------------------------
    # Scanner configuration
    # ---------------------------------------------------------

    NMAP_IMAGE: str = os.getenv(
        "NMAP_IMAGE",
        "vapt-tool-nmap",
    )

    NUCLEI_IMAGE: str = os.getenv(
        "NUCLEI_IMAGE",
        "vapt-tool-nuclei",
    )

    SCANNER_MAX_ATTEMPTS: int = int(
        os.getenv(
            "SCANNER_MAX_ATTEMPTS",
            "2",
        )
    )

    # ---------------------------------------------------------
    # External security intelligence
    # ---------------------------------------------------------

    NVD_API_KEY: str = os.getenv(
        "NVD_API_KEY",
        "",
    )

    SHODAN_API_KEY: str = os.getenv(
        "SHODAN_API_KEY",
        "",
    )

    CENSYS_API_ID: str = os.getenv(
        "CENSYS_API_ID",
        "",
    )

    CENSYS_API_SECRET: str = os.getenv(
        "CENSYS_API_SECRET",
        "",
    )

    # ---------------------------------------------------------
    # SCA
    # ---------------------------------------------------------

    SCA_VULNERABILITY_PROVIDER: str = os.getenv(
        "SCA_VULNERABILITY_PROVIDER",
        "osv" if os.getenv("ENVIRONMENT", "development").lower() == "production" else "fixture",
    ).lower()

    # ---------------------------------------------------------
    # AI
    # ---------------------------------------------------------

    OPENAI_API_KEY: str = os.getenv(
        "OPENAI_API_KEY",
        "",
    )

    OPENROUTER_API_KEY: str = os.getenv(
        "OPENROUTER_API_KEY",
        "",
    )

    AI_MODEL: str = os.getenv(
        "AI_MODEL",
        "",
    )

    # ---------------------------------------------------------
    # Scanner Control Plane
    # ---------------------------------------------------------

    SCANNER_CONTROL_PLANE_ENABLED: bool = os.getenv("SCANNER_CONTROL_PLANE_ENABLED", "true").lower() == "true"
    SCANNER_HEALTH_CHECK_TIMEOUT: int = int(os.getenv("SCANNER_HEALTH_CHECK_TIMEOUT", "30"))
    SCANNER_CANARY_ENABLED: bool = os.getenv("SCANNER_CANARY_ENABLED", "true").lower() == "true"
    SCANNER_CANARY_HEALTH_THRESHOLD: int = int(os.getenv("SCANNER_CANARY_HEALTH_THRESHOLD", "1"))
    SCANNER_ALLOWED_REGISTRIES: str = os.getenv("SCANNER_ALLOWED_REGISTRIES", "")
    SCANNER_AUTO_UPDATE_ENABLED: bool = os.getenv("SCANNER_AUTO_UPDATE_ENABLED", "false").lower() == "true"

    # ---------------------------------------------------------
    # Connectors (Phase 11)
    # ---------------------------------------------------------
    CONNECTOR_ENCRYPTION_KEY: str = os.getenv("CONNECTOR_ENCRYPTION_KEY", "")
    MAX_REPO_SIZE_MB: int = int(os.getenv("MAX_REPO_SIZE_MB", "500"))
    MAX_CLOUD_RESOURCES: int = int(os.getenv("MAX_CLOUD_RESOURCES", "500"))
    WEBHOOK_MAX_PAYLOAD_BYTES: int = int(os.getenv("WEBHOOK_MAX_PAYLOAD_BYTES", str(1024 * 1024)))


settings = Settings()