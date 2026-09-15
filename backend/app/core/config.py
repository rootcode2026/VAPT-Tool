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

    # Row-Level Security (RLS) — defense-in-depth, production default enabled.
    # When true (production default), the RLS helper enforces transaction-local
    # organization/project isolation via set_config; application RBAC remains authoritative.
    # Existing migration i9a0b1c2d3e4 enables RLS on 9 tenant tables; FORCE RLS ensures
    # even table owners cannot bypass policies. Development may still set RLS_ENABLED=false
    # explicitly for SQLite-only tests, but production must use true.
    RLS_ENABLED: bool = os.getenv("RLS_ENABLED", "true").lower() == "true"

    # RBAC strict mode — production default enabled.
    # When true (production default), missing project membership is DENIED for all projects.
    # When false (transitional), projects without explicit memberships use org fallback
    # (member → analyst, org_admin → project_admin) for backward compat. New projects always
    # get explicit membership for creator and are strict when they have at least one explicit row.
    # Hardened to true by default for MMP-1; set RBAC_STRICT_MODE=false only for legacy dev if needed.
    RBAC_STRICT_MODE: bool = os.getenv("RBAC_STRICT_MODE", "true").lower() == "true"

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

    AI_ENABLED: bool = os.getenv("AI_ENABLED", "false").lower() == "true"
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "mock").lower()
    AI_MODEL: str = os.getenv(
        "AI_MODEL",
        "mock-analyst",
    )
    AI_BASE_URL: str = os.getenv("AI_BASE_URL", "")
    AI_API_KEY: str = os.getenv("AI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
    AI_TIMEOUT: int = int(os.getenv("AI_TIMEOUT", "30"))
    AI_MAX_TOKENS: int = int(os.getenv("AI_MAX_TOKENS", "1000"))
    AI_TEMPERATURE: float = float(os.getenv("AI_TEMPERATURE", "0.2"))
    AI_MAX_CONTEXT_FINDINGS: int = int(os.getenv("AI_MAX_CONTEXT_FINDINGS", "20"))
    AI_MAX_CONTEXT_ASSETS: int = int(os.getenv("AI_MAX_CONTEXT_ASSETS", "10"))

    OPENAI_API_KEY: str = os.getenv(
        "OPENAI_API_KEY",
        "",
    )

    OPENROUTER_API_KEY: str = os.getenv(
        "OPENROUTER_API_KEY",
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
    REPOSITORY_PROVIDER_MODE: str = os.getenv("REPOSITORY_PROVIDER_MODE", "mock").lower()
    CLOUD_PROVIDER_MODE: str = os.getenv("CLOUD_PROVIDER_MODE", "mock").lower()
    PROVIDER_TIMEOUT: int = int(os.getenv("PROVIDER_TIMEOUT", "10"))
    SECRET_STORE_MODE: str = os.getenv("SECRET_STORE_MODE", "development").lower()
    MAX_REPOSITORY_CONNECTIONS_PER_PROJECT: int = int(os.getenv("MAX_REPOSITORY_CONNECTIONS_PER_PROJECT", "10"))
    MAX_CLOUD_CONNECTIONS_PER_PROJECT: int = int(os.getenv("MAX_CLOUD_CONNECTIONS_PER_PROJECT", "5"))
    MAX_CONCURRENT_CLOUD_DISCOVERY: int = int(os.getenv("MAX_CONCURRENT_CLOUD_DISCOVERY", "3"))


settings = Settings()