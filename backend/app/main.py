from fastapi import FastAPI

app = FastAPI(
    title="Security SaaS API",
    version="1.0.0",
)


@app.get("/")
async def root():
    return {
        "message": "Security SaaS API is running"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }