from fastapi import FastAPI
from sentinel.api.webhooks import router as webhook_router


def create_app() -> FastAPI:
    app = FastAPI(title="Sentinel API", version="0.1.0")
    app.include_router(webhook_router, prefix="/webhooks")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
