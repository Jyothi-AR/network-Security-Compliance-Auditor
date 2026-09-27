from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sih26155.api.routes.analysis import router as analysis_router
from sih26155.api.routes.history import router as history_router
from sih26155.api.routes.intelligence import router as intelligence_router
from sih26155.api.routes.learning import router as learning_router
from sih26155.api.routes.live import router as live_router
from sih26155.api.routes.reports import router as reports_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create all database tables on startup."""
    from sih26155.storage.database import create_all_tables

    create_all_tables()

    yield


app = FastAPI(
    title="SIH AI Compliance Engine",
    version="0.1.0",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(analysis_router)
app.include_router(live_router)
app.include_router(intelligence_router)
app.include_router(learning_router)
app.include_router(history_router)
app.include_router(reports_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
