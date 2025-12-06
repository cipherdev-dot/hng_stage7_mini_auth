

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import src.db.database as database
import models
import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables
    await database.init_db()
    yield
  

app = FastAPI(
    title="Mini Authentication API",
    description="JWT and API Key Authentication System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include authentication router
app.include_router(router.router, prefix="/api/v1", tags=["authentication"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Mini Authentication API"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}
