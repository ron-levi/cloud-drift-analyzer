from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def health_check():
    """
    Basic health check endpoint that returns status OK
    """
    return {"status": "OK"}