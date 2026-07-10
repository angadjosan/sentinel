from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..auth import get_current_user
from ..models import User

router = APIRouter(prefix="/v1", tags=["completions"])


class CompletionRequest(BaseModel):
    model: str
    prompt: str
    max_tokens: int = 256
    temperature: float = 0.7


class CompletionResponse(BaseModel):
    id: str
    model: str
    content: str
    prompt_tokens: int
    completion_tokens: int


@router.post("/completions", response_model=CompletionResponse)
async def create_completion(
    payload: CompletionRequest,
    user: User = Depends(get_current_user),
) -> CompletionResponse:
    """Generate a text completion."""
    import uuid
    # Placeholder — real implementation calls upstream LLM
    return CompletionResponse(
        id=str(uuid.uuid4()),
        model=payload.model,
        content="[completion placeholder]",
        prompt_tokens=len(payload.prompt.split()),
        completion_tokens=0,
    )
