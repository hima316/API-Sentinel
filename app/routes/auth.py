"""Demonstration authentication routes.

WARNING: This is a demonstration authentication endpoint for traffic generation
and anomaly detection testing. Real systems must never hardcode credentials or
bypass industry-standard token-based authentication (OAuth2 / JWT / bcrypt).
"""

from fastapi import APIRouter, HTTPException, status

from app.models.auth import DUMMY_CREDENTIALS, LoginRequest, LoginResponse

router = APIRouter(prefix="/api", tags=["Authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Simulated user login",
    description=(
        "Authenticates against mock credentials for testing.\n\n"
        "**Valid Demo Credentials:**\n"
        "- `admin` / `sentinel123`\n"
        "- `analyst` / `guard456`\n"
        "- `testuser` / `password123`\n\n"
        "Returns HTTP 200 on success, or HTTP 401 on bad credentials."
    ),
    responses={
        200: {"description": "Authentication successful"},
        401: {"description": "Invalid username or password"},
    },
)
def login(payload: LoginRequest) -> LoginResponse:
    """Validate credentials against dummy users and return status."""
    expected_password = DUMMY_CREDENTIALS.get(payload.username)

    if expected_password is None or expected_password != payload.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return LoginResponse(
        success=True,
        message="Authentication successful",
        username=payload.username,
    )
