from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    public_key_x: int
    public_key_y: int
    salt: str


class LoginRequest(BaseModel):
    username: str
    commitment_x: int
    commitment_y: int
    challenge: int
    response: int


class TokenResponse(BaseModel):
    token: str