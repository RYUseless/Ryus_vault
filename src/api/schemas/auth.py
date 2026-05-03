from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    public_key_x: str
    public_key_y: str
    salt: str
    secret: str


class OrProofBranchSchema(BaseModel):
    commitment_x: str
    commitment_y: str
    challenge: str
    response: str


class LoginRequest(BaseModel):
    username: str
    branch0: OrProofBranchSchema
    branch1: OrProofBranchSchema