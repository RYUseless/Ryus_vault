from pydantic import BaseModel


class CreateEntryRequest(BaseModel):
    title: str
    ciphertext: str
    nonce: str


class EntryResponse(BaseModel):
    id: str
    title: str
    ciphertext: str
    nonce: str


class EntriesResponse(BaseModel):
    entries: list[EntryResponse]