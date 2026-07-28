from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl


class VaultItemCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    url: HttpUrl | None = None
    username: str | None = Field(default=None, max_length=500)
    password: str | None = Field(default=None, max_length=2000)
    notes: str | None = Field(default=None, max_length=10000)


class VaultItemUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    url: HttpUrl | None = None
    username: str | None = Field(default=None, max_length=500)
    password: str | None = Field(default=None, max_length=2000)
    notes: str | None = Field(default=None, max_length=10000)


class VaultItemSummary(BaseModel):
    id: str
    title: str
    url: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VaultItemResponse(VaultItemSummary):
    username: str | None
    password: str | None
    notes: str | None
