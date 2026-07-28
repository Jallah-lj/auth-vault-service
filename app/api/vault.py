from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select

from app.api.dependencies import CurrentUser, DbSession
from app.core.security import decrypt_payload, encrypt_payload
from app.db.models import VaultItem
from app.schemas.vault import VaultItemCreate, VaultItemResponse, VaultItemSummary, VaultItemUpdate

router = APIRouter(prefix="/vault/items", tags=["vault"])


def owned_item(item_id: str, user_id: str, db: DbSession) -> VaultItem:
    item = db.scalar(select(VaultItem).where(VaultItem.id == item_id, VaultItem.user_id == user_id))
    if not item:
        # Do not disclose whether another user's item exists.
        raise HTTPException(status_code=404, detail="Vault item not found")
    return item


def reveal(item: VaultItem) -> VaultItemResponse:
    return VaultItemResponse(
        id=item.id, title=item.title, url=item.url, created_at=item.created_at, updated_at=item.updated_at,
        **decrypt_payload(item.encrypted_data),
    )


@router.post("", response_model=VaultItemResponse, status_code=status.HTTP_201_CREATED)
def create_item(payload: VaultItemCreate, db: DbSession, current_user: CurrentUser):
    item = VaultItem(
        user_id=current_user.id,
        title=payload.title,
        url=str(payload.url) if payload.url else None,
        encrypted_data=encrypt_payload({key: getattr(payload, key) for key in ("username", "password", "notes")}),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return reveal(item)


@router.get("", response_model=list[VaultItemSummary])
def list_items(db: DbSession, current_user: CurrentUser):
    return list(db.scalars(select(VaultItem).where(VaultItem.user_id == current_user.id).order_by(VaultItem.updated_at.desc())))


@router.get("/{item_id}", response_model=VaultItemResponse)
def get_item(item_id: str, db: DbSession, current_user: CurrentUser):
    return reveal(owned_item(item_id, current_user.id, db))


@router.patch("/{item_id}", response_model=VaultItemResponse)
def update_item(item_id: str, payload: VaultItemUpdate, db: DbSession, current_user: CurrentUser):
    item = owned_item(item_id, current_user.id, db)
    values = payload.model_dump(exclude_unset=True)
    if "title" in values:
        item.title = values.pop("title")
    if "url" in values:
        url = values.pop("url")
        item.url = str(url) if url else None
    secret_fields = {key: values[key] for key in ("username", "password", "notes") if key in values}
    if secret_fields:
        current = decrypt_payload(item.encrypted_data)
        current.update(secret_fields)
        item.encrypted_data = encrypt_payload(current)
    db.commit()
    db.refresh(item)
    return reveal(item)


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(item_id: str, db: DbSession, current_user: CurrentUser) -> Response:
    db.delete(owned_item(item_id, current_user.id, db))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
