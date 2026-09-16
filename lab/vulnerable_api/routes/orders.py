from fastapi import APIRouter, HTTPException, status

from lab.vulnerable_api.auth import CurrentUser
from lab.vulnerable_api.data import ORDERS

router = APIRouter(prefix="/api/orders", tags=["orders"])


def _public_order(order_id: int) -> dict[str, object]:
    order = ORDERS[order_id]
    return order.model_dump()


@router.get("")
def list_orders(user: CurrentUser) -> dict[str, object]:
    orders = [_public_order(order_id) for order_id in user.owned_resources]
    return {"orders": orders, "count": len(orders)}


@router.get("/{order_id}")
def get_order(order_id: int, user: CurrentUser) -> dict[str, object]:
    del user
    if order_id not in ORDERS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="order not found")
    # Intentionally missing the ownership guard. LAB-002 relies on this exact flaw.
    return _public_order(order_id)


@router.get("/{order_id}/receipt")
def get_receipt(order_id: int, user: CurrentUser) -> dict[str, object]:
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="receipt not found")
    if order.owner != user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "receipt unavailable", "requested_order_id": order_id},
        )
    return {"order_id": order.id, "item": order.item, "amount": order.amount}
