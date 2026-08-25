"""Mock storefront catalog for dogfooding the agentic-commerce flow.

This is a static, read-only product catalog so a UI (or an agent loop) has
something to "shop". Prices are integers in the smallest currency unit
(e.g. USD cents) to match the Session `amount` / scope `max_amount` semantics.

No real payments are involved — purchases are authorized via the Session API
(scope + trust + cumulative AP2 budget + merchant allowlist), not settled.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/v1/storefront", tags=["storefront"])


class Product(BaseModel):
    id: str
    name: str
    merchant: str
    merchant_name: str
    price: int          # smallest currency unit (e.g. cents)
    currency: str
    category: str
    image: str          # emoji placeholder for the mock UI


class Merchant(BaseModel):
    id: str
    name: str


# Static catalog. `merchant` ids are what a session scope allowlist references.
_CATALOG: list[Product] = [
    Product(id="nike-airmax", name="Nike Air Max", merchant="nike-store",
            merchant_name="Nike Store", price=8999, currency="USD",
            category="apparel", image="👟"),
    Product(id="nike-pegasus", name="Nike Pegasus 40", merchant="nike-store",
            merchant_name="Nike Store", price=12999, currency="USD",
            category="apparel", image="🏃"),
    Product(id="apple-airpods", name="AirPods Pro", merchant="apple-store",
            merchant_name="Apple Store", price=24900, currency="USD",
            category="electronics", image="🎧"),
    Product(id="apple-cable", name="USB-C Cable", merchant="apple-store",
            merchant_name="Apple Store", price=1900, currency="USD",
            category="electronics", image="🔌"),
    Product(id="books-clean-code", name="Clean Code (book)", merchant="acme-books",
            merchant_name="Acme Books", price=3499, currency="USD",
            category="books", image="📘"),
    Product(id="books-dune", name="Dune (book)", merchant="acme-books",
            merchant_name="Acme Books", price=1899, currency="USD",
            category="books", image="📗"),
]


class CatalogResponse(BaseModel):
    products: list[Product]
    merchants: list[Merchant]


@router.get("/products", response_model=CatalogResponse)
def list_products() -> CatalogResponse:
    """Return the mock product catalog and the set of merchants."""
    seen: dict[str, str] = {}
    for p in _CATALOG:
        seen.setdefault(p.merchant, p.merchant_name)
    merchants = [Merchant(id=mid, name=name) for mid, name in seen.items()]
    return CatalogResponse(products=_CATALOG, merchants=merchants)
