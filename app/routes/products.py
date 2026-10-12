"""Sample product catalog routes."""

from typing import List
from fastapi import APIRouter, HTTPException, status

from app.models.product import SAMPLE_PRODUCTS, Product

router = APIRouter(prefix="/api/products", tags=["Products"])


@router.get(
    "",
    response_model=List[Product],
    summary="List sample products",
    description="Returns a static list of catalog products for activity testing.",
)
def list_products() -> List[Product]:
    """Retrieve all sample catalog items."""
    return SAMPLE_PRODUCTS


@router.get(
    "/{product_id}",
    response_model=Product,
    summary="Get single product by ID",
    description="Returns a specific product, or HTTP 404 if not found.",
    responses={
        200: {"description": "Product details"},
        404: {"description": "Product not found"},
    },
)
def get_product(product_id: int) -> Product:
    """Retrieve a single product by numeric identifier."""
    for product in SAMPLE_PRODUCTS:
        if product.id == product_id:
            return product

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Product with ID {product_id} not found",
    )
