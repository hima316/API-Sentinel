"""Product schemas and sample catalog data."""

from typing import List
from pydantic import BaseModel, Field


class Product(BaseModel):
    """Schema representing an e-commerce catalog product."""

    id: int = Field(..., description="Unique product identifier", examples=[1])
    name: str = Field(..., description="Product name", examples=["API Firewall Pro"])
    category: str = Field(..., description="Product category", examples=["Security"])
    price: float = Field(..., description="Unit price in USD", examples=[199.99])
    description: str = Field(..., description="Short product description")
    in_stock: bool = Field(default=True, description="Stock availability status")


# Static sample product catalog
SAMPLE_PRODUCTS: List[Product] = [
    Product(
        id=1,
        name="Sentinel API Gateway",
        category="Security",
        price=299.99,
        description="High-performance reverse proxy with rate limiting and TLS termination.",
        in_stock=True,
    ),
    Product(
        id=2,
        name="Telemetry Collector Probe",
        category="Monitoring",
        price=89.50,
        description="Lightweight sidecar collector for streaming request metrics.",
        in_stock=True,
    ),
    Product(
        id=3,
        name="Anomaly Engine License",
        category="Analytics",
        price=499.00,
        description="Real-time behavioral ML anomaly detector for API endpoints.",
        in_stock=True,
    ),
    Product(
        id=4,
        name="Audit Log Exporter",
        category="Compliance",
        price=149.00,
        description="Encrypted compliance log shipper for SOC2 and ISO27001.",
        in_stock=False,
    ),
]
