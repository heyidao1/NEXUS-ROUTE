# -*- coding: utf-8 -*-
"""
NEXUS-ROUTE Data Contract & Schema Verification Layer (v3.0.0-PRO)
Securing asynchronous stream validation using rigidly typed pydantic schemas.
Path: B:\NEXUS_ROUTE\config_refined.py
"""

from pydantic import BaseModel, Field, field_validator
from typing import List

class RefinedOrderPacket(BaseModel):
    """
    Data Contract Schema declaring strict verification boundaries 
    for high-concurrency order clearing operations.
    """
    client_id: str = Field(
        ..., 
        description="Unique enterprise partition identifier matched against vector profiles"
    )
    sku_list: List[str] = Field(
        ..., 
        description="Array of validated standard inventory SKU strings extracted by gateway"
    )
    total_weight: float = Field(
        ..., 
        description="Consolidated mass of payload shipment in kilograms"
    )
    dispatch_priority: int = Field(
        default=3, 
        description="Dynamic scheduling router priority level bounded [1-5]"
    )

    @field_validator('client_id')
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        """
        Enforce strict corporate prefix matching to prevent injection of toxic, unmapped routing payloads.
        Supported partitions: XC (Western), SH (Shanghai), BJ (Beijing), LC (Lüchun Agriculture Coop)
        """
        allowed_prefixes = ("XC_", "SH_", "BJ_", "LC_")
        if not any(v.startswith(prefix) for prefix in allowed_prefixes):
            raise ValueError(
                f"CRITICAL_SCHEMA_BREACH: Target 'client_id' ({v}) must begin with valid "
                f"corporate registry partition code: {allowed_prefixes}"
            )
        return v

    @field_validator('total_weight')
    @classmethod
    def validate_weight(cls, v: float) -> float:
        """
        Guarantees packet weight exceeds absolute zero boundary.
        """
        if v <= 0.0:
            raise ValueError(
                f"CRITICAL_SCHEMA_BREACH: Consolidated transaction cargo weight must "
                f"exceed 0.0 kg. Received: {v}"
            )
        return v
