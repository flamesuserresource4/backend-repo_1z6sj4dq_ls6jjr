"""
Database Schemas for HanuShreeJewels

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase class name (e.g., User -> "user").
"""
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr

# --- Auth & Users ---
class Address(BaseModel):
    name: str = Field(..., description="Full name for delivery")
    phone: str = Field(..., description="Contact phone number")
    line1: str
    line2: Optional[str] = None
    city: str
    state: str
    pincode: str
    country: str = "India"
    is_default: bool = False

class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    role: Literal["user", "admin"] = "user"
    gstin: Optional[str] = None
    business_name: Optional[str] = None
    addresses: List[Address] = []

# --- Catalog ---
class Category(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None

class Product(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    sku: str
    price: float = Field(..., ge=0)
    gst_rate: Literal[5, 12, 18] = 5
    category: str = Field(..., description="Category slug")
    materials: List[str] = []  # e.g., ["Kundan", "Polki"]
    colors: List[str] = []
    images: List[str] = []
    stock: int = 0
    bestseller: bool = False

# --- Orders ---
class CartItem(BaseModel):
    product_id: str
    name: str
    sku: str
    price: float
    gst_rate: Literal[5,12,18]
    quantity: int = Field(..., ge=1)

class TaxBreakup(BaseModel):
    cgst: float = 0
    sgst: float = 0
    igst: float = 0

class OrderItem(BaseModel):
    product_id: str
    name: str
    sku: str
    quantity: int
    price: float
    gst_rate: Literal[5,12,18]
    taxable_value: float
    gst_amount: float
    tax_breakup: TaxBreakup
    total: float

class Order(BaseModel):
    user_id: str
    items: List[OrderItem]
    shipping_address: Address
    billing_address: Address
    gstin: Optional[str] = None
    business_name: Optional[str] = None
    subtotal: float
    total_gst: float
    shipping_fee: float = 0
    grand_total: float
    gst_breakup: TaxBreakup
    status: Literal["pending", "confirmed", "shipped", "delivered", "cancelled"] = "pending"
    payment_status: Literal["pending", "paid", "failed"] = "pending"

# --- Search Index (optional later) ---
