import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Literal, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from bson import ObjectId
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User as UserSchema, Address, Category as CategorySchema, Product as ProductSchema, CartItem, Order as OrderSchema, OrderItem, TaxBreakup

JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="HanuShreeJewels API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Helpers ----------

def objectid_str(oid: Any) -> str:
    return str(oid) if isinstance(oid, ObjectId) else str(oid)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(token: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(token.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication")


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ---------- Models (requests/responses) ----------

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ProfileResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: Literal["user", "admin"]
    gstin: Optional[str] = None
    business_name: Optional[str] = None
    addresses: List[Address] = []

class CategoryCreateRequest(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None

class ProductCreateRequest(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    sku: str
    price: float
    gst_rate: Literal[5,12,18] = 5
    category: str
    materials: List[str] = []
    colors: List[str] = []
    images: List[str] = []
    stock: int = 0
    bestseller: bool = False

class ProductResponse(ProductCreateRequest):
    id: str

class FilterQuery(BaseModel):
    q: Optional[str] = None
    category: Optional[str] = None
    min_price: Optional[float] = None
    max_price: Optional[float] = None
    materials: Optional[List[str]] = None
    colors: Optional[List[str]] = None
    bestseller: Optional[bool] = None
    limit: int = 24
    skip: int = 0

class CheckoutRequest(BaseModel):
    items: List[CartItem]
    shipping_address: Address
    billing_address: Address
    gstin: Optional[str] = None
    business_name: Optional[str] = None
    shipping_fee: float = 0

class OrderResponse(BaseModel):
    id: str

# ---------- Base endpoints ----------
@app.get("/")
def root():
    return {"name": "HanuShreeJewels API", "status": "ok"}

@app.get("/test")
def test_database():
    resp = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            resp["database"] = "✅ Connected"
            resp["connection_status"] = "Connected"
            resp["collections"] = db.list_collection_names()
    except Exception as e:
        resp["database"] = f"⚠️ {str(e)[:80]}"
    return resp

# ---------- Auth ----------
@app.post("/api/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = pwd_context.hash(payload.password)
    user_model = UserSchema(name=payload.name, email=payload.email, password_hash=password_hash)
    user_id = create_document("user", user_model)
    token = create_access_token({"sub": user_id})
    return TokenResponse(access_token=token)

@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": objectid_str(user["_id"])})
    return TokenResponse(access_token=token)

@app.get("/api/auth/me", response_model=ProfileResponse)
def me(current: dict = Depends(get_current_user)):
    return ProfileResponse(
        id=objectid_str(current["_id"]),
        name=current.get("name"),
        email=current.get("email"),
        role=current.get("role", "user"),
        gstin=current.get("gstin"),
        business_name=current.get("business_name"),
        addresses=current.get("addresses", []),
    )

# ---------- Categories ----------
@app.get("/api/categories", response_model=List[CategorySchema])
def list_categories():
    cats = get_documents("category")
    for c in cats:
        c.pop("_id", None)
    return cats

@app.post("/api/admin/categories", dependencies=[Depends(require_admin)])
def create_category(payload: CategoryCreateRequest):
    if db["category"].find_one({"slug": payload.slug}):
        raise HTTPException(status_code=400, detail="Slug already exists")
    cid = create_document("category", CategorySchema(**payload.model_dump()))
    return {"id": cid}

@app.put("/api/admin/categories/{slug}", dependencies=[Depends(require_admin)])
def update_category(slug: str, payload: CategoryCreateRequest):
    res = db["category"].update_one({"slug": slug}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"updated": True}

@app.delete("/api/admin/categories/{slug}", dependencies=[Depends(require_admin)])
def delete_category(slug: str):
    db["category"].delete_one({"slug": slug})
    return {"deleted": True}

# ---------- Products ----------
@app.get("/api/products", response_model=List[ProductResponse])
def list_products(q: Optional[str] = None, category: Optional[str] = None, min_price: Optional[float] = None,
                  max_price: Optional[float] = None, materials: Optional[str] = None, colors: Optional[str] = None,
                  bestseller: Optional[bool] = None, limit: int = 24, skip: int = 0):
    query: Dict[str, Any] = {}
    if q:
        query["$or"] = [{"name": {"$regex": q, "$options": "i"}}, {"description": {"$regex": q, "$options": "i"}}]
    if category:
        query["category"] = category
    if min_price is not None or max_price is not None:
        price_q = {}
        if min_price is not None:
            price_q["$gte"] = min_price
        if max_price is not None:
            price_q["$lte"] = max_price
        query["price"] = price_q
    if materials:
        mats = [m.strip() for m in materials.split(",") if m.strip()]
        if mats:
            query["materials"] = {"$in": mats}
    if colors:
        cols = [c.strip() for c in colors.split(",") if c.strip()]
        if cols:
            query["colors"] = {"$in": cols}
    if bestseller is not None:
        query["bestseller"] = bestseller

    cursor = db["product"].find(query).skip(skip).limit(limit)
    products = []
    for p in cursor:
        p_resp = {**{k: v for k, v in p.items() if k != "_id"}, "id": objectid_str(p["_id"]) }
        products.append(ProductResponse(**p_resp))
    return products

@app.get("/api/products/{slug}", response_model=ProductResponse)
def get_product(slug: str):
    p = db["product"].find_one({"slug": slug})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    p_resp = {**{k: v for k, v in p.items() if k != "_id"}, "id": objectid_str(p["_id"]) }
    return ProductResponse(**p_resp)

@app.post("/api/admin/products", dependencies=[Depends(require_admin)])
def create_product(payload: ProductCreateRequest):
    if db["product"].find_one({"slug": payload.slug}):
        raise HTTPException(status_code=400, detail="Slug already exists")
    pid = create_document("product", ProductSchema(**payload.model_dump()))
    return {"id": pid}

@app.put("/api/admin/products/{slug}", dependencies=[Depends(require_admin)])
def update_product(slug: str, payload: ProductCreateRequest):
    res = db["product"].update_one({"slug": slug}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"updated": True}

@app.delete("/api/admin/products/{slug}", dependencies=[Depends(require_admin)])
def delete_product(slug: str):
    db["product"].delete_one({"slug": slug})
    return {"deleted": True}

# ---------- Checkout & Orders ----------

def compute_taxes(items: List[CartItem], shipping_state: str, seller_state: str = os.getenv("SELLER_STATE", "Karnataka")):
    order_items: List[OrderItem] = []
    subtotal = 0.0
    total_gst = 0.0
    breakup_total = TaxBreakup()
    intra_state = (shipping_state.strip().lower() == seller_state.strip().lower())
    for it in items:
        taxable = round(it.price * it.quantity, 2)
        gst_amount = round(taxable * (it.gst_rate / 100.0), 2)
        if intra_state:
            cgst = round(gst_amount / 2, 2)
            sgst = round(gst_amount - cgst, 2)
            igst = 0.0
        else:
            cgst = 0.0
            sgst = 0.0
            igst = gst_amount
        order_item = OrderItem(
            product_id=it.product_id,
            name=it.name,
            sku=it.sku,
            quantity=it.quantity,
            price=it.price,
            gst_rate=it.gst_rate,
            taxable_value=taxable,
            gst_amount=gst_amount,
            tax_breakup=TaxBreakup(cgst=cgst, sgst=sgst, igst=igst),
            total=round(taxable + gst_amount, 2)
        )
        subtotal += taxable
        total_gst += gst_amount
        breakup_total.cgst += cgst
        breakup_total.sgst += sgst
        breakup_total.igst += igst
        order_items.append(order_item)
    # round totals
    subtotal = round(subtotal, 2)
    total_gst = round(total_gst, 2)
    breakup_total.cgst = round(breakup_total.cgst, 2)
    breakup_total.sgst = round(breakup_total.sgst, 2)
    breakup_total.igst = round(breakup_total.igst, 2)
    return order_items, subtotal, total_gst, breakup_total

@app.post("/api/checkout", response_model=OrderResponse)
def checkout(payload: CheckoutRequest, user: dict = Depends(get_current_user)):
    if not payload.items:
        raise HTTPException(status_code=400, detail="Cart is empty")
    order_items, subtotal, total_gst, breakup_total = compute_taxes(payload.items, payload.shipping_address.state)
    grand_total = round(subtotal + total_gst + payload.shipping_fee, 2)
    order_model = OrderSchema(
        user_id=objectid_str(user["_id"]),
        items=order_items,
        shipping_address=payload.shipping_address,
        billing_address=payload.billing_address,
        gstin=payload.gstin,
        business_name=payload.business_name,
        subtotal=subtotal,
        total_gst=total_gst,
        shipping_fee=payload.shipping_fee,
        grand_total=grand_total,
        gst_breakup=breakup_total,
    )
    oid = create_document("order", order_model)
    return OrderResponse(id=oid)

@app.get("/api/orders")
def list_my_orders(user: dict = Depends(get_current_user)):
    orders = list(db["order"].find({"user_id": objectid_str(user["_id"])}).sort("created_at", -1))
    for o in orders:
        o["id"] = objectid_str(o.pop("_id"))
    return orders

@app.get("/api/admin/orders", dependencies=[Depends(require_admin)])
def admin_orders():
    orders = list(db["order"].find().sort("created_at", -1))
    for o in orders:
        o["id"] = objectid_str(o.pop("_id"))
    return orders

class UpdateOrderStatus(BaseModel):
    status: Literal["pending", "confirmed", "shipped", "delivered", "cancelled"]

@app.put("/api/admin/orders/{order_id}", dependencies=[Depends(require_admin)])
def update_order(order_id: str, payload: UpdateOrderStatus):
    res = db["order"].update_one({"_id": ObjectId(order_id)}, {"$set": {"status": payload.status, "updated_at": datetime.now(timezone.utc)}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"updated": True}

# ---------- GST Reports ----------
@app.get("/api/admin/gst-report", dependencies=[Depends(require_admin)])
def gst_report(month: str):
    # month in YYYY-MM
    try:
        start = datetime.strptime(month + "-01", "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if start.month == 12:
            end = start.replace(year=start.year + 1, month=1)
        else:
            end = start.replace(month=start.month + 1)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid month format. Use YYYY-MM")
    cursor = db["order"].find({"created_at": {"$gte": start, "$lt": end}})
    total_taxable = 0.0
    cgst = sgst = igst = 0.0
    for o in cursor:
        total_taxable += float(o.get("subtotal", 0))
        br = o.get("gst_breakup", {})
        cgst += float(br.get("cgst", 0))
        sgst += float(br.get("sgst", 0))
        igst += float(br.get("igst", 0))
    return {
        "month": month,
        "taxable_value": round(total_taxable, 2),
        "cgst": round(cgst, 2),
        "sgst": round(sgst, 2),
        "igst": round(igst, 2),
        "total_gst": round(cgst + sgst + igst, 2),
    }

# ---------- Simple Invoice (PDF) ----------
from fastapi.responses import StreamingResponse
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

@app.get("/api/orders/{order_id}/invoice.pdf")
def generate_invoice(order_id: str, user: dict = Depends(get_current_user)):
    order = db["order"].find_one({"_id": ObjectId(order_id)})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # only owner or admin
    if objectid_str(user["_id"]) != order.get("user_id") and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50
    p.setFont("Helvetica-Bold", 16)
    p.drawString(40, y, "HanuShreeJewels Invoice")
    y -= 30
    p.setFont("Helvetica", 10)
    p.drawString(40, y, f"Order ID: {order_id}")
    y -= 15
    p.drawString(40, y, f"Date: {order.get('created_at').strftime('%Y-%m-%d %H:%M')} IST")
    y -= 25
    p.setFont("Helvetica-Bold", 12)
    p.drawString(40, y, "Items")
    y -= 18
    p.setFont("Helvetica", 10)
    for it in order.get("items", []):
        line = f"{it['name']} (SKU: {it['sku']}) x{it['quantity']}  Price: ₹{it['price']}  GST {it['gst_rate']}%  Taxable: ₹{it['taxable_value']}  GST: ₹{it['gst_amount']}  Total: ₹{it['total']}"
        p.drawString(40, y, line[:110])
        y -= 14
        if y < 80:
            p.showPage(); y = height - 50
    y -= 10
    p.setFont("Helvetica-Bold", 11)
    p.drawString(40, y, f"Subtotal: ₹{order.get('subtotal')}")
    y -= 14
    p.drawString(40, y, f"GST: ₹{order.get('total_gst')} (CGST: ₹{order.get('gst_breakup',{}).get('cgst',0)}  SGST: ₹{order.get('gst_breakup',{}).get('sgst',0)}  IGST: ₹{order.get('gst_breakup',{}).get('igst',0)})")
    y -= 14
    p.drawString(40, y, f"Shipping: ₹{order.get('shipping_fee',0)}")
    y -= 14
    p.drawString(40, y, f"Grand Total: ₹{order.get('grand_total')}")
    p.showPage()
    p.save()
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f"inline; filename=invoice_{order_id}.pdf"})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
