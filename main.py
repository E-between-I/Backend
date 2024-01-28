from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from bson import ObjectId
from fastapi.responses import FileResponse
from fastapi import Depends, FastAPI, HTTPException, status,  Body, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from pymongo import MongoClient
from bson import json_util
import json
import uvicorn
import os
import uuid
UPLOAD_DIR_CERTIFY = "./certify"
UPLOAD_DIR_SIGN = "./sign"
client = MongoClient(
    os.environ['MONGODB_URI'])
db = client["hackathon"]
stock = db["stock"]
common = db["common"]
deposit = db["deposit"]
realty = db["realty"]
comment = db["comment"]
expert = db["expert"]
users_collection = db["users"]

SECRET_KEY = os.environ['SECRET_KEY']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    password: Optional[str] = None
    nickname: Optional[str] = None
    expert: Optional[bool] = None
    expert_detail: Optional[str] = None
    expert_certify: Optional[list] = None
    expert_sign: Optional[list] = None
    disabled: Optional[bool] = None


class UserRegister(BaseModel):
    username: str
    email: Optional[str] = None
    password: Optional[str] = None
    nickname: Optional[str] = None


class UserInDB(User):
    hashed_password: str


class article(BaseModel):
    item_id: Optional[str] = None
    title: str
    content: str
    author: str
    ref_id: Optional[str] = None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    user_data = users_collection.find_one({"username": username})
    if user_data:
        return UserInDB(**user_data)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/users/register")
async def register_user(User: UserRegister = Body(...)):
    user = get_user(User.username)
    if user:
        return {"message": "User already exists"}
    else:
        users_collection.insert_one(
            {"username": User.username, "hashed_password": get_password_hash(User.password), "email": User.email, "nickname": User.nickname, "expert": False, "disabled": False})
        return {"message": "User registered"}


@app.get("/post/stock")
async def get_stock():
    list = stock.find({})
    return json.loads(json_util.dumps(list))


@app.get("/post/realty")
async def get_realty():
    list = realty.find({})
    return json.loads(json_util.dumps(list))


@app.get("/post/deposit")
async def get_deposit():
    list = deposit.find({})
    return json.loads(json_util.dumps(list))


@app.get("/post/common")
async def get_common():
    list = common.find({})
    return json.loads(json_util.dumps(list))


@app.get("/post/stock/{item_id}")
async def get_stock_detail(item_id: str):
    item = stock.find_one({"_id": ObjectId(f'{item_id}')})
    return json.loads(json_util.dumps(item))


@app.get("/post/realty/{item_id}")
async def get_realty_detail(item_id: str):
    item = realty.find_one({"_id": ObjectId(f'{item_id}')})
    return json.loads(json_util.dumps(item))


@app.get("/post/deposit/{item_id}")
async def get_deposit_detail(item_id: str):
    item = deposit.find_one({"_id": ObjectId(f'{item_id}')})
    return json.loads(json_util.dumps(item))


@app.get("/post/common/{item_id}")
async def get_stock_detail(item_id: str):
    item = common.find_one({"_id": ObjectId(f'{item_id}')})
    return json.loads(json_util.dumps(item))


@app.post("/post/common")
async def post_common(Article: article = Body(...)):

    common.insert_one({
        "title": Article.title,
        "content": Article.content,
        "author": Article.author,
        "date": datetime.now(),
        "like": 0
    })

    return {"message": "True"}


@app.post("/post/deposit")
async def post_deposit(Article: article = Body(...)):

    deposit.insert_one({
        "title": Article.title,
        "content": Article.content,
        "author": Article.author,
        "date": datetime.now(),
        "like": 0
    })

    return {"message": "True"}


@app.put("/post/deposit/{item_id}")
async def update_deposit(Article: article = Body(...)):

    deposit.update_one({
        "_id": ObjectId(f'{Article.item_id}')}, {
        "$set": {"title": Article.title},
        "$set": {"content": Article.content},
        "$set": {"author": Article.author},
    })

    return {"message": "True"}


@app.put("/post/common/{item_id}")
async def update_common(Article: article = Body(...)):

    common.update_one({
        "_id": ObjectId(f'{Article.item_id}')}, {
        "$set": {"title": Article.title},
        "$set": {"content": Article.content},
        "$set": {"author": Article.author},
    })

    return {"message": "True"}


@app.put("/post/realty/{item_id}")
async def update_realty(Article: article = Body(...)):

    realty.update_one({
        "_id": ObjectId(f'{Article.item_id}')}, {
        "$set": {"title": Article.title},
        "$set": {"content": Article.content},
        "$set": {"author": Article.author},
    })

    return {"message": "True"}


@app.put("/post/stock/{item_id}")
async def update_stock(Article: article = Body(...)):

    stock.update_one({
        "_id": ObjectId(f'{Article.item_id}')}, {
        "$set": {"title": Article.title},
        "$set": {"content": Article.content},
        "$set": {"author": Article.author},
    })

    return {"message": "True"}


@app.delete("/post/deposit/{item_id}")
async def delete_deposit(item_id: str):
    deposit.delete_one({"_id": ObjectId(f'{item_id}')})
    return {"message": "True"}


@app.delete("/post/common/{item_id}")
async def delete_common(item_id: str):
    common.delete_one({"_id": ObjectId(f'{item_id}')})
    return {"message": "True"}


@app.delete("/post/realty/{item_id}")
async def delete_realty(item_id: str):
    realty.delete_one({"_id": ObjectId(f'{item_id}')})
    return {"message": "True"}


@app.delete("/post/stock/{item_id}")
async def delete_stock(item_id: str):
    stock.delete_one({"_id": ObjectId(f'{item_id}')})
    return {"message": "True"}


@app.post("/post/realty")
async def post_realty(Article: article = Body(...)):

    realty.insert_one({
        "title": Article.title,
        "content": Article.content,
        "author": Article.author,
        "date": datetime.now(),
        "like": 0
    })

    return {"message": "True"}


@app.post("/post/stock")
async def post_stock(Article: article = Body(...)):

    stock.insert_one({
        "title": Article.title,
        "content": Article.content,
        "author": Article.author,
        "date": datetime.now(),
        "like": 0
    })

    return {"message": "True"}


@app.get("/ranking/stock")
async def get_stock_ranking():
    list = stock.find({}).sort("like", -1).limit(5)
    return json.loads(json_util.dumps(list))


@app.get("/ranking/realty")
async def get_realty_ranking():
    list = realty.find({}).sort("like", -1).limit(5)
    return json.loads(json_util.dumps(list))


@app.get("/ranking/deposit")
async def get_deposit_ranking():
    list = deposit.find({}).sort("like", -1).limit(5)
    return json.loads(json_util.dumps(list))


@app.get("/ranking/common")
async def get_common_ranking():
    list = common.find({}).sort("like", -1).limit(5)
    return json.loads(json_util.dumps(list))


@app.get("/likes/stock/{item_id}")
async def like_stock(item_id: str):
    stock.update_one({"_id": ObjectId(f'{item_id}')}, {"$inc": {"like": 1}})
    return {"message": "True"}


@app.get("/likes/realty/{item_id}")
async def like_realty(item_id: str):
    realty.update_one({"_id": ObjectId(f'{item_id}')}, {"$inc": {"like": 1}})
    return {"message": "True"}


@app.get("/likes/deposit/{item_id}")
async def like_deposit(item_id: str):
    deposit.update_one({"_id": ObjectId(f'{item_id}')}, {"$inc": {"like": 1}})
    return {"message": "True"}


@app.get("/likes/common/{item_id}")
async def like_common(item_id: str):
    common.update_one({"_id": ObjectId(f'{item_id}')}, {"$inc": {"like": 1}})
    return {"message": "True"}


@app.post("/users/expert")
async def expert_user(User: User = Body(...)):
    users_collection.update_one({"username": User.username}, {
                                "$set": {"expert": True}})
    expert.insert_one({"username": User.username,
                      "content": User.expert_detail, "expert_certify": [], "expert_sign": []})
    return {"message": "True"}


@app.get("/users/expert")
async def get_expert_user(User: User = Body(...)):
    user = users_collection.find_one({"username": User.username})
    if user['expert']:
        expert = expert.find_one({"username": User.username})
        return {"message": "True", "expert": expert['content'], "certify": expert['expert_certify'], "sign": expert['expert_sign']}
    else:
        return {"message": "False"}


@app.post("/users/expert/certify")
async def upload_certify_photo(file: UploadFile, username: str):
    UPLOAD_DIR = "./certify"
    content = await file.read()
    filename = f"{str(uuid.uuid4())}.jpg"

    expert.update_one({"username": username}, {
                      "$addToSet": {"expert_certify": filename}})

    with open(os.path.join(UPLOAD_DIR, filename), "wb") as fp:
        fp.write(content)

    return {"filename": filename}


@app.post("/users/expert/sign")
async def upload_certify_photo(file: UploadFile, username: str):
    UPLOAD_DIR = "./sign"
    content = await file.read()
    filename = f"{str(uuid.uuid4())}.jpg"
    expert.update_one({"username": username}, {
                      "$addToSet": {"expert_sign": filename}})

    with open(os.path.join(UPLOAD_DIR, filename), "wb") as fp:
        fp.write(content)

    return {"filename": filename}


@app.get("/users/expert/certify/{username}")
async def certify_name(response_class: FileResponse, username: str):
    find_photo = expert.find_one({"username": f'{username}'})
    certify_photos = find_photo.get('expert_certify', [])
    if not certify_photos:
        raise HTTPException(status_code=404, detail="Certify photos not found")
    return [(f"./certify/{filename}") for filename in certify_photos]


@app.get("/users/expert/sign/{username}")
async def sign_name(response_class: FileResponse, username: str):
    find_photo = expert.find_one({"username": f'{username}'})
    sign_photos = find_photo.get('expert_sign', [])
    if not sign_photos:
        raise HTTPException(status_code=404, detail="Sign photos not found")
    return [(f"{filename}") for filename in sign_photos]


@app.get("/users/expert/sign/photo/{photo_id}")
async def download_sign(photo_id: str):
    return FileResponse(f"./sign/{photo_id}")


@app.get("/users/expert/certify/photo/{photo_id}")
async def download_certify(photo_id: str):
    return FileResponse(f"./certify/{photo_id}")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)
