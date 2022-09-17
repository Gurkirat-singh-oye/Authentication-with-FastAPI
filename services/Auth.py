from fastapi import HTTPException
from models.User import UserOP, UserRr, Userln, User
from services.DatabaseConnec import db, collec
import jwt, os
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from dotenv import load_dotenv
from essential_generators import DocumentGenerator
import bcrypt

load_dotenv()
gen = DocumentGenerator()
oauth2_scheme = OAuth2PasswordBearer("/api/auth")

def genHash() -> str:
    return bcrypt.hashpw(gen.sentence().encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def getPassHash(plaintext_pass: str) -> str:
    return bcrypt.hashpw(plaintext_pass.encode("utf-8"), bcrypt.gensalt()).decode('utf-8')

def verify_password(plaintext_pass: str, passHash: str) -> bool:
    return bcrypt.checkpw(plaintext_pass.encode("utf-8"), passHash.encode("utf-8"))

def create_jwt(payload: dict) -> str:
    dt = datetime.utcnow() + timedelta(minutes=5.0)
    payload["exp"] = dt
    return jwt.encode( payload=payload, key=os.getenv("SECRET"), algorithm="HS256")

def verify_token(token: str) -> list:
    try:
        return [{"message" : "Token is valid", "user" : jwt.decode(token, os.getenv("SECRET"), "HS256")},1]
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError):
        return [{"message" : "Invalid Token"}, 0]

def get_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, os.getenv("SECRET"), "HS256")
        token_obj = db["JWTblacklist"].find_one({"token" : token})
        if token_obj is not None:
            raise HTTPException(409, "User has logged out")
        username: str = payload.get("email")
        if username is None:
            raise HTTPException(401)
        db_user_obj = collec.find_one({"email" : username})
        if db_user_obj is None:
            db_user_obj = db["operations"].find_one({"email" : username})
            if db_user_obj is None:
                raise HTTPException(401)
            else:
                user = UserOP(**(db_user_obj)) #    operations user
        else:
            user = User(**(db_user_obj))  #    client user
    
    except (jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError):
        raise HTTPException(401)
    return user