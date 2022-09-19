from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from services import Auth
from services.smtpserver import mailServer
from services.DatabaseConnec import db, collec
from models.User import User, UserAbi, UserOP, UserRr, UserToken, Userln
from models.Resp import RespStruct
from models.Token import Token


app = FastAPI()


@app.get ("/api")
async def defualtpage():
    return  (RespStruct(message="default page"))


@app.get ("/api/user/me")
async def whoami(curr_user: UserOP | User = Depends(Auth.get_user)):
    return curr_user


@app.post ("/api/user/client/register")
async def users(user: UserRr):
    #   check if client exists
    if collec.find_one({ "email" : user.email }):
        return  (RespStruct(message="email already exists"))
    else :
        user.password = Auth.getPassHash(user.password)
        collec.insert_one(User(name=user.name, email=user.email, password=user.password).__dict__)
        thehash = Auth.genHash()  #   uses randomly generated salt

        db["tmpHashes"].insert_one({"hash" : thehash})

        ver = mailServer()
        ver.To = user.email
        ver.Message = f"hi, { user.name } use this link to activate your account http://localhost:8000/api/user/client/verify?email={user.email}&hash={thehash}"
        ver.sendlink()
        return  (RespStruct(message=f"user registered, verification link sent to {user.email}"))



@app.post ("/api/user/{userLevel}/login" , response_model=  UserToken)
async def login(user: Userln, userLevel: str):
    if (userLevel == "client"):
        userindb = collec.find_one({"email" : user.email}) # will return User struct
        if userindb is None:
            raise HTTPException(404, "user not found")
        else:
            userindb = User(**userindb)
        if not userindb.disabled:
            if Auth.verify_password( user.password, userindb.password):
                return  UserToken(token = Auth.create_jwt(
                        {
                            "email" : user.email
                        }
                        #   remains valid for 5 mins
                    ))
            else:
                raise HTTPException(401, "Authentication failed")
        else:
            raise HTTPException(403, "User is disabled")
    if (userLevel == "operations"):
        userindb = db["operations"].find_one({"email" : user.email}) # will return UserRr struct
        if userindb is None:
            raise HTTPException(401, "Authentication Failed")
        if Auth.verify_password( user.password, userindb["password"]):
            return  UserToken(token = Auth.create_jwt({
                        "email" : user.email
                    }
                    #   remains valid for 5 mins
                ))
        else:
            raise HTTPException(401, "Authentication Failed")
    raise HTTPException(404, "Not Found")



@app.get ("/api/user/logout")
async def logout(token: str = Depends(Auth.oauth2_scheme), curr_user: UserOP | User = Depends(Auth.get_user)):
    db["JWTblacklist"].insert_one({"token" : token})
    return HTTPException(200, f"{curr_user.name} logged out")



@app.get ("/api/user/client/verify")
async def verify(email: str, hash: str):
    if collec.find_one({ "email" : email}):
        if db["tmpHashes"].find_one({"hash" : hash}):
            db["tmpHashes"].find_one_and_delete({"hash" : hash})
            collec.find_one_and_update(
                {"email" : email},
                {"$set" : {"verified" : True}}
            )
            return  (RespStruct(message="email verified, now you can login"))
    return  (RespStruct(message="This link is not valid"))



@app.post ("/api/user/operations/userability")
async def disuser(user_to_dis: UserAbi, curr_user: UserOP | User = Depends(Auth.get_user)):
    try:
        if curr_user.OPuser:
            db_user_obj = collec.find_one( {"email" : user_to_dis.email} )
            if db_user_obj is None:
                raise HTTPException(404, "User not found")
            else:
                cli_user = User(**db_user_obj)
                collec.find_one_and_update(
                    {"email" : cli_user.email},
                    {"$set" : {"disabled" : user_to_dis.disability}}
                )
                action = "abled" if not user_to_dis.disability else "disabled"
                raise HTTPException(200, f"User with email : {cli_user.email} is now {action}")
        else :
            raise HTTPException(401, "Authentication error")
    except AttributeError:
        raise HTTPException(401)


# @app.post ("/api/auth", response_model=Token)
# async def auth( form_data: OAuth2PasswordRequestForm = Depends()):
#     print(form_data.username)
#     user = collec.find_one({"email" : form_data.username})
#     if not user:
#         raise HTTPException(400, "Incorrect")
#     user_validate = User(**user)
#     if not Auth.verify_password(form_data.password, user_validate.passhash):
#         raise HTTPException(400, "Incorrect")
#     access_token = Auth.create_jwt({"email" : user_validate.email})

#     return Token(access_token=access_token)