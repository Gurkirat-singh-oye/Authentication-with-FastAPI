from typing import Optional
from pydantic import BaseModel

#   for login
class Userln(BaseModel):
    email: str
    password: str

#   for registration and
class UserRr (Userln):
    name: str

#   client for database
class User (UserRr):
    verified: Optional[bool] = False
    disabled: Optional[bool] = False
    FSlogout: Optional[bool] = False

#   for operations user
class UserOP (UserRr):
    OPuser: bool = True

#   for disabling user
class UserAbi(BaseModel):
    email: str
    disability: bool

class UserToken(BaseModel):
    token: str #    JWT
