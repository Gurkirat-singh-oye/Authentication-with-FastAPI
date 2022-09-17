from pydantic import BaseModel
from typing import Optional, Union, List


class Token(BaseModel):
    access_token: str
    token_type: Optional[str] = "Brearer"


class TokenData(BaseModel):
    username: Union[str, None] = None
    scopes: List[str] = []