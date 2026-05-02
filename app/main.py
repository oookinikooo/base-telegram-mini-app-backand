import hashlib
import hmac
import json
import secrets
import urllib.parse
from datetime import datetime, timedelta
from operator import itemgetter

from config import config
from fastapi import Depends, FastAPI
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://dev-app-87355.firebaseapp.com/"],  # Your Vite dev server
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


oauth2_schema = HTTPBearer()

class InitDataRequest(BaseModel):
    initData: str


def verify_telegram_init_data(init_data: str) -> dict:
    parsed = dict(urllib.parse.parse_qsl(init_data))
    if "hash" not in parsed:
        raise HTTPException(status_code=400, detail="Missing hash")

    received_hash = parsed.pop("hash")

    data_check_string = "\n".join(
        f"{k}={v}" for k, v in sorted(parsed.items(), key=itemgetter(0))
    )

    secret_key = hmac.new(
        b"WebAppData",
        config.TOKEN.encode(), 
        hashlib.sha256
    ).digest()

    expected_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_hash, received_hash): 
        raise HTTPException(status_code=403, detail="Invalid auth data")

    return parsed

active_session = {}

@app.post('/auth/telegram')
async def telegram_auth(request: InitDataRequest):
    try:
        valid_data = verify_telegram_init_data(request.initData)
        user_data = json.loads(valid_data['user'])
        user_id = user_data['id']

        # session_id = secrets.token_urlsafe(32)
        jwt_token = jwt.encode(
            {
                "user_id": user_id,
                # "session_id": session_id,
                "exp": datetime.utcnow() + timedelta(minutes=1),
            },
            config.SECRET_KEY,
            algorithm="HS256",
        )

        # active_session[session_id] = {
        #     "user_id": user_id,
        #     "created_at": datetime.utcnow(),
        # }

        data = {
            "token": jwt_token,
            "user": user_data,
        }
        print(data)
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid Telegram auth")
    else:
        return data


async def get_current_user(token: str = Depends(oauth2_schema)):
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        # user_id = payload.get("user_id")
        expired = payload.get("exp")
        print(f"payload: {payload}\nexpired str: {expired}")

        if expired:
            raise HTTPException(status_code=401, detail="Session expired")

        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid Telegram auth")

@app.get("/api/user/data")
async def get_user_data(current_user: dict = Depends(get_current_user)):
    return {"data": f"Hello {current_user['user_id']}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=4444, reload=True)
