import os 
from dotenv import load_dotenv

load_dotenv()

#---- LOAD MINIO ENV VARIABLES --------------------------------------------
 
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false")

def minio_client():
    from minio import Minio
    return Minio(
        MINIO_ENDPOINT,
        access_key=os.getenv("MINIO_ACCESS_KEY", ""),
        secret_key=os.getenv("MINIO_SECRET_KEY", ""),
        secure=os.getenv("MINIO_SECURE", "false").lower() in ("1", "true", "yes"),
    )
