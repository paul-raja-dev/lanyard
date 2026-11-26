from fastapi import FastAPI
import jwt
app = FastAPI()

@app.get("/health")
def health_check():
    return {'msg' : 'Healthy and connection is good'}


with open("public.pem", "r") as f:
    PUBLIC_KEY = f.read()

KEY_ID = "auth-key-1"


@app.get("/.well-known/jwks.json")
def get_jwks():
    """
    Exposes the public key in standard JWKS format.
    Client apps will call this URL to verify JWTs issued by this service.
    """
    # Convert PEM string into a JWK dictionary
    jwk_obj = jwt.PyJWK.from_pem(PUBLIC_KEY)
    jwk_dict = jwk_obj.to_dict()

    # Add standard JWKS metadata fields
    jwk_dict["kid"] = KEY_ID  # Key ID
    jwk_dict["use"] = "sig"  # Intended use: signature verification
    jwk_dict["alg"] = "RS256"  # Algorithm used

    # JWKS always returns a JSON object with a "keys" array
    return {"keys": [jwk_dict]}
