from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health_check():
    return {'msg' : 'Healthy and connection is good'}

