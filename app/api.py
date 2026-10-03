"""Read-only loopback API. No upload or automated response endpoints."""
from fastapi import FastAPI, HTTPException
from app.storage import read

api = FastAPI(title='AetherSOC', version='1.0.0')

@api.get('/health')
def health():
    return {'status': 'ok', 'mode': 'synthetic-local'}

@api.get('/alerts')
def alerts():
    return read('alerts')

@api.get('/incidents')
def incidents():
    return read('incidents')

@api.get('/incidents/{incident_id}')
def incident(incident_id: str):
    for item in read('incidents'):
        if item['incident_id'] == incident_id:
            return item
    raise HTTPException(status_code=404, detail='Incident not found')
