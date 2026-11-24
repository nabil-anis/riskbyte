import os, json, requests

BASE_URL = 'http://127.0.0.1:8080'
TOKEN = os.getenv('RISKBYTE_INGEST_TOKEN') or 'dev-analyst'
HEADERS = {'Authorization': f'Bearer {TOKEN}'}

def get(endpoint):
    try:
        resp = requests.get(f'{BASE_URL}{endpoint}', headers=HEADERS)
        print(f'GET {endpoint} -> {resp.status_code}')
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text)
    except Exception as e:
        print(f'Error GET {endpoint}:', e)

def post_ingest():
    payload = {"events": [{"event_type": "login", "source_ip": "10.0.0.3", "username": "tester"}]}
    try:
        resp = requests.post(f'{BASE_URL}/api/ingest', json=payload, headers=HEADERS)
        print('POST /api/ingest ->', resp.status_code)
        print(resp.text)
    except Exception as e:
        print('Error POST ingest:', e)

if __name__ == '__main__':
    for ep in ['/api/alerts', '/api/license', '/api/cases', '/api/audit', '/api/stats']:
        get(ep)
    post_ingest()
