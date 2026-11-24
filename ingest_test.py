import requests, json
url = 'http://127.0.0.1:8080/api/ingest'
payload = {
    "events": [
        {
            "event_type": "login",
            "source_ip": "10.0.0.2",
            "username": "tester"
        }
    ]
}
resp = requests.post(url, json=payload)
print('Status code:', resp.status_code)
print('Response body:', resp.text)
