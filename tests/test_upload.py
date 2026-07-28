"""Quick smoke test for the /api/upload-log endpoint."""
import json
import urllib.request
from email.mime.multipart import MIMEMultipart
import io
import http.client

# Read the sample log file
with open(r"tests\sample_logs\mixed_format.log", "rb") as f:
    file_data = f.read()

# Build multipart form data manually
boundary = "----TestBoundary12345"
body = (
    "--{b}\r\n"
    'Content-Disposition: form-data; name="file"; filename="mixed_format.log"\r\n'
    "Content-Type: application/octet-stream\r\n\r\n"
).format(b=boundary).encode() + file_data + "\r\n--{b}--\r\n".format(b=boundary).encode()

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/upload-log",
    data=body,
    headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
)
resp = urllib.request.urlopen(req)
result = json.loads(resp.read().decode())
print(json.dumps(result, indent=2))
