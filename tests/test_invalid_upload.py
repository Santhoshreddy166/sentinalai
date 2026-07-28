"""Test that uploading a .exe file is rejected with HTTP 415."""
import json
import urllib.request
import urllib.error

boundary = "----TestBoundary99999"
body = (
    "--{b}\r\n"
    'Content-Disposition: form-data; name="file"; filename="malware.exe"\r\n'
    "Content-Type: application/octet-stream\r\n\r\n"
    "fake binary data\r\n"
    "--{b}--\r\n"
).format(b=boundary).encode()

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/upload-log",
    data=body,
    headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
)

try:
    resp = urllib.request.urlopen(req)
    print("ERROR: Expected rejection but got", resp.status)
except urllib.error.HTTPError as e:
    result = json.loads(e.read().decode())
    print("Status:", e.code)
    print("Detail:", result["detail"])
    assert e.code == 415, "Expected 415, got {}".format(e.code)
    print("\nPASS: Invalid file type correctly rejected.")
