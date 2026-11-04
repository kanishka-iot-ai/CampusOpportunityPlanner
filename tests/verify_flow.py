import re
from app import app

c = app.test_client()

print("--- Testing Public Pages ---")
for route in ['/', '/login', '/register']:
    r = c.get(route)
    print(f"GET {route} -> {r.status_code}")
    assert r.status_code == 200

print("\n--- Testing Student Login & Portal ---")
r = c.get('/login')
m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
csrf = m.group(1)

r_login = c.post('/login', data={
    'identifier': '26bit990001@cuchd.in',
    'password': 'UQJBC-6emzr6Zv73UoG6ziYf7G6pjwBR',
    'csrf_token': csrf
}, follow_redirects=True)
print(f"Student login result: {r_login.status_code}, current path: {r_login.request.path}")
assert r_login.request.path == '/student/dashboard'

for path in ['/student/dashboard', '/student/discover', '/student/profile', '/student/applications']:
    res = c.get(path)
    print(f"GET {path} -> {res.status_code}")
    assert res.status_code == 200

# Logout
r = c.get('/student/dashboard')
csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
r_logout = c.post('/logout', data={'csrf_token': csrf}, follow_redirects=True)
print(f"Student logout result: {r_logout.status_code}, path: {r_logout.request.path}")

print("\n--- Testing Admin Login & Portal ---")
r = c.get('/login')
csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
r_admin = c.post('/login', data={
    'identifier': 'report-demo-admin@example.test',
    'password': '6uPuwcfO5gf2IgOXW1QTAoZnMgj1toH_',
    'csrf_token': csrf
}, follow_redirects=True)
print(f"Admin login result: {r_admin.status_code}, current path: {r_admin.request.path}")
assert r_admin.request.path == '/admin/dashboard'

for path in ['/admin/dashboard', '/admin/opportunities', '/admin/applications', '/admin/opportunities/new']:
    res = c.get(path)
    print(f"GET {path} -> {res.status_code}")
    assert res.status_code == 200

print("\n>>> ALL TESTS PASSED SUCCESSFULLY! <<<")
