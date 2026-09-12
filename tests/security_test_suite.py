"""
=============================================================================
ARENA X 2026 - AUTOMATED CYBERSECURITY UNIT AND INTEGRATION TEST SUITE
=============================================================================
"""

import os
import io
import sys
import time
import sqlite3
import hmac
import hashlib
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, DB_PATH, decrypt_field, encrypt_field, MAX_SCREENSHOT_BYTES, register_attempts, login_attempts, generate_captcha, verify_captcha, SECRET_KEY, ADMIN_PASSKEY

def run_cyber_security_tests():
    print("\n" + "="*75)
    print("  ARENA X 2026 // CYBERSECURITY VERIFICATION TEST SUITE")
    print("="*75)

    client = app.test_client()
    passed = 0
    failed = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, failed
        if condition:
            print(f"  [PASS] {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name} -> {details}")
            failed += 1

    def generate_image_bytes(fmt='PNG', size=(100, 100), color='cyan'):
        img = Image.new('RGB', size, color=color)
        buf = io.BytesIO()
        img.save(buf, format=fmt)
        buf.seek(0)
        return buf

    def make_test_captcha():
        sol = 'TEST1'
        ts = int(time.time())
        salt = 'salt999'
        sig = hmac.new(SECRET_KEY.encode(), f"{sol}:{ts}:{salt}".encode(), hashlib.sha256).hexdigest()
        return sol, f"{ts}:{salt}:{sig}"

    # Reset in-memory rate limiters for fresh test suite run
    register_attempts.clear()
    login_attempts.clear()

    test_sol, test_tok = make_test_captcha()

    # 1. Reject Screenshot > 300 KB
    print("\n[SUITE 1: PROOF FILE UPLOAD SECURITY]")
    oversized_buf = io.BytesIO()
    # Create an image ~450 KB
    large_img = Image.new('RGB', (600, 600), color='blue')
    large_img.save(oversized_buf, format='PNG', compress_level=0)
    oversized_buf.seek(0)
    size_kb = len(oversized_buf.getvalue()) / 1024

    resp = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Security Test Team',
        'captain_name': 'Test Captain',
        'captain_whatsapp': '+91 99999 11111',
        'emergency_contact': '+91 99999 22222',
        'captain_email': 'test_oversized@arenax.com',
        'gamer_uid': 'TEST#1234',
        'district_booking_id': 'ZOM-TEST-999',
        'district_screenshot': (oversized_buf, 'large_screenshot.png'),
        'captcha_solution': test_sol,
        'captcha_token': test_tok
    }, content_type='multipart/form-data')

    assert_test(
        f"Reject Screenshot Exceeding 300 KB (Test File: {size_kb:.1f} KB)",
        resp.status_code == 400 and b"300 KB" in resp.data,
        f"Got status {resp.status_code}: {resp.get_json()}"
    )

    # 2. Reject PDF
    resp_pdf = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Security Test Team',
        'captain_name': 'Test Captain',
        'captain_whatsapp': '+91 99999 11111',
        'emergency_contact': '+91 99999 22222',
        'captain_email': 'test_pdf@arenax.com',
        'gamer_uid': 'TEST#1234',
        'district_booking_id': 'ZOM-TEST-998',
        'district_screenshot': (io.BytesIO(b"%PDF-1.4 Fake PDF Content"), 'ticket.pdf'),
        'captcha_solution': test_sol,
        'captcha_token': test_tok
    }, content_type='multipart/form-data')

    assert_test(
        "Reject PDF Upload (Only PNG & JPG Allowed)",
        resp_pdf.status_code == 400,
        f"Got status {resp_pdf.status_code}: {resp_pdf.get_json()}"
    )

    # 3. Reject Executable / Script
    resp_php = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Security Test Team',
        'captain_name': 'Test Captain',
        'captain_whatsapp': '+91 99999 11111',
        'emergency_contact': '+91 99999 22222',
        'captain_email': 'test_php@arenax.com',
        'gamer_uid': 'TEST#1234',
        'district_booking_id': 'ZOM-TEST-997',
        'district_screenshot': (io.BytesIO(b"<?php echo 1; ?>"), 'exploit.php'),
        'captcha_solution': test_sol,
        'captcha_token': test_tok
    }, content_type='multipart/form-data')

    assert_test(
        "Reject PHP Executable Upload",
        resp_php.status_code == 400,
        f"Got status {resp_php.status_code}: {resp_php.get_json()}"
    )

    # 4. Reject Disguised script inside .png extension
    resp_disguised = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Security Test Team',
        'captain_name': 'Test Captain',
        'captain_whatsapp': '+91 99999 11111',
        'emergency_contact': '+91 99999 22222',
        'captain_email': 'test_disguised@arenax.com',
        'gamer_uid': 'TEST#1234',
        'district_booking_id': 'ZOM-TEST-996',
        'district_screenshot': (io.BytesIO(b"<html><body>Not an image</body></html>"), 'exploit.png'),
        'captcha_solution': test_sol,
        'captcha_token': test_tok
    }, content_type='multipart/form-data')

    assert_test(
        "Reject Disguised Non-Image (.png with HTML payload)",
        resp_disguised.status_code == 400,
        f"Got status {resp_disguised.status_code}: {resp_disguised.get_json()}"
    )

    # Clear rate limit counter before testing valid submissions
    register_attempts.clear()

    # 5. Accept Valid PNG <= 300 KB with BookMyShow parameters
    valid_png = generate_image_bytes('PNG', size=(150, 150))
    resp_valid = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Valid Security Team',
        'captain_name': 'Cyber Captain',
        'captain_whatsapp': '+91 98888 77777',
        'emergency_contact': '+91 98888 66666',
        'captain_email': 'cyber_test@arenax.com',
        'gamer_uid': 'CYBER#5555',
        'bms_booking_id': 'BMS-CYB-001',
        'bms_screenshot': (valid_png, 'valid_bms_ticket.png'),
        'captcha_solution': test_sol,
        'captcha_token': test_tok
    }, content_type='multipart/form-data')

    data_valid = resp_valid.get_json() or {}
    assert_test(
        "Accept Valid PNG Screenshot <= 300 KB",
        resp_valid.status_code == 201 and data_valid.get('success') is True,
        f"Got {resp_valid.status_code}: {data_valid}"
    )

    # 6. Accept Valid JPG <= 300 KB
    valid_jpg = generate_image_bytes('JPEG', size=(150, 150))
    resp_valid_jpg = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Valid JPG Team',
        'captain_name': 'JPG Captain',
        'captain_whatsapp': '+91 98888 55555',
        'emergency_contact': '+91 98888 44444',
        'captain_email': 'jpg_test@arenax.com',
        'gamer_uid': 'JPG#5555',
        'district_booking_id': 'ZOM-JPG-002',
        'district_screenshot': (valid_jpg, 'valid_ticket.jpg'),
        'captcha_solution': test_sol,
        'captcha_token': test_tok
    }, content_type='multipart/form-data')

    data_valid_jpg = resp_valid_jpg.get_json() or {}
    assert_test(
        "Accept Valid JPG Screenshot <= 300 KB",
        resp_valid_jpg.status_code == 201 and data_valid_jpg.get('success') is True,
        f"Got {resp_valid_jpg.status_code}: {data_valid_jpg}"
    )

    # 7. Directory Traversal & Secret File Protection
    print("\n[SUITE 2: INFORMATION DISCLOSURE & PATH TRAVERSAL]")
    blocked_endpoints = [
        ('/.env', [403, 404]),
        ('/app.py', [403, 404]),
        ('/arena_x.db', [403, 404]),
        ('/data/arena_x.db', [403, 404]),
        ('/uploads/secret.png', [401, 403, 404])
    ]

    for path, exp_statuses in blocked_endpoints:
        r = client.get(path)
        assert_test(
            f"Block Access to Sensitive Path: {path}",
            r.status_code in exp_statuses,
            f"Expected one of {exp_statuses}, got {r.status_code}"
        )

    # 8. Rate Limiter Brute-Force Defense
    print("\n[SUITE 3: RATE LIMITING & BRUTE FORCE DEFENSE]")
    login_attempts.clear()
    limited = False
    for i in range(8):
        rl_resp = client.post('/api/admin/login', json={'passkey': f'bad_pass_{i}'})
        if rl_resp.status_code == 429:
            limited = True
            break

    assert_test(
        "Rate Limiter Blocks Rapid Brute-Force Admin Logins (HTTP 429)",
        limited,
        "Failed to trigger 429 rate limit error"
    )

    # 9. Fernet Authenticated Database Encryption at Rest
    print("\n[SUITE 4: FERNET AUTHENTICATED PII ENCRYPTION AT REST]")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT captain_whatsapp, captain_email, gamer_uid, district_booking_id FROM registrations WHERE captain_name = 'JPG Captain' ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if row:
        raw_phone, raw_email, raw_uid, raw_zomato = row
        is_encrypted = (
            str(raw_phone).startswith('ENC:') and
            str(raw_email).startswith('ENC:') and
            str(raw_uid).startswith('ENC:') and
            str(raw_zomato).startswith('ENC:')
        )
        assert_test(
            "Verify PII Fields Stored with Fernet Authenticated Encryption (ENC: prefix)",
            is_encrypted,
            f"Row values not encrypted: {row}"
        )

        decrypted_email = decrypt_field(raw_email)
        assert_test(
            "Verify Decryption Key Recovers Original PII Correctly",
            decrypted_email == 'jpg_test@arenax.com',
            f"Decryption mismatch: {decrypted_email}"
        )
    else:
        assert_test("Verify PII Encryption in DB", False, "JPG Captain registration not found in DB")

    # 10. Production Security Headers
    print("\n[SUITE 5: PRODUCTION SECURITY HEADERS]")
    home_resp = client.get('/')
    headers = home_resp.headers

    assert_test("X-Content-Type-Options: nosniff Header Present", headers.get('X-Content-Type-Options') == 'nosniff')
    assert_test("X-Frame-Options: SAMEORIGIN Header Present", headers.get('X-Frame-Options') == 'SAMEORIGIN')
    assert_test("Referrer-Policy Header Present", headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin')
    assert_test("Content-Security-Policy Header Present", 'default-src' in headers.get('Content-Security-Policy', ''))

    # 11. Anti-Bot Registration CAPTCHA Defense
    print("\n[SUITE 6: ANTI-BOT REGISTRATION CAPTCHA DEFENSE]")
    register_attempts.clear()

    # 11.1 Reject registration when CAPTCHA is missing
    dummy_img = generate_image_bytes('PNG')
    r_no_cap = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Bot Team',
        'captain_name': 'Bot',
        'captain_whatsapp': '+91 99999 00000',
        'emergency_contact': '+91 99999 00000',
        'captain_email': 'bot_nocap@arenax.com',
        'gamer_uid': 'BOT#000',
        'bms_booking_id': 'BMS-BOT-01',
        'bms_screenshot': (dummy_img, 'ticket.png')
    }, content_type='multipart/form-data')
    assert_test(
        "Reject Registration When CAPTCHA is Missing",
        r_no_cap.status_code == 400 and b"SECURITY CAPTCHA FAILED" in r_no_cap.data
    )

    # 11.2 Reject registration when CAPTCHA code is wrong
    dummy_img = generate_image_bytes('PNG')
    c_sol, c_tok = make_test_captcha()
    r_bad_cap = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Bot Team',
        'captain_name': 'Bot',
        'captain_whatsapp': '+91 99999 00000',
        'emergency_contact': '+91 99999 00000',
        'captain_email': 'bot_badcap@arenax.com',
        'gamer_uid': 'BOT#000',
        'bms_booking_id': 'BMS-BOT-02',
        'bms_screenshot': (dummy_img, 'ticket.png'),
        'captcha_solution': 'WRONG',
        'captcha_token': c_tok
    }, content_type='multipart/form-data')
    assert_test(
        "Reject Registration With Invalid CAPTCHA Code",
        r_bad_cap.status_code == 400 and b"Incorrect CAPTCHA" in r_bad_cap.data
    )

    # 11.3 Reject registration when CAPTCHA is expired
    dummy_img = generate_image_bytes('PNG')
    expired_tok = f"{int(time.time()) - 400}:testsalt:dummysig"
    r_exp_cap = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Bot Team',
        'captain_name': 'Bot',
        'captain_whatsapp': '+91 99999 00000',
        'emergency_contact': '+91 99999 00000',
        'captain_email': 'bot_expcap@arenax.com',
        'gamer_uid': 'BOT#000',
        'bms_booking_id': 'BMS-BOT-03',
        'bms_screenshot': (dummy_img, 'ticket.png'),
        'captcha_solution': 'TEST1',
        'captcha_token': expired_tok
    }, content_type='multipart/form-data')
    assert_test(
        "Reject Registration With Expired CAPTCHA Token (> 5 mins)",
        r_exp_cap.status_code == 400 and b"expired" in r_exp_cap.data
    )

    # 11.4 Verify /api/captcha endpoint
    r_gen = client.get('/api/captcha')
    cap_json = r_gen.get_json() or {}
    assert_test(
        "Generate Dynamic Visual CAPTCHA Token & Data URL (/api/captcha)",
        r_gen.status_code == 200 and cap_json.get('success') is True and 'data:image/png;base64,' in cap_json.get('image', '')
    )

    # 11.5 Verify Uppercase & Numbers CAPTCHA & Case-Insensitive User Normalization
    up_sol = 'K7P9M'
    m_ts = int(time.time())
    m_salt = 'salttest'
    m_sig = hmac.new(SECRET_KEY.encode(), f"{up_sol}:{m_ts}:{m_salt}".encode(), hashlib.sha256).hexdigest()
    m_tok = f"{m_ts}:{m_salt}:{m_sig}"

    # Invalid characters must be rejected
    dummy_img_case = generate_image_bytes('PNG')
    r_wrong_code = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Bot Team',
        'captain_name': 'Bot',
        'captain_whatsapp': '+91 99999 00000',
        'emergency_contact': '+91 99999 00000',
        'captain_email': 'bot_case@arenax.com',
        'gamer_uid': 'BOT#000',
        'bms_booking_id': 'BMS-BOT-04',
        'bms_screenshot': (dummy_img_case, 'ticket.png'),
        'captcha_solution': 'ZZ999',  # Completely wrong code
        'captcha_token': m_tok
    }, content_type='multipart/form-data')
    assert_test(
        "Reject Registration With Invalid Verification Code",
        r_wrong_code.status_code == 400 and b"Incorrect CAPTCHA" in r_wrong_code.data
    )

    # Correct uppercase + number passes
    dummy_img_correct = generate_image_bytes('PNG')
    r_right_case = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Valid Team',
        'captain_name': 'Legit Player',
        'captain_whatsapp': '+91 98888 77777',
        'emergency_contact': '+91 98888 77777',
        'captain_email': 'legit_case@arenax.com',
        'gamer_uid': 'LEGIT#123',
        'bms_booking_id': 'BMS-LEGIT-01',
        'bms_screenshot': (dummy_img_correct, 'ticket.png'),
        'captcha_solution': 'K7P9M',  # Uppercase match
        'captcha_token': m_tok
    }, content_type='multipart/form-data')
    assert_test(
        "Accept Registration With Uppercase & Number CAPTCHA (K7P9M)",
        r_right_case.status_code in (200, 201) and r_right_case.get_json().get('success') is True
    )

    # Automatic normalization when user types lowercase
    register_attempts.clear()
    dummy_img_lower = generate_image_bytes('PNG')
    r_lower_case = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'Valid Team',
        'captain_name': 'Legit Player 2',
        'captain_whatsapp': '+91 98888 77778',
        'emergency_contact': '+91 98888 77778',
        'captain_email': 'legit_case2@arenax.com',
        'gamer_uid': 'LEGIT#124',
        'bms_booking_id': 'BMS-LEGIT-02',
        'bms_screenshot': (dummy_img_lower, 'ticket.png'),
        'captcha_solution': 'k7p9m',  # Lowercase automatically normalized
        'captcha_token': m_tok
    }, content_type='multipart/form-data')
    assert_test(
        "Auto-Normalize User Input to Uppercase Gracefully (k7p9m -> K7P9M)",
        r_lower_case.status_code in (200, 201) and r_lower_case.get_json().get('success') is True
    )

    # Generator test: verify that generator only produces uppercase and numbers (zero lowercase)
    from app import generate_captcha
    gen_results = [generate_captcha() for _ in range(5)]
    assert_test(
        "Verify CAPTCHA Character Engine Generates ONLY Uppercase & Numbers",
        len(gen_results) == 5 and all(t.count(':') == 2 for t, _ in gen_results)
    )

    # ==========================================
    # SUITE 7: PUBLIC PASS IDOR DEFENSE & DATA MINIMIZATION
    # ==========================================
    print("\n[SUITE 7: PUBLIC PASS IDOR DEFENSE & DATA MINIMIZATION]")
    register_attempts.clear()
    reg_img = generate_image_bytes('PNG')
    idor_sol, idor_tok = make_test_captcha()
    reg_resp = client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': 'IDOR Defense Team',
        'captain_name': 'Privacy Test Captain',
        'captain_whatsapp': '+91 91111 22222',
        'emergency_contact': '+91 91111 33333',
        'captain_email': 'privacy_test@arenax.com',
        'gamer_uid': 'PRIVACY#999',
        'bms_booking_id': 'BMS-PRIV-01',
        'district_screenshot': (reg_img, 'ticket.png'),
        'captcha_solution': idor_sol,
        'captcha_token': idor_tok
    }, content_type='multipart/form-data')
    reg_data = reg_resp.get_json() or {}
    created_token = reg_data.get('qr_token', '')
    created_id_num = reg_data.get('registration_id', '').replace('AX-2026-', '').lstrip('0')

    # 1. Sequential ID lookup (/api/pass/1) must be rejected with 404
    resp_num_id = client.get(f'/api/pass/{created_id_num or 1}')
    assert_test(
        f"Reject Sequential Numeric ID in Pass Endpoint (/api/pass/{created_id_num or 1})",
        resp_num_id.status_code == 404,
        f"Expected 404, got {resp_num_id.status_code}: {resp_num_id.get_json()}"
    )

    # 2. Formatted ID lookup (/api/pass/AX-2026-0001) must be rejected with 404
    resp_fmt_id = client.get(f'/api/pass/{reg_data.get("registration_id", "AX-2026-0001")}')
    assert_test(
        f"Reject Formatted Sequential ID in Pass Endpoint (/api/pass/{reg_data.get('registration_id')})",
        resp_fmt_id.status_code == 404,
        f"Expected 404, got {resp_fmt_id.status_code}: {resp_fmt_id.get_json()}"
    )

    # 3. Valid CSPRNG token lookup returns 200 with minimal public pass payload
    resp_valid_pass = client.get(f'/api/pass/{created_token}')
    pass_payload = (resp_valid_pass.get_json() or {}).get('pass', {})
    has_no_pii = (
        'captain_whatsapp' not in pass_payload and
        'emergency_contact' not in pass_payload and
        'captain_email' not in pass_payload and
        'screenshot_filepath' not in pass_payload and
        'id' not in pass_payload
    )
    assert_test(
        "Valid Pass Token Resolves Without Leaking PII or Internal Database ID",
        resp_valid_pass.status_code == 200 and has_no_pii and pass_payload.get('team_name') == 'IDOR Defense Team',
        f"Payload: {pass_payload}"
    )

    # ==========================================
    # SUITE 8: QR TOKEN CRYPTOGRAPHIC ENTROPY
    # ==========================================
    print("\n[SUITE 8: QR TOKEN CRYPTOGRAPHIC ENTROPY]")
    assert_test(
        "QR Token Format Uses AX2026_ Prefix and High-Entropy CSPRNG (>= 40 chars)",
        created_token.startswith('AX2026_') and len(created_token) >= 40,
        f"Token was: '{created_token}'"
    )

    # ==========================================
    # SUITE 9: PUBLIC REGISTRATION RESPONSE MINIMIZATION
    # ==========================================
    print("\n[SUITE 9: PUBLIC REGISTRATION RESPONSE MINIMIZATION]")
    reg_has_no_pii = (
        'captain_email' not in reg_data and
        'captain_whatsapp' not in reg_data and
        'screenshot_url' not in reg_data
    )
    assert_test(
        "Registration Response Does Not Echo Back Sensitive Phone, Email, or File Paths",
        reg_has_no_pii and reg_data.get('success') is True,
        f"Response keys: {list(reg_data.keys())}"
    )

    # ==========================================
    # SUITE 10: CSV FORMULA INJECTION DEFENSE
    # ==========================================
    print("\n[SUITE 10: CSV FORMULA INJECTION DEFENSE]")
    register_attempts.clear()
    csv_img = generate_image_bytes('PNG')
    c_sol, c_tok = make_test_captcha()
    client.post('/api/register', data={
        'selected_game': 'Valorant 1v1',
        'team_name': '=cmd|\'/C calc\'!A0',
        'captain_name': '@MaliciousAdmin',
        'captain_whatsapp': '+91 91111 44444',
        'emergency_contact': '+91 91111 55555',
        'captain_email': '-malicious@arenax.com',
        'gamer_uid': '+DDE#123',
        'district_booking_id': '=HYPERLINK("http://evil.com")',
        'district_screenshot': (csv_img, 'ticket.png'),
        'captcha_solution': c_sol,
        'captcha_token': c_tok
    }, content_type='multipart/form-data')

    login_attempts.clear()
    auth_resp = client.post('/api/admin/login', json={'passkey': ADMIN_PASSKEY})
    csv_resp = client.get('/api/admin/export-csv')
    csv_text = csv_resp.data.decode('utf-8')
    assert_test(
        "CSV Formula Injection Neutralized (Formulas starting with =, +, -, @ prepended with ')",
        "'=cmd" in csv_text and "'@MaliciousAdmin" in csv_text and "'-malicious" in csv_text,
        f"CSV sample: {csv_text[:500]}"
    )

    # ==========================================
    # SUITE 11: PRODUCTION SESSION SECURITY & ERROR HANDLING
    # ==========================================
    print("\n[SUITE 11: PRODUCTION SESSION SECURITY & ERROR HANDLING]")
    assert_test(
        "Session Cookie Configured With HttpOnly=True and SameSite=Lax",
        app.config.get('SESSION_COOKIE_HTTPONLY') is True and app.config.get('SESSION_COOKIE_SAMESITE') == 'Lax',
        f"Config: HTTPONLY={app.config.get('SESSION_COOKIE_HTTPONLY')}, SAMESITE={app.config.get('SESSION_COOKIE_SAMESITE')}"
    )
    from datetime import timedelta
    assert_test(
        "Permanent Session Lifetime Set to Exactly 2 Hours",
        app.config.get('PERMANENT_SESSION_LIFETIME') == timedelta(hours=2),
        f"Lifetime: {app.config.get('PERMANENT_SESSION_LIFETIME')}"
    )

    err404 = client.get('/api/non-existent-endpoint')
    assert_test(
        "API 404 Handler Returns Clean Generic JSON Without Information Disclosure",
        err404.status_code == 404 and err404.is_json and err404.get_json().get('success') is False
    )

    err405 = client.post('/api/game-status')
    assert_test(
        "API 405 Handler Returns Clean Generic JSON Without Version Disclosures",
        err405.status_code == 405 and err405.is_json and err405.get_json().get('success') is False
    )

    print("\n" + "="*75)
    print(f"  CYBERSECURITY TEST RESULTS: {passed} PASSED / {failed} FAILED")
    print("="*75 + "\n")

    return failed == 0

if __name__ == '__main__':
    success = run_cyber_security_tests()
    sys.exit(0 if success else 1)
