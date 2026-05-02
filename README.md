# Secure Student Portal

Secure Student Portal is a cybersecurity-focused web application inspired by the MiniPay reference project. It demonstrates real-world vulnerabilities such as SQL Injection and Cross-Site Scripting (XSS), along with their secure implementations. The system allows students to view academic records and enables administrators to manage student data. Additional features such as password hashing, account lockout, logging, and role-based access control enhance the system's security.

## Features

- Vulnerable `/login` route using string-built SQL for SQL Injection demonstration.
- Secure `/secure-login` route using parameterized queries, bcrypt password checking, and account lockout.
- Student dashboard showing marks, GPA, and attendance.
- Vulnerable `/search` route demonstrating reflected XSS.
- Secure `/secure-search` route using Jinja auto-escaping.
- Admin record management.
- Vulnerable admin add form with no validation.
- Secure admin add form with marks, attendance, and length validation.
- Login/search/security event logging to `logs.txt` and the `logs` database table.
- Role-based authorization for admin-only pages.

## Setup

```powershell
cd student_portal
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

- Vulnerable login: `http://127.0.0.1:5000/login`
- Secure login: `http://127.0.0.1:5000/secure-login`

## Demo Users

| Username | Password | Role |
| --- | --- | --- |
| admin | admin123 | admin |
| alice | alicepass | student |
| bob | bobpass | student |

## Demo Attacks

### SQL Injection

On `/login`:

- Username: `admin'--`
- Password: `anything`

This bypasses login because the vulnerable route builds SQL with raw user input.

### XSS

On `/search`:

```html
<script>alert('Hacked')</script>
```

The vulnerable route renders the search term as trusted HTML.

## Fix Explanation

- SQL Injection is fixed with parameterized queries.
- XSS is fixed by allowing Jinja to escape user input.
- Password security is improved with bcrypt hashing.
- Brute force attacks are reduced with a 45-second lock after 3 failed attempts.
- Unauthorized access is prevented with role-based checks.
