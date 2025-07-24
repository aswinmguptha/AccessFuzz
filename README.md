## 🚨 AccessFuzz - Automated Authorization Tester

AccessFuzz is a lightweight internal tool designed to help security teams identify **Broken Access Control** issues like **Horizontal** and **Vertical Privilege Escalation** in web APIs.

---

### ✨ Features

- ✅ Role-based request replay for API endpoints 
- ✅ Supports GET, POST, PUT, DELETE methods 
- ✅ Detects unauthorized access based on status codes 
- ✅ JSON report output 
- ✅ Minimal, extensible codebase 

---

### 🧪 What It Detects

| Type                               | Example                                 |
| ---------------------------------- | --------------------------------------- |
| 🔼 Vertical Privilege Escalation   | A `user` accessing an `/admin` endpoint |
| ↔️ Horizontal Privilege Escalation | A `user` accessing another user's data  |

---

### 📦 Requirements

* Python 3.7+
* `requests` library

Install dependencies:

```bash
pip install -r requirements.txt
```

---

### 🚀 Usage

#### **Configure Endpoints and Tokens**

Edit `accessfuzz.py` and set:

```python
# List of endpoints to test
endpoints = [
    {
        "method": "GET",
        "url": "http://localhost:5000/api/admin/dashboard",
        ...
    },
    ...
]

# Map of roles and their auth headers
role_tokens = {
    "admin": {"Authorization": "Bearer ADMIN_TOKEN"},
    "user": {"Authorization": "Bearer USER_TOKEN"},
    "guest": {"Authorization": "Bearer GUEST_TOKEN"},
}
```

#### **Run the Tool**

```bash
python3 accessfuzz.py
```

#### **View the Results**

* Console output shows status codes for each role
* JSON report saved to: `accessfuzz_report.json`
