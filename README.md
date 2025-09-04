# 🔐 Secure Authentication System (Python Tkinter)

A simple yet secure **desktop-based authentication system** developed as part of my internship at **Internee.pk**.
The project focuses on secure user login and registration with **bcrypt password hashing** and **AES-256 encryption**, built with **Python Tkinter** for GUI.

---

## 🚀 Features

* ✅ **User Registration & Login** with a friendly Tkinter GUI
* ✅ **Secure password storage** using `bcrypt` hashing
* ✅ **AES-256-GCM encryption** for sensitive data (emails)
* ✅ **SQLite database** for persistence
* ✅ **Account management** (Change password, Delete account, Logout)

---

## 🛠️ Tech Stack

* **Python 3.x**
* **Libraries:**

  * `tkinter` → GUI
  * `bcrypt` → Password hashing
  * `cryptography` → AES-256 encryption
  * `sqlite3` → Database
* **Platform:** Windows Virtual Machine

---

## 📂 Project Structure

```
secure-auth-system/
│-- app.py             # Main Tkinter application
│-- users.db           # SQLite database (auto-created on first run)
│-- master.key         # AES-256 encryption key (auto-generated)
│-- requirements.txt   # Python dependencies
│-- README.md          # Project documentation
```

---

## ⚡ Setup & Usage

1. Clone the repository:

```bash
git clone https://github.com/your-username/secure-auth-system.git
cd secure-auth-system
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
python app.py
```

---

## 🔒 Security Notes

* Passwords are stored as **bcrypt hashes** (not plain text).
* Emails are encrypted with **AES-256-GCM** before being stored.
* A `master.key` file is generated for AES encryption. **Keep it safe**.

---

## 🌟 Future Enhancements

Planned features for future iterations:

* 🔹 **Two-Factor Authentication (2FA)** using Google Authenticator (TOTP).
* 🔹 **OAuth 2.0 Login** (Google/GitHub/Microsoft).
* 🔹 **Better Key Management** (move from local files to secure KMS).
* 🔹 **Logging & Monitoring** of login attempts and activity.
* 🔹 **UI/UX improvements** with modern Tkinter themes.

---

## 📌 Internship Context

This project was developed as part of my **Internship at Internee.pk** to gain hands-on experience in:

* Secure application development
* Applying cryptography & authentication best practices
* Designing user-friendly GUIs with security in mind

---

## 👤 Author

**Ammad Aziz**
Intern at [Internee.pk](https://internee.pk)

---

👉 Do you also want me to add **screenshots of your Tkinter app** (Register/Login/Dashboard windows) into the README for a more professional GitHub presentation?
