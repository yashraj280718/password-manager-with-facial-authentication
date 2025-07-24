# SecurePass Manager

A modern password manager with facial authentication, built using Python, Tkinter, OpenCV, and face_recognition. SecurePass Manager allows users to securely store and retrieve passwords for various sites and applications, using facial recognition for authentication.

## Features

- **Facial Authentication:** Register and log in using your face for enhanced security.
- **Password Storage:** Securely store passwords for different sites and applications.
- **Encryption:** Passwords are encrypted using Fernet symmetric encryption.
- **User-Friendly GUI:** Simple and intuitive interface built with Tkinter.
- **Automatic Form Filling:** (Planned) Automatically fill login forms for saved credentials.

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd password-manager
   ```
2. **Set up a virtual environment (optional but recommended):**
   ```bash
   python -m venv myvenv
   source myvenv/bin/activate  # On Windows: myvenv\Scripts\activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Required packages include:
   - tkinter
   - opencv-python
   - face_recognition
   - numpy
   - cryptography

## Usage

1. **Run the application:**
   ```bash
   python pass2.py
   ```
2. **Register:**
   - Click "Register" and enter a username.
   - Capture your face using your webcam.
   - Complete registration.
3. **Login:**
   - Enter your username and verify your face.
   - Access your dashboard to add or view passwords.
4. **Add/View Passwords:**
   - Add new credentials for sites/apps.
   - View saved passwords (decrypted after authentication).

## Security Notes

- Passwords are encrypted using a key stored in `secret.key`. Keep this file safe!
- Facial data is stored as face encodings (not raw images) for privacy.
- The database is stored locally in `passman.db`.

## Planned Features

- **Automatic Form Filling:** Automatically fill login forms in browsers using saved credentials (requires browser extension or automation integration).
- **Password Generator:** Generate strong passwords.
- **Multi-factor Authentication:** Add more security layers.

## License

MIT License

---

**Disclaimer:** This project is for educational purposes. Do not use it for highly sensitive or production environments without further security review. 