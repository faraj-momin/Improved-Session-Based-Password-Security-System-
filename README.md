# Improved-Session-Based-Password-Security-System-

# Session-Based Password Security System

## Overview
This project is a secure, session-based password management system implemented in Python using the Tkinter library for the GUI. It incorporates modern password hashing techniques, session management, and user authentication, providing a safe environment for managing user accounts.

## Features
- **User Registration**: Securely create new users with password hashing using SHA-256 and salted passwords.
- **Login System**: Authenticate users by checking hashed passwords and generating session IDs.
- **Session Management**: Validate sessions with automatic expiration after a predefined time limit (1 hour).
- **Password Change**: Allows users to update their password after authentication, maintaining security.
- **Logout Functionality**: Terminate active sessions and remove them from the active sessions database.

## Requirements
- Python 3.x
- Tkinter
- hashlib
- secrets
- time

## How to Run
1. Clone this repository.
2. Run `python3 app.py` to start the GUI.
3. Use the GUI for registration, login, and session management.

## License
This project is licensed under the MIT License.
