"""
Interactive CLI to create a dashboard admin account.

Run from parser/ with its venv active:

    python create_admin.py

Prompts for username and password (hidden input, typed twice to confirm) -
never pass them as command-line arguments or environment variables, since
those can leak through shell history or `ps`. The password is bcrypt-hashed
before being stored; the plaintext is never written anywhere.
"""

from __future__ import annotations

import getpass
import sys

import auth

MIN_PASSWORD_LENGTH = 8


def main() -> None:
    print("=== Tạo tài khoản quản trị Dashboard ===\n")

    username = input("Username: ").strip()
    if not username:
        print("Username không được để trống.")
        sys.exit(1)

    if auth.users_col.find_one({"username": username}):
        confirm = input(
            f"Username '{username}' đã tồn tại. Đặt lại mật khẩu cho tài khoản này? [y/N]: "
        ).strip().lower()
        if confirm != "y":
            print("Đã hủy.")
            sys.exit(0)

    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"Password phải có ít nhất {MIN_PASSWORD_LENGTH} ký tự.")
        sys.exit(1)

    password_confirm = getpass.getpass("Nhập lại password: ")
    if password != password_confirm:
        print("Hai mật khẩu không khớp.")
        sys.exit(1)

    password_hash = auth.hash_password(password)
    auth.users_col.update_one(
        {"username": username},
        {"$set": {"username": username, "password_hash": password_hash, "created_at": auth._now()}},
        upsert=True,
    )
    print(f"\n✅ Đã tạo/cập nhật tài khoản '{username}'. Đăng nhập tại dashboard/login.html.")


if __name__ == "__main__":
    main()
