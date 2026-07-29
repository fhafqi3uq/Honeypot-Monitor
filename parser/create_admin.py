"""
Interactive CLI to create a dashboard account. Defaults to the "admin" role
(full access); pass --role viewer (or run create_viewer.py, a thin wrapper
around this same logic) to create a read-only account instead - see
auth.require_admin() for exactly which endpoints "viewer" is blocked from.

Run from parser/ with its venv active:

    python create_admin.py                 # admin (default)
    python create_admin.py --role viewer    # read-only account
    python create_viewer.py                 # equivalent to the line above

Prompts for username and password (hidden input, typed twice to confirm) -
never pass them as command-line arguments or environment variables, since
those can leak through shell history or `ps`. The password is bcrypt-hashed
before being stored; the plaintext is never written anywhere.
"""

from __future__ import annotations

import argparse
import getpass
import sys

import auth

MIN_PASSWORD_LENGTH = 8


def create_account(role: str) -> None:
    if role not in auth.VALID_ROLES:
        print(f"Role không hợp lệ: {role} (phải là 'admin' hoặc 'viewer')")
        sys.exit(1)

    label = "quản trị (admin)" if role == auth.ROLE_ADMIN else "chỉ xem (viewer)"
    print(f"=== Tạo tài khoản {label} cho Dashboard ===\n")

    username = input("Username: ").strip()
    if not username:
        print("Username không được để trống.")
        sys.exit(1)

    if auth.users_col.find_one({"username": username}):
        confirm = input(
            f"Username '{username}' đã tồn tại. Đặt lại mật khẩu/role cho tài khoản này? [y/N]: "
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
        {"$set": {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "created_at": auth._now(),
        }},
        upsert=True,
    )
    print(f"\n✅ Đã tạo/cập nhật tài khoản '{username}' (role: {role}). Đăng nhập tại dashboard/login.html.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--role", choices=auth.VALID_ROLES, default=auth.ROLE_ADMIN,
        help="Quyền của tài khoản mới (mặc định: admin)",
    )
    args = parser.parse_args()
    create_account(args.role)


if __name__ == "__main__":
    main()
