"""
Interactive CLI to create a read-only ("viewer") dashboard account.

Run from parser/ with its venv active:

    python create_viewer.py

Thin wrapper around create_admin.py's create_account() - see that file for
the full docstring and auth.require_admin() for exactly which endpoints a
viewer is blocked from (data export, and anything with a write side-effect).
"""

from __future__ import annotations

import auth
from create_admin import create_account

if __name__ == "__main__":
    create_account(auth.ROLE_VIEWER)
