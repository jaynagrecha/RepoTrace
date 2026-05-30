import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DATA_DIR = Path('data')
USERS_FILE = DATA_DIR / 'users.json'
DATA_DIR.mkdir(exist_ok=True)


def _load() -> dict[str, Any]:
    if not USERS_FILE.exists():
        return {"users": {}, "sessions": {}}
    try:
        return json.loads(USERS_FILE.read_text(encoding='utf-8'))
    except Exception:
        return {"users": {}, "sessions": {}}


def _save(data: dict[str, Any]) -> None:
    tmp = USERS_FILE.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2), encoding='utf-8')
    tmp.replace(USERS_FILE)


def _pbkdf(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000)
    return base64.b64encode(dk).decode()


def _token_fingerprint(token: str) -> str:
    if not token:
        return ''
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def _domain_env_key(domain: str) -> str:
    safe = ''.join(ch if ch.isalnum() else '_' for ch in (domain or '').upper()).strip('_')
    return f'ORG_GITHUB_TOKEN_{safe}'


def _org_token_for_domain(domain: str) -> tuple[str, str]:
    """Return a server-side GitHub token for an org domain.

    Supported .env formats:
      ORG_GITHUB_TOKENS_JSON={"wu.com":"ghp_xxx","example.com":"ghp_yyy"}
      ORG_GITHUB_TOKEN_WU_COM=ghp_xxx
      ORG_GITHUB_TOKEN_DEFAULT=ghp_fallback
    """
    domain = (domain or '').strip().lower()
    raw = os.getenv('ORG_GITHUB_TOKENS_JSON', '').strip()
    if raw:
        try:
            mapping = json.loads(raw)
            val = (mapping.get(domain) or mapping.get('*') or '').strip()
            if val:
                return val, f'env-json:{domain if mapping.get(domain) else "*"}'
        except Exception:
            pass
    key = _domain_env_key(domain)
    val = os.getenv(key, '').strip()
    if val:
        return val, f'env:{key}'
    val = os.getenv('ORG_GITHUB_TOKEN_DEFAULT', '').strip()
    if val:
        return val, 'env:ORG_GITHUB_TOKEN_DEFAULT'
    return '', ''


class AuthManager:
    def register(self, email: str, password: str, github_token: str | None = None, org_name: str | None = None) -> dict[str, Any]:
        email = (email or '').strip().lower()
        if '@' not in email or len(email) < 6:
            raise ValueError('A valid organization/work email is required.')
        if not password or len(password) < 8:
            raise ValueError('Password must be at least 8 characters.')
        data = _load()
        if email in data.get('users', {}):
            raise ValueError('Account already exists. Please login instead.')
        salt = secrets.token_hex(16)
        domain = email.split('@', 1)[1]
        data.setdefault('users', {})[email] = {
            'email': email,
            'org_domain': domain,
            'org_name': (org_name or domain).strip(),
            'password_salt': salt,
            'password_hash': _pbkdf(password, salt),
            # No user-facing GitHub token collection. Org tokens are resolved server-side from .env by email domain.
            # Legacy fallback: if an older account had a stored token, it can still be used, but new UI does not collect it.
            'github_token': (github_token or '').strip(),
            'github_token_fingerprint': _token_fingerprint(github_token or ''),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_login': None,
            'searches': 0,
        }
        _save(data)
        env_token, source = _org_token_for_domain(domain)
        return {'ok': True, 'email': email, 'org_domain': domain, 'github_token_configured': bool(env_token or github_token), 'token_source': 'server_org_env' if env_token else ('legacy_user_token' if github_token else 'public_default')}

    def login(self, email: str, password: str) -> dict[str, Any]:
        email = (email or '').strip().lower()
        data = _load()
        user = data.get('users', {}).get(email)
        if not user:
            raise ValueError('Invalid email or password.')
        expected = user.get('password_hash') or ''
        actual = _pbkdf(password or '', user.get('password_salt') or '')
        if not hmac.compare_digest(expected, actual):
            raise ValueError('Invalid email or password.')
        session = secrets.token_urlsafe(32)
        user['last_login'] = datetime.now(timezone.utc).isoformat()
        data.setdefault('sessions', {})[session] = {
            'email': email,
            'created_at': datetime.now(timezone.utc).isoformat(),
        }
        _save(data)
        return {
            'ok': True,
            'session_token': session,
            'user': self.public_user(user),
        }

    def logout(self, session: str) -> dict[str, Any]:
        data = _load()
        data.get('sessions', {}).pop(session, None)
        _save(data)
        return {'ok': True}

    def public_user(self, user: dict[str, Any]) -> dict[str, Any]:
        env_token, source = _org_token_for_domain(user.get('org_domain') or '')
        legacy = user.get('github_token') or ''
        return {
            'email': user.get('email'),
            'org_domain': user.get('org_domain'),
            'org_name': user.get('org_name'),
            'github_token_configured': bool(env_token or legacy),
            'github_token_source': 'server_org_env' if env_token else ('legacy_user_token' if legacy else 'public_default'),
            'github_token_fingerprint': _token_fingerprint(env_token or legacy),
            'created_at': user.get('created_at'),
            'last_login': user.get('last_login'),
            'searches': user.get('searches', 0),
        }

    def user_from_session(self, session: Optional[str]) -> Optional[dict[str, Any]]:
        if not session:
            return None
        data = _load()
        s = data.get('sessions', {}).get(session)
        if not s:
            return None
        return data.get('users', {}).get(s.get('email'))


    def has_server_org_token(self, session: Optional[str]) -> bool:
        """True when a logged-in org user is routed to a server-side org GitHub token.

        These users should not consume the public RepoTrace search quota because
        their organization has a dedicated token configured in environment variables.
        """
        user = self.user_from_session(session)
        if not user:
            return False
        env_token, source = _org_token_for_domain(user.get('org_domain') or '')
        return bool(env_token)

    def user_github_token(self, session: Optional[str]) -> Optional[str]:
        user = self.user_from_session(session)
        if not user:
            return None
        env_token, source = _org_token_for_domain(user.get('org_domain') or '')
        if env_token:
            return env_token
        # Legacy fallback for accounts created by older versions. New UI no longer asks users for tokens.
        if user.get('github_token'):
            return user.get('github_token')
        return None

    def record_user_search(self, session: Optional[str], units: int = 1) -> None:
        if not session:
            return
        data = _load()
        s = data.get('sessions', {}).get(session)
        if not s:
            return
        u = data.get('users', {}).get(s.get('email'))
        if not u:
            return
        u['searches'] = int(u.get('searches') or 0) + int(units or 1)
        _save(data)

    def status(self, session: Optional[str]) -> dict[str, Any]:
        user = self.user_from_session(session)
        if not user:
            return {'authenticated': False}
        return {'authenticated': True, 'user': self.public_user(user)}


auth_manager = AuthManager()
