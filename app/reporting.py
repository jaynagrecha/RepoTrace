import json
import os
import smtplib
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

REPORT_DIR = Path('data/reports')
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def malicious_file_evidence(result: dict[str, Any] | None) -> list[dict[str, str]]:
    """Return only VT-malicious files as reporting evidence.

    RepoTrace report workflow intentionally restricts GitHub abuse-report
    templates to cases where VirusTotal marks at least one repository file
    as malicious. Evidence is minimal by design: file path + VT report link.
    """
    result = result or {}
    evidence = []
    for f in result.get('files_analyzed') or []:
        vt = f.get('vt') or f.get('virustotal') or {}
        if (vt.get('verdict') or '').lower() != 'malicious':
            continue
        path = f.get('path') or f.get('name') or f.get('filename') or 'unknown-file'
        link = vt.get('permalink') or vt.get('vt_link') or ''
        sha256 = (f.get('hashes') or {}).get('sha256') or f.get('sha256') or ''
        if not link and sha256:
            link = f'https://www.virustotal.com/gui/file/{sha256}'
        evidence.append({'path': str(path), 'vt_link': str(link), 'sha256': str(sha256)})
    return evidence


def build_report_template(kind: str, target_url: str, analyst_email: str | None, reason: str | None, result: dict[str, Any] | None = None, analyst_name: str | None = None, analyst_designation: str | None = None, analyst_org: str | None = None) -> str:
    """Build a clean GitHub-ready user/report template.

    Reporting is intentionally limited to VirusTotal-malicious file evidence only.
    The template avoids duplicate evidence and uses a professional GitHub Team tone.
    """
    result = result or {}
    snap = result.get('snapshot') or {}
    full_name = snap.get('full_name') or ''
    repo_url = snap.get('html_url') or (f'https://github.com/{full_name}' if full_name else '')
    owner = snap.get('owner') or (full_name.split('/')[0] if '/' in full_name else '')
    user_url = target_url or (f'https://github.com/{owner}' if owner else '')
    malicious = malicious_file_evidence(result)
    count = len(malicious)
    file_word = 'file' if count == 1 else 'files'
    verb = 'is' if count == 1 else 'are'

    lines = [
        'Subject: Malicious Files Hosted on GitHub – Request for User Review',
        '',
        'Hello GitHub Team,',
        '',
        f'I am reporting the following GitHub user because a public repository under this account is hosting {count} {file_word} that {verb} identified as malicious by VirusTotal and used to target our organisation.',
        '',
        f'Reported GitHub User: {user_url or "Not available"}',
        f'Associated Repository: {repo_url or full_name or "Not available"}',
        '',
    ]

    if reason:
        lines += ['Additional context:', reason.strip(), '']

    lines.append('Malicious file evidence:')
    if malicious:
        for idx, item in enumerate(malicious, start=1):
            lines.append(f'{idx}. File: {item["path"]}')
            lines.append(f'   VirusTotal report: {item["vt_link"] or "Not available"}')
    else:
        lines.append('No VirusTotal-malicious file evidence was available in the current RepoTrace scan.')

    lines += [
        '',
        f'Based on the above VirusTotal reputation evidence, the identified {file_word} {verb} malicious and associated with activity targeting our organisation.',
        'We request GitHub to review the reported user and associated repository and take appropriate enforcement action, including takedown or removal if this content violates GitHub policies.',
        '',
        'Regards,',
        '',
        analyst_name or '<Full Name>',
        analyst_designation or '<Designation>',
        analyst_org or '<Organisation>',
        '',
        'This report was generated using RepoTrace.',
    ]
    return '\n'.join(lines)

def save_report(kind: str, target_url: str, template: str, analyst_email: str | None, result: dict[str, Any] | None = None) -> dict[str, Any]:
    rid = uuid.uuid4().hex[:12]
    payload = {
        'id': rid,
        'kind': kind,
        'target_url': target_url,
        'analyst_email': analyst_email,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'template': template,
        'snapshot': (result or {}).get('snapshot'),
        'risk': (result or {}).get('risk'),
    }
    path = REPORT_DIR / f'{rid}.json'
    path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return {'id': rid, 'saved_to': str(path)}


def maybe_email_report(subject: str, body: str) -> dict[str, Any]:
    to = os.getenv('REPORT_TO_EMAIL', '').strip()
    if not to:
        return {'attempted': False, 'sent': False, 'reason': 'REPORT_TO_EMAIL not configured'}
    host = os.getenv('SMTP_HOST')
    port = int(os.getenv('SMTP_PORT', '587'))
    username = os.getenv('SMTP_USERNAME')
    password = os.getenv('SMTP_PASSWORD')
    sender = os.getenv('SMTP_FROM') or username
    if not host or not sender:
        return {'attempted': True, 'sent': False, 'error': 'SMTP_HOST and SMTP_FROM/SMTP_USERNAME required'}
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = to
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)
        return {'attempted': True, 'sent': True, 'to': to}
    except Exception as e:
        return {'attempted': True, 'sent': False, 'error': str(e)}
