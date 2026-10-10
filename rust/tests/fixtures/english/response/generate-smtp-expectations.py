#!/usr/bin/env python3
"""Generate English presentation expectations with independent CPython email.

The original SMTP scenarios, outcomes and audit events remain unchanged.
No product code or real server is executed; source fixtures are synthetic.
"""
import copy
import email.policy
import email.parser
import email.message
import json
import pathlib
import re
import sys

if sys.version_info[:3] != (3, 12, 14):
    raise SystemExit('Use CPython 3.12.14, matching the historical fixture generator')
root = pathlib.Path(__file__).resolve().parent
original = root.parents[1] / 'python/response/smtp_sessions.json'
rows = copy.deepcopy(json.loads(original.read_text()))
subject = '[ZeroPW] Notification configuration test'
body = ('ZeroPW notification configuration test.\n'
        'This is not a real intrusion incident. Receipt confirms the SMTP setup works.\n')
for row in rows:
    lines = row['transcript']
    data_at = next((i for i, line in enumerate(lines) if line.lower() == 'data\r\n'), None)
    end_at = next((i for i, line in enumerate(lines) if line == '.\r\n'), None)
    has_message = data_at is not None and end_at is not None
    if has_message:
        old_bytes = ''.join(lines[data_at + 1:end_at]).encode('utf-8')
        parsed = email.parser.BytesParser(policy=email.policy.default).parsebytes(old_bytes)
        sender, recipient = str(parsed['From']), str(parsed['To'])
    else:
        sender = 'zeropw@example.com'
        rcpt = [re.search(r'TO:<([^>]+)>', line, re.I).group(1)
                for line in lines if line.lower().startswith('rcpt to:')]
        recipient = ', '.join(rcpt) if rcpt else 'admin@example.com'
    if row['scenario'] == 'comment_refold':
        # HeaderRegistry's string view omits comments. Preserve the original
        # scenario input rather than reconstructing it from that lossy view.
        recipient = ('ops@example.com (a very long comment that goes on and on '
                     'and on and on and on and on and on)')
    message = email.message.EmailMessage()
    message['Subject'] = subject
    message['From'] = sender
    message['To'] = recipient
    message.set_content(body)
    international = any('SMTPUTF8' in line for line in lines)
    policy = message.policy.clone(utf8=international, linesep='\r\n')
    message_bytes = message.as_bytes(policy=policy)
    lines = [re.sub(r' size=\d+', f' size={len(message_bytes)}', line, flags=re.I)
             if line.lower().startswith('mail from:') else line for line in lines]
    if has_message:
        data_lines = message_bytes.decode('utf-8').splitlines(keepends=True)
        # SMTP DATA dot stuffing is independent of MIME encoding.
        data_lines = ['.' + line if line.startswith('.') else line for line in data_lines]
        lines[data_at + 1:end_at] = data_lines
    row['transcript'] = lines
(root / 'smtp_sessions.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2) + '\n')
print(f'Generated English SMTP expectations for {len(rows)} synthetic scenarios')
