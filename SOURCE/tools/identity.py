#!/usr/bin/env python3
"""Repository identity policy for public sources and release artifacts.

Exactly one repository may be referenced: the canonical `repository` field of
VERSION.json.  Any other `<owner>/<name>` reference for the same owner is
rejected.  Distinctive names of retired repositories are rejected even without
an owner prefix; they are stored only as SHA-256 digests so that this public
tree never spells them out.
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_FORMAT = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}')

# sha256(lower-case retired repository name). Generic words (the product name and
# the upstream core name) are deliberately not listed; they are only rejected
# when qualified by the owner, which the owner rule below already covers.
RETIRED_NAME_SHA256 = frozenset({
    '510180b7bfb1293da39ec3f199d1dae05345d909be779f44550b5ca1b62e70b1',
    'eec3cb077b6a2025d357f641d327c5098e233e4a480acbd78c49d8de3439cf10',
    '501ed131cd086d0af5832e399a40eec870cf52961aae7b835ff558600eae7b14',
    'e4775a2ee73e35b262d5e5d8880db0774435119681078ca57660c418183dcead',
    '6fabe9d1c534b47e3171e5a64646b4b5732fd58f1b168184d733db1ed01bbc4a',
    '90ee7f365aa12e35b82f99209033a407b08ccbd761c6bdfc34e41e6da7f6f300',
    '14468ddf4a31af0a1d407faa3e020f1b44f9ee7cf3dffd809673818748d59cfc',
    'beac0b491e8f273f783ea2e2cb25caa24f46e5884b051058d7eda9dcd096ef54',
    '32c3f086f6b12f458584e7bddccac17618981d851a0c76153817eb0bbeec9cd2',
})
MAX_PARTS = 3
TOKEN = re.compile(r'[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*')


class IdentityError(ValueError):
    pass


def canonical(root=ROOT):
    """Return 'owner/name' from VERSION.json, validated."""
    repo = json.loads((Path(root) / 'VERSION.json').read_text(encoding='utf-8'))['repository']
    if not isinstance(repo, str) or not REPOSITORY_FORMAT.fullmatch(repo):
        raise IdentityError('VERSION.json repository must be owner/name')
    return repo


def _digest(word):
    return hashlib.sha256(word.encode()).hexdigest()


def retired_name(text, extra_digests=(), exclude=None):
    """First token run (joined by - or _) whose digest is a retired name, else None."""
    digests = (RETIRED_NAME_SHA256 | frozenset(extra_digests)) - ({exclude} if exclude else set())
    for match in TOKEN.finditer(text):
        parts = re.split(r'[-_]', match[0].lower())
        if len(parts) < 2:
            continue
        for i in range(len(parts)):
            for j in range(i + 2, min(len(parts), i + MAX_PARTS) + 1):
                if _digest('-'.join(parts[i:j])) in digests:
                    return match[0]
    return None


def foreign_reference(text, repository, extra_digests=()):
    """Describe the first identity violation in decoded text, or return None.

    The description never contains the offending text (it may be a secret-bearing line).
    """
    owner, name = repository.split('/', 1)
    for match in re.finditer(re.escape(owner) + r'/([A-Za-z0-9._-]+)', text, re.I):
        found = re.sub(r'\.git$', '', match[1].rstrip('.'))
        if found.lower() != name.lower():
            return 'reference to a repository other than the canonical one'
    # The canonical name may coincide with a retired predecessor name (owner/name differ). It is
    # then allowed ONLY as the canonical repository: the same name under any other owner is still
    # a predecessor reference, and every other retired name stays banned.
    own = _digest(name.lower())
    if own in RETIRED_NAME_SHA256 | frozenset(extra_digests):
        for match in re.finditer(r'([A-Za-z0-9][A-Za-z0-9-]{0,38})/' + re.escape(name) + r'(?![A-Za-z0-9._-])', text, re.I):
            if match[1].lower() != owner.lower():
                return 'retired repository name'
        if retired_name(text, (frozenset(extra_digests) | RETIRED_NAME_SHA256) - {own}, exclude=own):
            return 'retired repository name'
        return None
    if retired_name(text, extra_digests):
        return 'retired repository name'
    return None
