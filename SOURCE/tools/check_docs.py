#!/usr/bin/env python3
"""Validate local documentation links and self-contained delivery metadata."""
from pathlib import Path
from public_files import is_public
from urllib.parse import unquote, urlsplit
import argparse, hashlib, json, re, unicodedata

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = {'AGENTS.md','CONTINUITY.md','PLAN.md','DECISIONS.md','STATE.json','KNOWN_BLOCKERS.md','MASTER_BRIEF.md','BASELINE_INVENTORY.md','UX_RESEARCH.md'}
REQUIRED = ('README.md','docs/README.md','docs/getting-started.md','docs/installation.md','docs/cli-reference.md','docs/architecture.md','docs/webui.md','docs/users-and-quotas.md','docs/upgrades-and-recovery.md','docs/troubleshooting.md','docs/development.md','docs/releasing.md')
from identity import canonical, foreign_reference
CANONICAL = canonical(Path(__file__).resolve().parents[1])

def sha(data):
    return hashlib.sha256(data).hexdigest()

def distribution(root):
    """Require delivery metadata to describe only the included installer."""
    data=json.loads((root/'assets/distribution.json').read_text())
    release=json.loads((root/'assets/release.json').read_text())
    assert type(data.get('schema')) is int and data['schema']==1, 'Invalid distribution schema'
    assert data.get('channel') in ('candidate','stable'), 'Invalid delivery channel'
    raw=(root/'install.sh').read_bytes()
    digest=sha(raw)
    for key,value in (('version',release.get('version')),('installer_sha256',digest),('installer_bytes',len(raw))):
        assert data.get(key)==value and release.get(key)==value, f'Included installer metadata mismatch: {key}'
    assert release.get('components')==json.loads((root/'BUILD.json').read_text()), 'Release component metadata mismatch'
    assert (root/'install.sh.sha256').read_text()==digest+'  install.sh\n', 'Installer checksum sidecar mismatch'
    assert 'repository' not in data and 'source_commit' not in data, 'Local delivery must not require a repository or commit'
    return data

def anchors(markdown):
    text=re.sub(r'^```[^\n]*\n.*?^```\s*$', '', markdown, flags=re.M|re.S)
    used,found={},set()
    for heading in re.findall(r'^ {0,3}#{1,6}\s+(.+?)\s*#*$',text,re.M):
        heading=re.sub(r'\[([^]]+)\]\([^)]*\)',r'\1',heading)
        heading=re.sub(r'<[^>]+>','',heading).lower()
        slug=''.join(c for c in heading if c in '-_ ' or unicodedata.category(c)[0] in 'LN').replace(' ','-')
        count=used.get(slug,0);used[slug]=count+1;found.add(slug+(f'-{count}' if count else ''))
    return found

def local_target(root,document,path,fragment=''):
    target=(document.parent/unquote(path)).resolve() if path else document.resolve()
    assert target.is_relative_to(root.resolve()) and target.is_file(), f'{document.relative_to(root)}: missing/unsafe target {path}'
    if fragment and target.suffix=='.md':
        assert unquote(fragment) in anchors(target.read_text()), f'{document.relative_to(root)}: missing anchor {fragment} in {target.relative_to(root)}'
    return target

def check_link(root,document,url):
    url=url.strip('<>');parts=urlsplit(url)
    if parts.netloc.lower() in ('github.com','raw.githubusercontent.com') and foreign_reference(unquote(parts.path), CANONICAL):
        raise AssertionError(f'Inactive product repository URL in {document.relative_to(root)}')
    if not parts.scheme and not parts.netloc:
        local_target(root,document,parts.path,parts.fragment);return
    assert parts.scheme in ('https','http','mailto'), f'Unsupported link scheme in {document}'

def markdown_links(text):
    inline=re.findall(r'!?\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)',text)
    references=dict((k.lower(),v) for k,v in re.findall(r'^ {0,3}\[([^]]+)\]:\s*(<[^>]+>|\S+)',text,re.M))
    for label,name in re.findall(r'\[([^]\n]+)\]\[([^]\n]*)\]',text):
        key=(name or label).lower();assert key in references, f'Undefined Markdown reference: {key}';inline.append(references[key])
    return inline+list(references.values())

def project_documents(root):
    docs=[*root.glob('*.md'),*(root/'docs').rglob('*.md'),*(root/'examples').rglob('*.md')]
    docs += [root/d/'README.md' for d in ('src','shared_webui','core-source','assets','tools','tests','THIRD_PARTY_LICENSES')]
    return sorted(doc for doc in set(docs) if doc.name not in INTERNAL)

def validate(root=ROOT):
    root=root.resolve()
    for name in REQUIRED: assert (root/name).is_file(), f'Required documentation missing: {name}'
    distribution(root);docs=project_documents(root);count=0
    for doc in docs:
        for url in markdown_links(doc.read_text()):check_link(root,doc,url);count+=1
    for path in root.rglob('*'):
        if not path.is_file() or not is_public(path.relative_to(root).as_posix()) or INTERNAL.intersection(path.relative_to(root).parts):continue
        assert not foreign_reference(path.read_bytes().decode('latin-1'), CANONICAL), f'Inactive product repository URL in {path.relative_to(root)}'
    # Standalone package entrypoint (SING-BOX.tar.gz -> /root/SING-BOX/install.sh).
    for name in ('README.md','docs/installation.md','docs/getting-started.md'):
        text=(root/name).read_text()
        assert 'cd /root/SING-BOX' in text and 'bash install.sh' in text, f'Standalone package command missing from {name}'
        assert 'installer/install.sh' not in text, f'Retired installer/ layout referenced in {name}'
    print(f'PASS offline documentation: {len(docs)} files, {count} local/external links; included installer metadata verified')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--public-ref',help=argparse.SUPPRESS);args=parser.parse_args()
    if args.public_ref:parser.error('Public repository verification is disabled; use the included archive and checksums')
    validate()
if __name__=='__main__':main()
