#!/usr/bin/env python3
"""Deterministically generate the SBOX Personal Cloud site under ./site.

    python3 src/fallback-web/build_site.py          # write
    python3 src/fallback-web/build_site.py --check  # fail if committed output is stale

Every asset is original to this project (GPL-3.0-or-later, see ../../LICENSE and
site/ASSETS.txt). No remote fonts, images, scripts or analytics. The Files page
lists exactly the curated read-only files below site/library/, with their real
byte sizes, so the listing can never drift from what the server actually serves.
"""
import hashlib
import html
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SITE = HERE / 'site'
MARKER = '<meta name="generator" content="sbox-personal-cloud">'
TITLE = 'SBOX Personal Cloud'
NAV = [('/', 'Home', 'home'), ('/files/', 'Files', 'files'), ('/media/', 'Media', 'media'), ('/about/', 'About', 'about')]
ICONS = {
    'home': '<path d="M3 11.5 12 4l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
    'files': '<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    'media': '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m21 17-5-5-9 8"/>',
    'about': '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/>',
    'doc': '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
    'sheet': '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M4 10h16M4 15h16M10 4v16"/>',
    'image': '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="8.5" cy="10" r="1.6"/><path d="m21 16-5-4-8 7"/>',
    'pdf': '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M8.5 16.5h7"/>',
    'download': '<path d="M12 4v11m0 0-4-4m4 4 4-4M5 20h14"/>',
    'shield': '<path d="M12 3 5 6v6c0 4.4 3 7.6 7 9 4-1.4 7-4.6 7-9V6z"/><path d="m9 12 2 2 4-4"/>',
    'sync': '<path d="M20 8a8 8 0 0 0-14-2M4 4v4h4M4 16a8 8 0 0 0 14 2m2 2v-4h-4"/>',
    'folder': '<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
}
DATE = {'documents/welcome.txt': '2026-09-02', 'documents/getting-started.md': '2026-09-02', 'documents/personal-cloud-guide.pdf': '2026-09-18',
        'spreadsheets/travel-checklist.csv': '2026-10-04', 'spreadsheets/monthly-budget-template.csv': '2026-10-04'}
ARTWORK = [
    ('harbour-dusk', 'Harbour at dusk', 'Evenings', '2026-08-14', ('#1d2b53', '#7e2553', '#ff8a5b'), 'water'),
    ('mountain-morning', 'Mountain morning', 'Hikes', '2026-08-30', ('#9ad1f0', '#d7ecf7', '#f6c177'), 'peaks'),
    ('forest-trail', 'Forest trail', 'Hikes', '2026-09-06', ('#123524', '#2d6a4f', '#95d5b2'), 'trees'),
    ('island-ferry', 'Island ferry', 'Weekends', '2026-09-21', ('#4ea8de', '#90e0ef', '#ffd166'), 'water'),
    ('city-rain', 'City after rain', 'Evenings', '2026-10-03', ('#22223b', '#4a4e69', '#c9ada7'), 'city'),
    ('northern-lights', 'Northern lights', 'Travel', '2026-10-11', ('#03071e', '#1b4965', '#5fffa8'), 'aurora'),
]


def icon(name, cls='i'):
    return f'<svg class="{cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{ICONS[name]}</svg>'


def kb(n):
    return f'{n:,} B' if n < 1000 else f'{n / 1000:.1f} KB' if n < 10**6 else f'{n / 10**6:.2f} MB'


def page(key, heading, lead, body, title=None):
    current = ' aria-current="page"'
    nav = ''.join(f'<a href="{href}"{current if k == key else ""}>{icon(k)}<span>{label}</span></a>' for href, label, k in NAV)
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{MARKER}
<meta name="color-scheme" content="light dark">
<meta name="description" content="A small personal cloud for documents, pictures and shared files.">
<title>{html.escape(title or heading)} · {TITLE}</title>
<link rel="icon" href="/assets/logo.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/site.css">
<script defer src="/assets/site.js"></script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="app">
<header class="masthead">
<a class="brand" href="/"><img src="/assets/logo.svg" alt="" width="34" height="34"><span><b>SBOX</b> Personal Cloud</span></a>
<nav aria-label="Main">{nav}</nav>
</header>
<main id="main" tabindex="-1">
<div class="page-head"><div><h1>{heading}</h1><p class="lead">{lead}</p></div></div>
{body}
</main>
<footer class="foot"><span>{TITLE}</span><span>Read-only public library · No account needed to browse</span></footer>
</div>
</body>
</html>
'''


def library():
    rows = []
    for path in sorted((SITE / 'library').rglob('*')):
        if path.is_file():
            rel = path.relative_to(SITE / 'library').as_posix()
            rows.append((rel, path.stat().st_size))
    return rows


def kind(rel):
    ext = rel.rsplit('.', 1)[-1]
    return {'txt': ('doc', 'Text document'), 'md': ('doc', 'Markdown document'), 'pdf': ('pdf', 'PDF document'),
            'csv': ('sheet', 'Spreadsheet (CSV)'), 'svg': ('image', 'Picture (SVG)')}[ext]


def artwork(name, palette, scene):
    a, b, c = palette
    seed = int(hashlib.sha256(name.encode()).hexdigest()[:8], 16)
    shapes = []
    if scene in ('peaks', 'water', 'aurora'):
        ridge = ' '.join(f'{x},{230 - ((seed >> (x // 40)) % 70) - (40 if x % 160 == 80 else 0)}' for x in range(0, 641, 80))
        shapes.append(f'<polygon points="0,360 {ridge} 640,360" fill="{a}" opacity=".85"/>')
    if scene == 'aurora':
        for i in range(3):
            shapes.append(f'<path d="M-20 {120 + i * 30} C 160 {40 + i * 25}, 320 {170 - i * 20}, 660 {70 + i * 30}" stroke="{c}" stroke-width="{26 - i * 6}" fill="none" opacity="{.35 + i * .15}"/>')
    if scene == 'water':
        shapes.append(f'<rect x="0" y="250" width="640" height="110" fill="{a}"/>')
        for i in range(6):
            shapes.append(f'<rect x="{40 + i * 95}" y="{270 + (i % 3) * 22}" width="{60 + (seed >> i) % 50}" height="3" rx="1.5" fill="{c}" opacity=".55"/>')
        shapes.append(f'<circle cx="{460 - seed % 120}" cy="150" r="46" fill="{c}" opacity=".9"/>')
    if scene == 'peaks':
        shapes.append(f'<circle cx="480" cy="96" r="38" fill="{c}"/>')
        shapes.append('<polygon points="40,360 230,140 420,360" fill="#5c7a99"/><polygon points="230,140 262,178 236,172 214,186" fill="#ffffff"/>')
        shapes.append('<polygon points="250,360 450,170 640,330 640,360" fill="#3f5873"/>')
    if scene == 'trees':
        for i in range(11):
            x = 20 + i * 58 + (seed >> i) % 20
            h = 120 + (seed >> (i + 3)) % 90
            shapes.append(f'<polygon points="{x},{330 - h} {x - 34},330 {x + 34},330" fill="{b if i % 2 else a}"/><rect x="{x - 5}" y="330" width="10" height="20" fill="#3b2a1a"/>')
        shapes.append(f'<path d="M260 360 C 300 300, 340 300, 380 360" fill="{c}" opacity=".6"/>')
    if scene == 'city':
        for i in range(12):
            w = 36 + (seed >> i) % 26
            h = 90 + (seed >> (i + 5)) % 150
            x = i * 54
            shapes.append(f'<rect x="{x}" y="{300 - h}" width="{w}" height="{h + 60}" fill="{a if i % 2 else b}"/>')
            for j in range(3):
                shapes.append(f'<rect x="{x + 8}" y="{310 - h + 18 + j * 26}" width="8" height="10" fill="{c}" opacity=".8"/>')
        shapes.append(f'<rect x="0" y="330" width="640" height="30" fill="{c}" opacity=".18"/>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 360" width="640" height="360" role="img" aria-label="{html.escape(name.replace('-', ' '))}">
<defs><linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{b}"/><stop offset="1" stop-color="{c}"/></linearGradient></defs>
<rect width="640" height="360" fill="url(#sky)"/>
{chr(10).join(shapes)}
</svg>
'''


def pdf_bytes():
    lines = ['SBOX Personal Cloud - Quick guide', '', 'Browse: open Files to see the shared library.', 'Download: each file has its own download button.',
             'Media: the gallery shows a few shared pictures.', 'This public library is read-only.']
    text = 'BT /F1 18 Tf 72 760 Td (%s) Tj /F1 12 Tf' % lines[0]
    for line in lines[1:]:
        text += ' 0 -22 Td (%s) Tj' % line
    text += ' ET'
    objects = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
               '<< /Length %d >>\nstream\n%s\nendstream' % (len(text), text), '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    out = b'%PDF-1.4\n'
    offsets = []
    for n, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f'{n} 0 obj\n{obj}\nendobj\n'.encode('latin-1')
    xref = len(out)
    out += f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode()
    out += ''.join(f'{o:010d} 00000 n \n' for o in offsets).encode()
    out += f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info << /Title (SBOX Personal Cloud guide) >> >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    return out


STATIC = {
    'library/documents/welcome.txt': 'Welcome to SBOX Personal Cloud\n\nThis is the public, read-only part of a small personal cloud.\nFiles shared here can be downloaded by anyone who has the address.\nPrivate folders are not published on this site.\n',
    'library/documents/getting-started.md': '# Getting started\n\n1. Open **Files** to browse the shared library.\n2. Use the search box to filter by name or type.\n3. Select **Download** to save a copy.\n4. Visit **Media** for the photo gallery.\n\nThe public library is read-only: nothing can be uploaded or changed from the web.\n',
    'library/spreadsheets/travel-checklist.csv': 'Item,Category,Packed\nPassport,Documents,yes\nPhone charger,Electronics,yes\nTravel adaptor,Electronics,no\nRain jacket,Clothing,no\nWalking shoes,Clothing,yes\nFirst aid kit,Health,no\n',
    'library/spreadsheets/monthly-budget-template.csv': 'Category,Planned,Actual,Notes\nRent,0,0,\nUtilities,0,0,\nGroceries,0,0,\nTransport,0,0,\nSavings,0,0,\nOther,0,0,\n',
    'ASSETS.txt': 'SBOX Personal Cloud site assets\n\nAll pages, styles, scripts, icons, illustrations and sample library files in\nthis directory were created for the SBOX project and are distributed under the\nproject licence (GPL-3.0-or-later). They contain no third-party logos, fonts,\nphotographs, trademarks or tracking code.\n',
}

LOGO = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3a7bd5"/><stop offset="1" stop-color="#00a6a6"/></linearGradient></defs><rect width="64" height="64" rx="16" fill="url(#g)"/><path d="M20 41h25a9 9 0 0 0 .8-18 13 13 0 0 0-24.7 3.4A7.4 7.4 0 0 0 20 41z" fill="#fff"/><path d="M28 34h9M28 29h12" stroke="#3a7bd5" stroke-width="3" stroke-linecap="round"/></svg>
'''

CSS = r''':root{color-scheme:light dark;--bg:#f4f6fb;--panel:#fff;--panel-2:#eef2f8;--line:#d9e0ea;--text:#162033;--muted:#55637a;--accent:#2563c9;--accent-2:#0e8a8a;--accent-soft:#e6eefb;--shadow:0 10px 30px #1620330f;--radius:14px;--font:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans","PingFang HK","Microsoft JhengHei",sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#0f141c;--panel:#161d28;--panel-2:#1d2633;--line:#2b3646;--text:#e7edf6;--muted:#a3b0c2;--accent:#8db4ff;--accent-2:#5fd3c8;--accent-soft:#1f2d45;--shadow:0 10px 30px #0006}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--font)}
a{color:var(--accent)}:focus-visible{outline:3px solid var(--accent-2);outline-offset:2px;border-radius:6px}
.skip{position:absolute;left:-9999px}.skip:focus{left:12px;top:12px;z-index:9;background:var(--panel);padding:10px 14px;border-radius:8px}
.app{min-height:100vh;display:grid;grid-template-columns:232px minmax(0,1fr);grid-template-rows:1fr auto;background:linear-gradient(to right,var(--panel) 232px,var(--line) 232px 233px,transparent 233px)}
.masthead{grid-row:1/3;position:sticky;top:0;height:100vh;padding:22px 16px;background:transparent;display:flex;flex-direction:column;gap:26px}
.brand{display:flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;font-size:15px;line-height:1.2}.brand b{letter-spacing:.06em}.brand span{display:grid}
nav{display:grid;gap:4px}nav a{display:flex;align-items:center;gap:12px;min-height:42px;padding:8px 12px;border-radius:10px;color:var(--muted);text-decoration:none;font-weight:560}
nav a:hover{background:var(--panel-2);color:var(--text)}nav a[aria-current=page]{background:var(--accent-soft);color:var(--accent)}
.i{width:20px;height:20px;flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
main{padding:34px clamp(18px,4vw,48px) 40px;min-width:0;outline:none}
.page-head{display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between;align-items:end;margin-bottom:26px}
h1{margin:0;font-size:clamp(26px,3vw,34px);letter-spacing:-.02em;line-height:1.2}h2{font-size:18px;margin:0 0 12px}h3{font-size:15px;margin:0 0 6px}
.lead{margin:8px 0 0;color:var(--muted);max-width:68ch}p{margin:0 0 12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:22px;box-shadow:var(--shadow);min-width:0}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr))}
.hero{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:18px;margin-bottom:18px}
.hero .card:first-child{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;border:0}.hero .card:first-child p{color:#eef4ff;max-width:52ch}
.hero .card:first-child a.button{background:#fff;color:#16408c}
.button{display:inline-flex;align-items:center;gap:8px;min-height:40px;padding:8px 16px;border-radius:10px;background:var(--accent);color:#fff;text-decoration:none;font-weight:600;border:0}
.button.ghost{background:var(--panel-2);color:var(--text);border:1px solid var(--line)}
.stat{font-size:28px;font-weight:700;letter-spacing:-.02em}.muted{color:var(--muted)}.small{font-size:13px}
.meter{height:8px;border-radius:5px;background:var(--panel-2);overflow:hidden;margin:12px 0 6px}.meter i{display:block;height:100%;width:3%;background:var(--accent-2);border-radius:5px}
.feature{display:flex;gap:14px;align-items:flex-start}.feature .i{width:28px;height:28px;color:var(--accent)}
.recent li{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}.recent li:last-child{border:0}.recent ul,.plain{list-style:none;margin:0;padding:0}
.recent .name{flex:1;min-width:0;overflow-wrap:anywhere}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}.toolbar input{flex:1 1 240px;min-height:42px;padding:8px 12px;border:1px solid var(--line);border-radius:10px;background:var(--panel);color:var(--text);font:inherit}
.crumbs{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:14px}
.folders{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(min(100%,200px),1fr));margin-bottom:22px}
.folder{display:flex;gap:12px;align-items:center;padding:14px 16px;border:1px solid var(--line);border-radius:12px;background:var(--panel);text-decoration:none;color:var(--text)}.folder .i{color:var(--accent);width:26px;height:26px}.folder small{display:block;color:var(--muted)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:middle}th{font-size:13px;color:var(--muted);background:var(--panel-2);font-weight:600}
tbody tr:hover td{background:var(--panel-2)}td.name{display:flex;align-items:center;gap:10px;min-width:0;overflow-wrap:anywhere}td.name .i{color:var(--accent)}.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.table{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel)}
.dl{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:9px;border:1px solid var(--line);text-decoration:none;color:var(--text);font-weight:560;white-space:nowrap}.dl:hover{border-color:var(--accent)}
.gallery{display:grid;gap:18px;grid-template-columns:repeat(auto-fill,minmax(min(100%,260px),1fr))}
figure{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}figure img{display:block;width:100%;height:auto;aspect-ratio:16/9;object-fit:cover}
figcaption{padding:12px 14px}figcaption b{display:block}dl.meta{display:grid;grid-template-columns:auto 1fr;gap:2px 12px;margin:8px 0 0;font-size:13px;color:var(--muted)}dl.meta dd{margin:0}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}.chip{padding:4px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel);font-size:13px;color:var(--muted)}
.foot{grid-column:2;display:flex;flex-wrap:wrap;gap:8px 20px;justify-content:space-between;padding:16px clamp(18px,4vw,48px);border-top:1px solid var(--line);color:var(--muted);font-size:13px}
.empty{padding:24px;text-align:center;color:var(--muted)}#recent{margin-top:18px}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
@media (max-width:860px){.app{grid-template-columns:1fr;background:none}.masthead{background:var(--panel)}.masthead{position:static;height:auto;grid-row:auto;flex-direction:row;flex-wrap:wrap;align-items:center;justify-content:space-between;padding:12px 16px;gap:10px;border-right:0;border-bottom:1px solid var(--line)}nav{grid-auto-flow:column;gap:2px}nav a{padding:8px 10px}nav a span{font-size:14px}.foot{grid-column:1}.hero{grid-template-columns:1fr}}
@media (max-width:520px){nav{width:100%;grid-auto-flow:column;grid-template-columns:repeat(4,minmax(0,1fr))}nav a{flex-direction:column;gap:2px;font-size:12px;justify-content:center;min-height:52px}main{padding-top:24px}th.type,td.type,th.date,td.date{display:none}td,th{padding:10px}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
'''

JS = r'''/* Progressive enhancement only: client-side filter of the curated list. */
(function(){var input=document.getElementById('filter');if(!input)return;var rows=[].slice.call(document.querySelectorAll('[data-file-row]'));var count=document.getElementById('filter-count');var empty=document.getElementById('filter-empty');
function apply(){var q=input.value.toLowerCase().trim(),shown=0;rows.forEach(function(r){var hit=!q||r.getAttribute('data-search').indexOf(q)>=0;r.hidden=!hit;if(hit)shown++});count.textContent=shown+' of '+rows.length+' files';empty.hidden=shown>0}
input.addEventListener('input',apply);input.hidden=false;apply();})();
'''


def build():
    out = {}
    for rel, text in STATIC.items():
        out[rel] = text.encode()
    out['library/documents/personal-cloud-guide.pdf'] = pdf_bytes()
    for name, label, album, date, palette, scene in ARTWORK:
        out[f'library/pictures/{name}.svg'] = artwork(name, palette, scene).encode()
        DATE[f'pictures/{name}.svg'] = date
    out['assets/logo.svg'] = LOGO.encode()
    out['assets/site.css'] = CSS.encode()
    out['assets/site.js'] = JS.encode()
    files = sorted((rel[len('library/'):], len(data)) for rel, data in out.items() if rel.startswith('library/'))
    total = sum(size for _, size in files)
    folders = {}
    for rel, size in files:
        folders.setdefault(rel.split('/')[0], []).append(size)

    recent = sorted(files, key=lambda r: (DATE[r[0]], r[0]), reverse=True)[:4]
    home = f'''<section class="hero"><div class="card"><h2>Welcome to your Personal Cloud</h2><p>A calm place for everyday documents, travel lists and favourite pictures. The shared library below is public and read-only, so anyone with the address can browse and download.</p><p><a class="button" href="/files/">{icon('files')}Browse files</a></p></div>
<div class="card"><h2>Library</h2><div class="stat">{len(files)} files</div><p class="muted">{kb(total)} shared in {len(folders)} folders</p><div class="meter" role="img" aria-label="Library uses a small part of its space"><i></i></div><p class="small muted">Plenty of room left for new albums.</p></div></section>
<section class="grid">
<article class="card feature">{icon('folder')}<div><h3>Organised folders</h3><p class="muted">Documents, spreadsheets and pictures, each in its own place.</p></div></article>
<article class="card feature">{icon('media')}<div><h3>Photo gallery</h3><p class="muted">A small album of recent trips and evenings in the city.</p></div></article>
<article class="card feature">{icon('shield')}<div><h3>Read-only sharing</h3><p class="muted">Public visitors can look and download. Nothing can be uploaded or changed here.</p></div></article>
<article class="card feature">{icon('sync')}<div><h3>Always up to date</h3><p class="muted">The library refreshes when new files are published.</p></div></article>
</section>
<section class="card recent" style="margin-top:18px"><h2>Recently added</h2><ul>{''.join(f'<li>{icon(kind(rel)[0])}<span class="name"><a href="/library/{rel}">{html.escape(rel.split("/")[-1])}</a><br><span class="small muted">{html.escape(kind(rel)[1])} · {kb(size)}</span></span><span class="small muted num">{DATE[rel]}</span></li>' for rel, size in recent)}</ul></section>'''
    out['index.html'] = page('home', 'Personal Cloud', 'Your documents, lists and pictures, neatly in one place.', home, 'Home').replace(' style="margin-top:18px"', ' id="recent"').encode()

    folder_cards = ''.join(f'<a class="folder" href="#{name}">{icon("folder")}<span>{name.title()}<small>{len(sizes)} files · {kb(sum(sizes))}</small></span></a>' for name, sizes in sorted(folders.items()))
    rows = ''.join(
        f'<tr data-file-row data-search="{html.escape((rel + " " + kind(rel)[1]).lower())}" id="{rel.split("/")[0] if i == 0 or files[i-1][0].split("/")[0] != rel.split("/")[0] else ""}">'
        f'<td class="name">{icon(kind(rel)[0])}<span>{html.escape(rel.split("/")[-1])}<br><span class="small muted">{html.escape(rel.split("/")[0].title())}</span></span></td>'
        f'<td class="type">{html.escape(kind(rel)[1])}</td><td class="num">{kb(size)}</td><td class="date num">{DATE[rel]}</td>'
        f'<td><a class="dl" href="/library/{rel}" download>{icon("download")}<span>Download</span></a></td></tr>'
        for i, (rel, size) in enumerate(files)).replace(' id=""', '')
    files_body = f'''<div class="crumbs" aria-label="Location">{icon('files')}<span>Shared library</span></div>
<p class="small muted">Read-only. {len(files)} curated files · {kb(total)}</p>
<div class="folders">{folder_cards}</div>
<div class="toolbar"><label class="small muted" for="filter">Filter files</label><input id="filter" type="search" placeholder="Search by name or type" autocomplete="off" hidden><span id="filter-count" class="small muted" aria-live="polite">{len(files)} files</span></div>
<div class="table"><table><caption class="small muted" style="display:none">Shared files</caption><thead><tr><th scope="col">Name</th><th scope="col" class="type">Type</th><th scope="col">Size</th><th scope="col" class="date">Added</th><th scope="col"><span class="sr">Download</span></th></tr></thead><tbody>{rows}</tbody></table><p id="filter-empty" class="empty" hidden>No files match this search.</p></div>'''
    out['files/index.html'] = page('files', 'Files', 'Browse and download the shared library.', files_body).replace('<caption class="small muted" style="display:none">Shared files</caption>', '').replace('<span class="sr">Download</span>', 'Download').encode()

    albums = sorted({a[2] for a in ARTWORK})
    figures = ''.join(
        f'<figure><img src="/library/pictures/{name}.svg" alt="{html.escape(label)}" width="640" height="360" loading="lazy"><figcaption><b>{html.escape(label)}</b>'
        f'<dl class="meta"><dt>Album</dt><dd>{html.escape(album)}</dd><dt>Added</dt><dd>{date}</dd><dt>Size</dt><dd>640 × 360 · {kb(len(out[f"library/pictures/{name}.svg"]))}</dd></dl></figcaption></figure>'
        for name, label, album, date, _, _ in ARTWORK)
    media_body = f'<div class="chips" aria-label="Albums">{"".join(f"<span class=chip>{html.escape(a)}</span>" for a in albums)}</div><div class="gallery">{figures}</div>'
    out['media/index.html'] = page('media', 'Media', f'{len(ARTWORK)} pictures in {len(albums)} albums.', media_body).encode()

    about_body = f'''<section class="grid"><article class="card"><h2>About this site</h2><p>{TITLE} is a lightweight home for a few shared documents and pictures. Pages are plain, fast and work without accounts.</p><p class="muted">Everything here is public. Private folders are never published on this website.</p></article>
<article class="card"><h2>Using the library</h2><ul class="plain"><li>Open <a href="/files/">Files</a> to browse folders.</li><li>Use Download to save a copy.</li><li>See <a href="/media/">Media</a> for the gallery.</li></ul></article>
<article class="card"><h2>Privacy</h2><p>No cookies, no analytics and no third-party content are used on these pages.</p><p class="muted small">Files are served read-only over HTTPS.</p></article></section>'''
    out['about/index.html'] = page('about', 'About', 'What this site is and how to use it.', about_body).encode()
    out['404.html'] = page('', 'Page not found', 'The page you asked for is not part of this library.', '<div class="card"><p>Try the <a href="/">home page</a> or browse <a href="/files/">Files</a>.</p></div>', 'Not found').encode()
    return out


def main():
    check = '--check' in sys.argv
    out = build()
    stale = []
    for rel, data in sorted(out.items()):
        target = SITE / rel
        if check:
            if not target.is_file() or target.read_bytes() != data:
                stale.append(rel)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    existing = {p.relative_to(SITE).as_posix() for p in SITE.rglob('*') if p.is_file()} if SITE.exists() else set()
    extra = sorted(existing - set(out))
    if check and (stale or extra):
        print('STALE or unexpected site files: ' + ', '.join(stale + extra), file=sys.stderr)
        return 1
    if not check:
        for rel in extra:
            (SITE / rel).unlink()
    print(('PASS' if check else 'WROTE') + f' {len(out)} SBOX Personal Cloud site files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
