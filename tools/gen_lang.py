#!/usr/bin/env python3
import re, os, sys, io

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SRC = ['src/main.cpp', 'src/netmon.cpp', 'src/procinfo.cpp', 'src/ai.cpp',
       'src/common.cpp', 'src/geo.cpp', 'src/cert.cpp', 'src/banner.cpp',
       'src/wifi.cpp', 'src/history.cpp']

BLOCK_KEYS = [
    ('src/main.cpp', None, r'\{\s*[CAH]_[A-Z0-9_]+,\s*L"((?:[^"\\]|\\.)*)"'),
    ('src/main.cpp', 'static const HelpRow rows[]', r'L"((?:[^"\\]|\\.)*)"'),
    ('src/netmon.cpp', 'static const BadPort kBadPorts[]', r'L"((?:[^"\\]|\\.)*)"'),
    ('src/netmon.cpp', 'static const M marks[]',
     r'L"(?:[^"\\]|\\.)*"\s*,\s*L"((?:[^"\\]|\\.)*)"'),
]

LANGS = ['tr', 'es', 'de', 'fr', 'ja', 'zh', 'pt']

FORMAT_SPECS = ['%s', '%d', '%ld', '%u', '%%', '%llu', '%02llu', '%.0f']


def unescape_c(k):
    k = k.replace('\\"', '"').replace('\\\\', '\\')
    return k.replace('\\n', '\n').replace('\\t', '\t')


def block_text(src, anchor):
    if anchor is None:
        return src
    i = src.index(anchor)
    j = src.index('};', i)
    return src[i:j]


def extract_keys():
    keys = []

    def add(k):
        if k and k not in keys:
            keys.append(k)

    for f in SRC:
        s = io.open(os.path.join(ROOT, f), encoding='utf-8').read()
        for m in re.finditer(r'Tr\s*\(\s*L"((?:[^"\\]|\\.)*)"\s*\)', s):
            add(unescape_c(m.group(1)))
    for f, anchor, pat in BLOCK_KEYS:
        s = io.open(os.path.join(ROOT, f), encoding='utf-8').read()
        for m in re.finditer(pat, block_text(s, anchor)):
            add(unescape_c(m.group(1)))
    return keys


def esc_key(s):
    return s.replace('=', '\\=').replace('\n', '\\n').replace('\t', '\\t').replace('\r', '')


def esc_val(s):
    return s.replace('\n', '\\n').replace('\t', '\\t').replace('\r', '')


def check_format(key, trans, lang):
    for spec in FORMAT_SPECS:
        if key.count(spec) != trans.count(spec):
            raise SystemExit('format mismatch [%s]: %r -> %r' % (lang, key[:48], trans[:48]))


def main():
    sys.path.insert(0, os.path.join(ROOT, 'tools'))
    from lang_table import TABLE

    keys = extract_keys()
    print('keys extracted:', len(keys))

    table = {}
    for key, values in TABLE:
        if key in table:
            raise SystemExit('duplicate table key: %r' % key[:48])
        table[key] = values

    missing = [k for k in keys if k not in table]
    if missing:
        raise SystemExit('%d key(s) without a table row:\n%s'
                         % (len(missing), '\n'.join(repr(k) for k in missing)))
    unused = [k for k in table if k not in keys]
    if unused:
        raise SystemExit('%d unused table row(s):\n%s'
                         % (len(unused), '\n'.join(repr(k) for k in unused)))

    for key in keys:
        for lang, trans in table[key].items():
            if not trans:
                raise SystemExit('empty translation [%s]: %r' % (lang, key[:48]))
            check_format(key, trans, lang)

    outdir = os.path.join(ROOT, 'lang')
    if not os.path.isdir(outdir):
        os.makedirs(outdir)

    check = '--check' in sys.argv
    stale = []

    def render(lang):
        out = ['# NetLurker language file - %s (UTF-8)' % lang,
               '# Format: key=value  (lines starting with # are comments)',
               '# \\n and \\t escapes are resolved in both key and value.']
        for k in keys:
            out.append('%s=%s' % (esc_key(k), esc_val(table[k].get(lang, k))))
        return '\n'.join(out) + '\n'

    def write_ini(lang):
        path = os.path.join(outdir, lang + '.ini')
        text = render(lang)
        if check:
            current = io.open(path, encoding='utf-8').read() if os.path.exists(path) else ''
            if current != text:
                stale.append(lang)
            return
        with io.open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        print('written:', path)

    for lang in ['en'] + LANGS:
        write_ini(lang)

    if check:
        if stale:
            raise SystemExit('lang/*.ini out of date: %s  ->  python3 tools/gen_lang.py'
                             % ', '.join(stale))
        print('catalog up to date: %d keys x %d languages' % (len(keys), len(LANGS) + 1))


if __name__ == '__main__':
    main()
