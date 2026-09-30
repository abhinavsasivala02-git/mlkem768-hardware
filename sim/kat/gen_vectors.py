#!/usr/bin/env python3
"""Emit per-testcase NIST ACVP vector files for tb_kat_multi.v (ML-KEM-768).

Vectors come straight from the NIST ACVP server repository, so nothing here is
hand-transcribed:

  https://github.com/usnistgov/ACVP-Server
      gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
      gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json

Usage:
    python gen_vectors.py [--download] [-o OUTDIR] [--kg N] [--en N] [--de N]

    --download   fetch both JSON files into OUTDIR first (needs network)

Writes v_kg<i>_*.hex / v_en<i>_*.hex / v_de<i>_*.hex plus nvec.vh, which
tb_kat_multi.v `include`s.  One byte per line, lowest address first, which is
the layout $readmemh expects.
"""
import argparse, json, os, sys

PS = 'ML-KEM-768'
BASE = ('https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/'
        'gen-val/json-files/ML-KEM-%s-FIPS203/internalProjection.json')


def download(outdir):
    from urllib.request import urlopen
    for name, dest in (('keyGen', 'kg.json'), ('encapDecap', 'ed.json')):
        url = BASE % name
        print('fetching', url)
        with urlopen(url, timeout=180) as r:
            data = r.read()
        with open(os.path.join(outdir, dest), 'wb') as f:
            f.write(data)
        print('  %s (%d bytes)' % (dest, len(data)))


def dump(outdir, name, hexstr):
    b = bytes.fromhex(hexstr)
    with open(os.path.join(outdir, name), 'w') as f:
        f.write('\n'.join('%02x' % x for x in b) + '\n')


def group(doc, **match):
    for g in doc['testGroups']:
        if all(g.get(k) == v for k, v in match.items()):
            return g
    sys.exit('no test group matching %r' % (match,))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-o', '--outdir', default='.')
    ap.add_argument('--download', action='store_true')
    ap.add_argument('--kg', type=int, default=5)
    ap.add_argument('--en', type=int, default=5)
    ap.add_argument('--de', type=int, default=10)
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    if a.download:
        download(a.outdir)

    kgp = os.path.join(a.outdir, 'kg.json')
    edp = os.path.join(a.outdir, 'ed.json')
    for p in (kgp, edp):
        if not os.path.exists(p):
            sys.exit('%s missing - run once with --download' % p)

    kg = json.load(open(kgp))
    ed = json.load(open(edp))

    kgt = group(kg, parameterSet=PS)['tests'][:a.kg]
    ent = group(ed, parameterSet=PS, function='encapsulation')['tests'][:a.en]
    det = group(ed, parameterSet=PS, function='decapsulation')['tests'][:a.de]

    for i, t in enumerate(kgt):
        for k in ('d', 'z', 'ek', 'dk'):
            dump(a.outdir, 'v_kg%d_%s.hex' % (i, k), t[k])
    for i, t in enumerate(ent):
        for k in ('ek', 'm', 'c', 'k'):
            dump(a.outdir, 'v_en%d_%s.hex' % (i, k), t[k])
    for i, t in enumerate(det):
        for k in ('dk', 'c', 'k'):
            dump(a.outdir, 'v_de%d_%s.hex' % (i, k), t[k])

    # FIPS 203 Sec 7.2 / 7.3 input-check vectors.  testPassed == False means
    # the implementation is required to REJECT that key.
    ekc = group(ed, parameterSet=PS, function='encapsulationKeyCheck')['tests']
    dkc = group(ed, parameterSet=PS, function='decapsulationKeyCheck')['tests']
    for i, t in enumerate(ekc):
        dump(a.outdir, 'v_ekc%d_ek.hex' % i, t['ek'])
    for i, t in enumerate(dkc):
        dump(a.outdir, 'v_dkc%d_dk.hex' % i, t['dk'])
    with open(os.path.join(a.outdir, 'v_kc_exp.hex'), 'w') as f:
        # one byte per test: 00 = must reject, 01 = must accept
        flags = (['%02x' % (1 if t['testPassed'] else 0) for t in ekc] +
                 ['%02x' % (1 if t['testPassed'] else 0) for t in dkc])
        f.write('\n'.join(flags) + '\n')
    print('encapKeyCheck:', [(t['tcId'], t['testPassed']) for t in ekc])
    print('decapKeyCheck:', [(t['tcId'], t['testPassed']) for t in dkc])

    with open(os.path.join(a.outdir, 'nvec.vh'), 'w') as f:
        f.write('`define N_KG %d\n`define N_EN %d\n`define N_DE %d\n'
                '`define N_EKC %d\n`define N_DKC %d\n`define V_DIR "%s"\n'
                % (len(kgt), len(ent), len(det), len(ekc), len(dkc),
                   os.path.abspath(a.outdir).replace('\\', '/')))

    print('keyGen tcIds :', [t['tcId'] for t in kgt])
    print('encaps tcIds :', [t['tcId'] for t in ent])
    print('decaps tcIds :', [(t['tcId'], t['reason']) for t in det])
    print('wrote %d vectors to %s' % (len(kgt) + len(ent) + len(det), a.outdir))


if __name__ == '__main__':
    main()
