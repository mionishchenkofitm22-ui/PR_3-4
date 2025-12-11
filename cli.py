import argparse, os, time, base64
from logger import get_logger
from sym import SymKeyStore, encrypt_gcm, decrypt_gcm, encrypt_cbc_hmac, decrypt_cbc_hmac
from asym import gen_rsa, save_priv_pem, save_pub_pem, load_priv, load_pub, rsa_encrypt, rsa_decrypt, sign, verify
from hybrid import encrypt_hybrid, decrypt_hybrid

logger = get_logger()

def sym_cmd(args):
    ks = SymKeyStore()
    if args.action=='new':
        meta, key = ks.new(args.label, bits=args.bits)
        logger.info('sym.new', extra={'extra': meta})
        print('NEW KEY (keep secret):', base64.b64encode(key).decode())
    elif args.action=='enc':
        key = base64.b64decode(args.key) if args.key else None
        if not key:
            raise SystemExit('Provide --key (base64) from sym new output')
        t0=time.perf_counter()
        if args.mode=='gcm': encrypt_gcm(args.infile, args.outfile, key)
        else: encrypt_cbc_hmac(args.infile, args.outfile, key)
        dt=time.perf_counter()-t0
        logger.info('sym.enc', extra={'extra':{'mode':args.mode,'in':args.infile,'out':args.outfile,'sec':round(dt,4)}})
        print(f'Encrypted in {dt:.3f}s')
    elif args.action=='dec':
        key = base64.b64decode(args.key)
        t0=time.perf_counter()
        if args.mode=='gcm': decrypt_gcm(args.infile, args.outfile, key)
        else: decrypt_cbc_hmac(args.infile, args.outfile, key)
        dt=time.perf_counter()-t0
        logger.info('sym.dec', extra={'extra':{'mode':args.mode,'in':args.infile,'out':args.outfile,'sec':round(dt,4)}})
        print(f'Decrypted in {dt:.3f}s')


def rsa_cmd(args):
    if args.action=='gen':
        priv,pub = gen_rsa(args.bits)
        os.makedirs('keys', exist_ok=True)
        save_priv_pem(priv, args.priv, args.password)
        save_pub_pem(pub, args.pub)
        logger.info('rsa.gen', extra={'extra':{'bits':args.bits,'priv':args.priv,'pub':args.pub}})
        print('RSA keys saved.')
    elif args.action=='enc':
        pub = load_pub(args.pub)
        ct = rsa_encrypt(pub, open(args.infile,'rb').read())
        open(args.outfile,'wb').write(ct)
        print('RSA encrypt OK')
    elif args.action=='dec':
        priv = load_priv(args.priv, args.password)
        pt = rsa_decrypt(priv, open(args.infile,'rb').read())
        open(args.outfile,'wb').write(pt)
        print('RSA decrypt OK')
    elif args.action=='sign':
        priv = load_priv(args.priv, args.password)
        sig = sign(priv, open(args.infile,'rb').read())
        open(args.sig,'wb').write(sig)
        print('Signed')
    elif args.action=='verify':
        pub = load_pub(args.pub)
        ok = verify(pub, open(args.infile,'rb').read(), open(args.sig,'rb').read())
        print('VERIFY:', 'OK' if ok else 'FAIL')


def hybrid_cmd(args):
    if args.action=='enc':
        encrypt_hybrid(args.pub, args.infile, args.outfile)
        print('Hybrid encrypt OK')
    else:
        decrypt_hybrid(args.priv, args.password, args.infile, args.outfile)
        print('Hybrid decrypt OK')


def bench_cmd(args):
    import secrets
    sizes=[]
    for s in args.sizes:
        if s.lower().endswith('mb'): sizes.append(int(float(s[:-2])*1024*1024))
        elif s.lower().endswith('kb'): sizes.append(int(float(s[:-2])*1024))
        else: sizes.append(int(s))
    os.makedirs('outputs', exist_ok=True)
    key = secrets.token_bytes(32)
    results=[]
    for size in sizes:
        path=f'outputs/bench_{size}.bin'
        if not os.path.exists(path):
            with open(path,'wb') as f: f.write(secrets.token_bytes(size))
        for mode in args.modes:
            t0=time.perf_counter();
            if mode=='gcm': encrypt_gcm(path, path+'.enc', key)
            else: encrypt_cbc_hmac(path, path+'.enc', key)
            e=time.perf_counter()-t0
            t1=time.perf_counter();
            if mode=='gcm': decrypt_gcm(path+'.enc', path+'.dec', key)
            else: decrypt_cbc_hmac(path+'.enc', path+'.dec', key)
            d=time.perf_counter()-t1
            results.append((size, mode, e, d))
    # RSA keygens timing
    for bits in args.rsa_bits:
        t0=time.perf_counter();
        from asym import gen_rsa
        gen_rsa(bits)
        e=time.perf_counter()-t0
        results.append((0, f'RSA-{bits}-keygen', e, 0))
    # write markdown
    lines=["| Size | Mode | Enc (s) | Dec (s) | Enc MB/s | Dec MB/s |","|---:|---|---:|---:|---:|---:|"]
    for size, mode, e, d in results:
        mb=size/1024/1024 if size else 0
        lines.append(f"| {mb:.1f} | {mode} | {e:.3f} | {d:.3f} | {mb/e if e>0 else 0:.1f} | {mb/d if d>0 else 0:.1f} |")
    open('outputs/bench.md','w',encoding='utf-8').write("\n".join(lines))
    print('Bench -> outputs/bench.md')


def main():
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest='cmd', required=True)

    ps = sp.add_parser('sym'); ssp = ps.add_subparsers(dest='action', required=True)
    ps_new = ssp.add_parser('new'); ps_new.add_argument('--label', required=True); ps_new.add_argument('--bits', type=int, default=256)
    ps_enc = ssp.add_parser('enc'); ps_enc.add_argument('--label'); ps_enc.add_argument('--key'); ps_enc.add_argument('--in', dest='infile', required=True); ps_enc.add_argument('--out', dest='outfile', required=True); ps_enc.add_argument('--mode', choices=['gcm','cbc'], required=True)
    ps_dec = ssp.add_parser('dec'); ps_dec.add_argument('--key', required=True); ps_dec.add_argument('--in', dest='infile', required=True); ps_dec.add_argument('--out', dest='outfile', required=True); ps_dec.add_argument('--mode', choices=['gcm','cbc'], required=True)

    pr = sp.add_parser('rsa'); rsp = pr.add_subparsers(dest='action', required=True)
    pr_gen = rsp.add_parser('gen'); pr_gen.add_argument('--bits', type=int, default=3072); pr_gen.add_argument('--priv', required=True); pr_gen.add_argument('--pub', required=True); pr_gen.add_argument('--password', required=True)
    pr_enc = rsp.add_parser('enc'); pr_enc.add_argument('--pub', required=True); pr_enc.add_argument('--in', dest='infile', required=True); pr_enc.add_argument('--out', dest='outfile', required=True)
    pr_dec = rsp.add_parser('dec'); pr_dec.add_argument('--priv', required=True); pr_dec.add_argument('--password', required=True); pr_dec.add_argument('--in', dest='infile', required=True); pr_dec.add_argument('--out', dest='outfile', required=True)
    pr_sig = rsp.add_parser('sign'); pr_sig.add_argument('--priv', required=True); pr_sig.add_argument('--password', required=True); pr_sig.add_argument('--in', dest='infile', required=True); pr_sig.add_argument('--sig', required=True)
    pr_ver = rsp.add_parser('verify'); pr_ver.add_argument('--pub', required=True); pr_ver.add_argument('--in', dest='infile', required=True); pr_ver.add_argument('--sig', required=True)

    ph = sp.add_parser('hybrid'); hsp = ph.add_subparsers(dest='action', required=True)
    ph_enc = hsp.add_parser('enc'); ph_enc.add_argument('--pub', required=True); ph_enc.add_argument('--in', dest='infile', required=True); ph_enc.add_argument('--out', dest='outfile', required=True)
    ph_dec = hsp.add_parser('dec'); ph_dec.add_argument('--priv', required=True); ph_dec.add_argument('--password', required=True); ph_dec.add_argument('--in', dest='infile', required=True); ph_dec.add_argument('--out', dest='outfile', required=True)

    pb = sp.add_parser('bench'); pb.add_argument('--sizes', nargs='+', required=True); pb.add_argument('--modes', nargs='+', choices=['gcm','cbc'], default=['gcm','cbc']); pb.add_argument('--rsa-bits', nargs='+', type=int, default=[2048,3072,4096])

    args = p.parse_args()
    if args.cmd=='sym': sym_cmd(args)
    elif args.cmd=='rsa': rsa_cmd(args)
    elif args.cmd=='hybrid': hybrid_cmd(args)
    elif args.cmd=='bench': bench_cmd(args)

if __name__ == '__main__':
    main()
