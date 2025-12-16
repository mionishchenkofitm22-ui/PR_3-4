#!/usr/bin/env python3
from __future__ import annotations

import argparse, time
from pathlib import Path

from src.logger_setup import log_event
from src.crypto_sym import KeyStore, read_container as sym_read, write_container as sym_write, encrypt_bytes, decrypt_bytes, IntegrityError, BadFormat
from src.crypto_rsa import generate_keys, load_private, load_public, sign_bytes, verify_bytes, BadKey
from src.crypto_hybrid import hybrid_encrypt, hybrid_decrypt, write_container as hybr_write, read_container as hybr_read

def cmd_sym(args):
    ks = KeyStore()
    if args.action == "new":
        km = ks.new_key(args.label)
        log_event("sym_key_new", label=args.label, version=km.version)
        print(f"OK: created key label={km.label} version=v{km.version}")
        return

    if args.action in ("enc", "dec"):
        km = ks.get(args.label, args.version)
        inp = Path(args.in_path)
        out = Path(args.out_path)
        if args.action == "enc":
            pt = inp.read_bytes()
            header, ct = encrypt_bytes(pt, km, mode=args.mode)
            sym_write(out, header, ct)
            log_event("sym_encrypt", label=km.label, version=km.version, mode=args.mode, in_path=str(inp), out_path=str(out), bytes=len(pt))
            print(f"OK: encrypted mode={args.mode} -> {out}")
        else:
            header, ct = sym_read(inp)
            try:
                pt = decrypt_bytes(header, ct, km)
            except IntegrityError as e:
                log_event("sym_decrypt_failed", reason="integrity", in_path=str(inp))
                raise SystemExit(f"ERROR: integrity check failed ({e})")
            except BadFormat as e:
                log_event("sym_decrypt_failed", reason="format", in_path=str(inp))
                raise SystemExit(f"ERROR: bad format ({e})")
            out.write_bytes(pt)
            log_event("sym_decrypt", label=km.label, version=km.version, mode=header.get("mode"), in_path=str(inp), out_path=str(out), bytes=len(pt))
            print(f"OK: decrypted -> {out}")
        return

    raise SystemExit("Unknown sym action")

def cmd_rsa(args):
    if args.action == "gen":
        generate_keys(Path(args.priv), Path(args.pub), password=args.password, bits=args.bits)
        log_event("rsa_gen", bits=args.bits, priv=args.priv, pub=args.pub)
        print("OK: generated RSA keypair")
        return

    if args.action == "sign":
        priv = load_private(Path(args.priv), password=args.password)
        data = Path(args.in_path).read_bytes()
        sig = sign_bytes(priv, data)
        Path(args.sig).write_bytes(sig)
        log_event("rsa_sign", in_path=args.in_path, sig=args.sig, bytes=len(data))
        print(f"OK: signature -> {args.sig}")
        return

    if args.action == "verify":
        pub = load_public(Path(args.pub))
        data = Path(args.in_path).read_bytes()
        sig = Path(args.sig).read_bytes()
        ok = verify_bytes(pub, data, sig)
        log_event("rsa_verify", in_path=args.in_path, sig=args.sig, ok=ok)
        print("OK" if ok else "FAIL")
        raise SystemExit(0 if ok else 2)

    raise SystemExit("Unknown rsa action")

def cmd_hybrid(args):
    inp = Path(args.in_path)
    out = Path(args.out_path)
    if args.action == "enc":
        data = inp.read_bytes()
        header, ct = hybrid_encrypt(Path(args.pub), data, mode=args.mode)
        hybr_write(out, header, ct)
        log_event("hybrid_encrypt", mode=args.mode, in_path=str(inp), out_path=str(out), bytes=len(data))
        print(f"OK: hybrid encrypted -> {out}")
        return

    if args.action == "dec":
        header, ct = hybr_read(Path(args.in_path))
        try:
            pt = hybrid_decrypt(Path(args.priv), password=args.password, header=header, ciphertext=ct)
        except BadKey as e:
            log_event("hybrid_decrypt_failed", reason="bad_key", in_path=args.in_path)
            raise SystemExit(f"ERROR: bad private key / password ({e})")
        except Exception as e:
            log_event("hybrid_decrypt_failed", reason="crypto", in_path=args.in_path)
            raise SystemExit(f"ERROR: decrypt failed ({e})")
        out.write_bytes(pt)
        log_event("hybrid_decrypt", out_path=str(out), bytes=len(pt))
        print(f"OK: hybrid decrypted -> {out}")
        return

    raise SystemExit("Unknown hybrid action")

def parse_size(s: str) -> int:
    s = s.strip().upper()
    if s.endswith("KB"):
        return int(s[:-2]) * 1024
    if s.endswith("MB"):
        return int(s[:-2]) * 1024 * 1024
    if s.endswith("B"):
        return int(s[:-1])
    return int(s)

def cmd_bench(args):
    import os
    from statistics import median

    sizes = [parse_size(x) for x in args.sizes]
    modes = args.modes
    rsa_bits = args.rsa_bits

    print("Benchmarking... (times in ms)")
    rows = []

    # symmetric
    ks = KeyStore()
    try:
        km = ks.get("bench")
    except Exception:
        km = ks.new_key("bench")

    for sz in sizes:
        data = os.urandom(sz)
        for mode in modes:
            # encrypt
            t0 = time.perf_counter()
            h, ct = encrypt_bytes(data, km, mode=mode)
            t1 = time.perf_counter()
            # decrypt
            pt = decrypt_bytes(h, ct, km)
            t2 = time.perf_counter()
            assert pt == data
            rows.append(("AES-"+mode.upper(), sz, (t1-t0)*1000, (t2-t1)*1000))

    # RSA keygen cost (rough)
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import serialization as _ser

    for bits in rsa_bits:
        t0 = time.perf_counter()
        k = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
        t1 = time.perf_counter()
        # sign small payload
        small = b"bench"
        sig = k.sign(small, __import__("cryptography.hazmat.primitives.asymmetric.padding").hazmat.primitives.asymmetric.padding.PSS(
            mgf=__import__("cryptography.hazmat.primitives.asymmetric.padding").hazmat.primitives.asymmetric.padding.MGF1(__import__("cryptography.hazmat.primitives.hashes").hazmat.primitives.hashes.SHA256()),
            salt_length=__import__("cryptography.hazmat.primitives.asymmetric.padding").hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH,
        ), __import__("cryptography.hazmat.primitives.hashes").hazmat.primitives.hashes.SHA256())
        t2 = time.perf_counter()
        rows.append((f"RSA-{bits} (gen)", 0, (t1-t0)*1000, 0.0))
        rows.append((f"RSA-{bits} (sign 4B)", 4, (t2-t1)*1000, 0.0))

    # Print table
    print(f"{'Algo':<18} {'Size(B)':>10} {'Enc(ms)':>10} {'Dec(ms)':>10}")
    for algo, sz, enc_ms, dec_ms in rows:
        print(f"{algo:<18} {sz:>10} {enc_ms:>10.2f} {dec_ms:>10.2f}")

    log_event("bench_done", rows=len(rows), sizes=args.sizes, modes=modes, rsa_bits=rsa_bits)
    # Save CSV
    out_csv = Path("outputs/bench.csv")
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_csv.write_text("algo,size_bytes,enc_ms,dec_ms\n" + "\n".join(
        f"{a},{s},{e:.3f},{d:.3f}" for a,s,e,d in rows
    ) + "\n", encoding="utf-8")
    print(f"\nSaved: {out_csv}")

def build_parser():
    p = argparse.ArgumentParser(prog="cli.py", description="PR3-4 crypto demo (AES/RSA/Hybrid)")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("sym", help="symmetric AES operations")
    ps_sub = ps.add_subparsers(dest="action", required=True)
    ps_new = ps_sub.add_parser("new", help="create new key version for label")
    ps_new.add_argument("--label", required=True)
    ps_new.set_defaults(func=cmd_sym)

    ps_enc = ps_sub.add_parser("enc", help="encrypt file")
    ps_enc.add_argument("--label", required=True)
    ps_enc.add_argument("--version", type=int, default=None)
    ps_enc.add_argument("--mode", choices=["gcm","cbc"], default="gcm")
    ps_enc.add_argument("--in", dest="in_path", required=True)
    ps_enc.add_argument("--out", dest="out_path", required=True)
    ps_enc.set_defaults(func=cmd_sym)

    ps_dec = ps_sub.add_parser("dec", help="decrypt file")
    ps_dec.add_argument("--label", required=True)
    ps_dec.add_argument("--version", type=int, default=None)
    ps_dec.add_argument("--in", dest="in_path", required=True)
    ps_dec.add_argument("--out", dest="out_path", required=True)
    ps_dec.set_defaults(func=cmd_sym)

    pr = sub.add_parser("rsa", help="RSA operations")
    pr_sub = pr.add_subparsers(dest="action", required=True)
    pr_gen = pr_sub.add_parser("gen")
    pr_gen.add_argument("--priv", required=True)
    pr_gen.add_argument("--pub", required=True)
    pr_gen.add_argument("--password", required=True)
    pr_gen.add_argument("--bits", type=int, default=3072)
    pr_gen.set_defaults(func=cmd_rsa)

    pr_sign = pr_sub.add_parser("sign")
    pr_sign.add_argument("--priv", required=True)
    pr_sign.add_argument("--password", required=True)
    pr_sign.add_argument("--in", dest="in_path", required=True)
    pr_sign.add_argument("--sig", required=True)
    pr_sign.set_defaults(func=cmd_rsa)

    pr_ver = pr_sub.add_parser("verify")
    pr_ver.add_argument("--pub", required=True)
    pr_ver.add_argument("--in", dest="in_path", required=True)
    pr_ver.add_argument("--sig", required=True)
    pr_ver.set_defaults(func=cmd_rsa)

    ph = sub.add_parser("hybrid", help="hybrid encryption")
    ph_sub = ph.add_subparsers(dest="action", required=True)
    ph_enc = ph_sub.add_parser("enc")
    ph_enc.add_argument("--pub", required=True)
    ph_enc.add_argument("--mode", choices=["gcm","cbc"], default="gcm")
    ph_enc.add_argument("--in", dest="in_path", required=True)
    ph_enc.add_argument("--out", dest="out_path", required=True)
    ph_enc.set_defaults(func=cmd_hybrid)

    ph_dec = ph_sub.add_parser("dec")
    ph_dec.add_argument("--priv", required=True)
    ph_dec.add_argument("--password", required=True)
    ph_dec.add_argument("--in", dest="in_path", required=True)
    ph_dec.add_argument("--out", dest="out_path", required=True)
    ph_dec.set_defaults(func=cmd_hybrid)

    pb = sub.add_parser("bench", help="performance benchmarks")
    pb.add_argument("--sizes", nargs="+", default=["1MB","10MB"])
    pb.add_argument("--modes", nargs="+", choices=["gcm","cbc"], default=["gcm","cbc"])
    pb.add_argument("--rsa-bits", dest="rsa_bits", nargs="+", type=int, default=[2048,3072,4096])
    pb.set_defaults(func=cmd_bench)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
