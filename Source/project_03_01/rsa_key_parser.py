#!/usr/bin/env python3

import argparse
import sys
import os
from math import gcd

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def load_private_key(filepath):
    with open(filepath, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("File does not contain an RSA private key")
    return private_key


def load_public_key(filepath):
    with open(filepath, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("File does not contain an RSA public key")
    return public_key


def extract_private_key_components(private_key):
    # Lay cac thanh phan tu private key
    # Cau truc theo RSAPrivateKey trong rsa_asn1.c
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    
    return {
        'n': public_numbers.n,
        'e': public_numbers.e,
        'd': private_numbers.d,
        'p': private_numbers.p,
        'q': private_numbers.q,
        'dmp1': private_numbers.dmp1,
        'dmq1': private_numbers.dmq1,
        'iqmp': private_numbers.iqmp,
    }


def extract_public_key_components(public_key):
    # Lay n va e tu public key
    public_numbers = public_key.public_numbers()
    return {
        'n': public_numbers.n,
        'e': public_numbers.e,
    }


def lcm(a, b):
    return abs(a * b) // gcd(a, b)


def mod_inverse(a, m):
    # Tim nghich dao modular bang thuat toan Euclid mo rong
    old_r, r = m, a % m
    old_s, s = 0, 1
    
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    
    return (old_s % m + m) % m


def validate_key_components(components):
    # Kiem tra tinh hop le cua khoa (dua tren rsa_chk.c)
    results = {}
    
    n = components['n']
    e = components['e']
    d = components['d']
    p = components['p']
    q = components['q']
    dmp1 = components['dmp1']
    dmq1 = components['dmq1']
    iqmp = components['iqmp']
    
    # kiem tra n = p * q
    n_calc = p * q
    results['n_equals_p_times_q'] = (n == n_calc)
    
    # kiem tra d * e = 1 (mod lambda(n)), voi lambda(n) = lcm(p-1, q-1)
    lambda_n = lcm(p - 1, q - 1)
    de_mod_lambda = (d * e) % lambda_n
    results['d_e_congruent_to_1_mod_lambda'] = (de_mod_lambda == 1)
    
    # kiem tra voi phi(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    de_mod_phi = (d * e) % phi_n
    results['d_e_congruent_to_1_mod_phi'] = (de_mod_phi == 1)
    
    # kiem tra dmp1 = d mod (p-1)
    dmp1_calc = d % (p - 1)
    results['dmp1_valid'] = (dmp1 == dmp1_calc)
    
    # kiem tra dmq1 = d mod (q-1)
    dmq1_calc = d % (q - 1)
    results['dmq1_valid'] = (dmq1 == dmq1_calc)
    
    # kiem tra iqmp = q^-1 mod p
    iqmp_calc = mod_inverse(q, p)
    results['iqmp_valid'] = (iqmp == iqmp_calc)
    
    # kiem tra iqmp * q = 1 (mod p)
    results['iqmp_inverse_check'] = ((iqmp * q) % p == 1)
    
    return results


def format_number(num, name, bits=None):
    # format so lon de hien thi giong OpenSSL
    if bits is None:
        bits = num.bit_length()
    
    hex_str = format(num, 'x')
    
    formatted_hex = ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    
    # wrap at 45 chars
    lines = []
    current_line = ""
    for part in formatted_hex.split(':'):
        if len(current_line) + len(part) + 1 > 45:
            lines.append(current_line)
            current_line = part
        else:
            current_line = current_line + ':' + part if current_line else part
    if current_line:
        lines.append(current_line)
    
    wrapped = '\n\t\t'.join(lines)
    
    return f"\t{name} ({bits} bits):\n\t\t{wrapped}"


def print_private_key_info(components, validation):
    n = components['n']
    key_bits = n.bit_length()
    
    print(f"\n{'='*60}")
    print(f"RSA Private Key ({key_bits} bits)")
    print(f"{'='*60}")
    
    print("\n[Key Components]")
    print(format_number(components['n'], 'modulo (n)', key_bits))
    print(format_number(components['e'], 'publicExponent (e)'))
    print(format_number(components['d'], 'privateExponent (d)'))
    print(format_number(components['p'], 'prime1 (p)'))
    print(format_number(components['q'], 'prime2 (q)'))
    print(format_number(components['dmp1'], 'exponent1 (dP = d mod p-1)'))
    print(format_number(components['dmq1'], 'exponent2 (dQ = d mod q-1)'))
    print(format_number(components['iqmp'], 'coefficient (qInv = q^-1 mod p)'))
    
    print(f"\n[Key Validation]")
    all_valid = True
    
    # Required checks for a valid RSA key
    required_checks = [
        ('n_equals_p_times_q', 'n = p * q'),
        ('d_e_congruent_to_1_mod_lambda', 'd * e = 1 (mod lambda(n))'),
        ('dmp1_valid', 'dP = d mod (p-1)'),
        ('dmq1_valid', 'dQ = d mod (q-1)'),
        ('iqmp_valid', 'qInv = q^-1 mod p'),
        ('iqmp_inverse_check', 'qInv x q = 1 (mod p)'),
    ]
    
    for key, desc in required_checks:
        status = "PASS" if validation[key] else "FAIL"
        if not validation[key]:
            all_valid = False
        print(f"\t{status}: {desc}")
    

    phi_status = "PASS" if validation['d_e_congruent_to_1_mod_phi'] else "FAIL"
    print(f"\t{phi_status}: d x e = 1 (mod phi(n))")
    
    print(f"\n\tOverall: {'KEY IS VALID' if all_valid else 'KEY IS INVALID'}")


def print_public_key_info(components):
    n = components['n']
    key_bits = n.bit_length()
    
    print(f"\n{'='*60}")
    print(f"RSA Public Key ({key_bits} bits)")
    print(f"{'='*60}")
    
    print("\n[Key Components]")
    print(format_number(components['n'], 'modulo (n)', key_bits))
    print(format_number(components['e'], 'publicExponent (e)'))


def main():
    parser = argparse.ArgumentParser(
        description='Doc va kiem tra khoa RSA tu file PEM cua OpenSSL',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Vi du:
  %(prog)s priv.pem\t\tDoc private key
  %(prog)s priv.pem pub.pem\tDoc ca private va public key
        """
    )

    parser.add_argument('private_key', help='Duong dan toi file private key PEM')
    parser.add_argument('public_key', nargs='?', help='Duong dan toi file public key PEM (khong bat buoc)')
    
    args = parser.parse_args()
    
    if not args.private_key:
        parser.print_help()
        sys.exit(1)
    
    # Parse private key
    if not os.path.exists(args.private_key):
        print(f"Error: File not found: {args.private_key}", file=sys.stderr)
        sys.exit(1)
    
    try:
        private_key = load_private_key(args.private_key)
        priv_components = extract_private_key_components(private_key)
        validation = validate_key_components(priv_components)
        print_private_key_info(priv_components, validation)
    except Exception as e:
        print(f"Error loading private key: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Parse public key if provided
    if args.public_key:
        if not os.path.exists(args.public_key):
            print(f"Error: File not found: {args.public_key}", file=sys.stderr)
            sys.exit(1)
        
        try:
            public_key = load_public_key(args.public_key)
            pub_components = extract_public_key_components(public_key)
            print_public_key_info(pub_components)
            
            # So sanh
            print(f"\n[So sanh]")
            n_match = priv_components['n'] == pub_components['n']
            e_match = priv_components['e'] == pub_components['e']
            print(f"\t{'OK' if n_match else 'FAIL'} - Modulus (n) giong nhau")
            print(f"\t{'OK' if e_match else 'FAIL'} - Public exponent (e) giong nhau")
            
        except Exception as e:
            print(f"Error loading public key: {e}", file=sys.stderr)
            sys.exit(1)
    
    print()


if __name__ == '__main__':
    main()