"""
Usage:
    Sign:   python rsa_signature.py sign <priv.pem> <message_file> <signature_output>
    Verify: python rsa_signature.py verify <pub.pem> <message_file> <signature_file>

Examples:
    python rsa_signature.py sign priv.pem mess.txt sign.bin
    python rsa_signature.py verify pub.pem mess.txt sign.bin

OpenSSL:
    Signing:   openssl pkeyutl -in <mess> -out <sign> -inkey <priv.pem> -sign
    Verifying: openssl pkeyutl -in <mess> -sigfile <sign> -inkey <pub.pem> -pubin -verify
"""

import argparse
import sys
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


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


def sign_message_raw(private_key, message):
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15 
    # Get key size in bytes
    key_size_bytes = (private_key.key_size + 7) // 8
    
    # Maximum message length = key_size_bytes - 11
    max_message_len = key_size_bytes - 11
    
    if len(message) > max_message_len:
        raise ValueError(f"Message too long for raw RSA signing. Max: {max_message_len} bytes, Got: {len(message)} bytes")
    
    padding_length = key_size_bytes - len(message) - 3
    padded = bytes([0x00, 0x01]) + bytes([0xFF] * padding_length) + bytes([0x00]) + message
    
    # Convert to integer
    padded_int = int.from_bytes(padded, 'big')
    
    # Get private key numbers for RSA operation
    private_numbers = private_key.private_numbers()
    n = private_numbers.public_numbers.n
    d = private_numbers.d
    
    # Raw RSA: signature = padded^d mod n
    sig_int = pow(padded_int, d, n)
    
    # Convert back to bytes
    signature = sig_int.to_bytes(key_size_bytes, 'big')
    
    return signature


def verify_signature_raw(public_key, message, signature):
    try:
        # Get key size in bytes
        key_size_bytes = (public_key.key_size + 7) // 8
        
        # Get public key numbers
        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e
        
        # Convert signature to integer
        sig_int = int.from_bytes(signature, 'big')
        
        # Verification: decrypted = signature^e mod n
        decrypted_int = pow(sig_int, e, n)
        
        # Convert back to bytes
        decrypted = decrypted_int.to_bytes(key_size_bytes, 'big')
        
        # Check PKCS#1 v1.5 type 1 padding
        if decrypted[0:2] != bytes([0x00, 0x01]):
            return False
        
        separator_idx = decrypted.find(bytes([0x00]), 2)
        if separator_idx == -1:
            return False
        
        padding_bytes = decrypted[2:separator_idx]
        if not all(b == 0xFF for b in padding_bytes):
            return False
        
        # Extract message
        extracted_message = decrypted[separator_idx + 1:]
        
        # Compare with original message
        return extracted_message == message
        
    except Exception:
        return False


def do_sign(args):
    """Execute signing operation."""
    # Check if files exist
    if not os.path.exists(args.key):
        print(f"Error: Private key file not found: {args.key}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.message):
        print(f"Error: Message file not found: {args.message}", file=sys.stderr)
        sys.exit(1)

    # Load private key
    try:
        private_key = load_private_key(args.key)
        key_size = private_key.key_size
        print(f"Loaded private key from: {args.key} ({key_size} bits)")
    except Exception as e:
        print(f"Error loading private key: {e}", file=sys.stderr)
        sys.exit(1)

    # Read message
    try:
        with open(args.message, 'rb') as f:
            message = f.read()
        print(f"Read message from: {args.message} ({len(message)} bytes)")
    except Exception as e:
        print(f"Error reading message file: {e}", file=sys.stderr)
        sys.exit(1)

    # Sign the message
    try:
        signature = sign_message_raw(private_key, message)
        print(f"Generated signature ({len(signature)} bytes)")
    except Exception as e:
        print(f"Error signing message: {e}", file=sys.stderr)
        sys.exit(1)

    # Write signature to file
    try:
        with open(args.output, 'wb') as f:
            f.write(signature)
        print(f"Signature written to: {args.output}")
        print("\n" + "="*50)
        print("Signing completed successfully!")
        print("="*50)
    except Exception as e:
        print(f"Error writing signature file: {e}", file=sys.stderr)
        sys.exit(1)


def do_verify(args):
    """Execute verification operation."""
    # Check if files exist
    if not os.path.exists(args.key):
        print(f"Error: Public key file not found: {args.key}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.message):
        print(f"Error: Message file not found: {args.message}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.signature):
        print(f"Error: Signature file not found: {args.signature}", file=sys.stderr)
        sys.exit(1)

    # Load public key
    try:
        public_key = load_public_key(args.key)
        key_size = public_key.key_size
        print(f"Loaded public key from: {args.key} ({key_size} bits)")
    except Exception as e:
        print(f"Error loading public key: {e}", file=sys.stderr)
        sys.exit(1)

    # Read message
    try:
        with open(args.message, 'rb') as f:
            message = f.read()
        print(f"Read message from: {args.message} ({len(message)} bytes)")
    except Exception as e:
        print(f"Error reading message file: {e}", file=sys.stderr)
        sys.exit(1)

    # Read signature
    try:
        with open(args.signature, 'rb') as f:
            signature = f.read()
        print(f"Read signature from: {args.signature} ({len(signature)} bytes)")
    except Exception as e:
        print(f"Error reading signature file: {e}", file=sys.stderr)
        sys.exit(1)

    # Verify signature
    print("\n" + "="*50)
    if verify_signature_raw(public_key, message, signature):
        print("Signature Verified Successfully")
        print("="*50)
        print("\nThe signature is VALID for the given message.")
    else:
        print("Signature Verification Failed")
        print("="*50)
        print("\nThe signature is INVALID for the given message.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='RSA Digital Signature - Sign and Verify messages (raw RSA)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Sign a message:
    %(prog)s sign priv.pem mess.txt sign.bin
    
  Verify a signature:
    %(prog)s verify pub.pem mess.txt sign.bin
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Sign subcommand
    sign_parser = subparsers.add_parser('sign', help='Sign a message using private key')
    sign_parser.add_argument('key', help='Path to private key PEM file')
    sign_parser.add_argument('message', help='Path to message file to sign')
    sign_parser.add_argument('output', help='Path to output signature file')
    
    # Verify subcommand
    verify_parser = subparsers.add_parser('verify', help='Verify a signature using public key')
    verify_parser.add_argument('key', help='Path to public key PEM file')
    verify_parser.add_argument('message', help='Path to message file')
    verify_parser.add_argument('signature', help='Path to signature file')
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    elif args.command == 'sign':
        do_sign(args)
    elif args.command == 'verify':
        do_verify(args)


if __name__ == '__main__':
    main()
