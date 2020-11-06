import sys
from collections import namedtuple
from random import randint
import os
from codecs import getdecoder
from codecs import getencoder
import asn1
from sympy import invert
from hashlib import sha256

Point = namedtuple("Point", "x y")
EllipticCurve = namedtuple("EllipticCurve", "a b")
Origin = None

# Helper functions for bytes2long realization
_hexdecoder = getdecoder("hex")
_hexencoder = getencoder("hex")

def hexenc(data):
  """Encode hexadecimal
  """
  return _hexencoder(data)[0].decode("ascii")
# End of helper functions of bytes2long realization


# Function to convert bytes to long number
def bytes2long(raw):
  """ Deserialize big-endian bytes into long number
  :param \b0 bytes raw: binary string
  :returns\b0 : deserialized long number
  :rtype\b0 : int
  """
  return int(hexenc(raw), 16)

import math
# Generate random number from 1 to r-1
# Und return only mutually prime number with r
def rand(r):
    while True:
        k = randint(1, r - 1)
        if math.gcd(k, r) == 1:
            return k

# Let's init vars in global scope
p = q = d = 0
Q = Origin
point = Origin
curve = Origin

# Here is a function to multiply point to some number
# From theory
def multiply(point, x, a, p):
    if x == 0:
        return None
    x_bin = [int(k) for k in bin(x)[2:]]
    result = Origin
    for k in x_bin:
        result = add(result, result, a, p)
        if k != 0:
            result = add(result, point, a, p)
    return result

# Points addition from theory
def add(point_a, point_b, a, p):
    if point_a is Origin:
        return point_b
    elif point_b is Origin:
        return point_a
    s = slope(point_a, point_b, a, p)

    if s is None:
        return None
    else:
        s = int(s)
    x = (s ** 2 - point_a.x - point_b.x) % p
    y = (s * (point_a.x - x) - point_a.y) % p
    return Point(x, y)

def slope(point_a, point_b, a, p):
    if point_a.x != point_b.x:
        s = (point_b.y - point_a.y) * invert((point_b.x - point_a.x), p)
    elif point_a.y == point_b.y:
        s = (3 * point_a.x ** 2 + a) * invert((2 * point_a.y), p)
    else:
        return None
    return s % p

# Get random point in [1, n)
def random_point(n):
    x = randint(1, n - 1)
    y = randint(1, n - 1)
    return Point(x, y)

# Check equation
def is_curve_params_correct(a, b):
    return True if 4 * a ** 3 + 27 * b ** 2 != 0 else False

# Generate elliptic curve
def random_elliptic_curve(n):
    while True:
        point = random_point(n)
        a = randint(1, n - 1)
        b = (point.y ** 2 - point.x ** 3 - a * point.x) % n
        if is_curve_params_correct(a, b) is True:
            break
    return EllipticCurve(a, b), point

def prv_unmarshal(prv):
    """Unmarshal private key
    :param \b0 bytes prv: serialized private key
    :rtype\b0 : long
    """
    return bytes2long(prv[::-1])

# Process parameters from given numbers
def ProcessParameter():
    p = 57896044620753384133869303843568937902752767818974600847634902975134129543643
    q = 28948022310376692066934651921784468951377218528270520403696863131129758387393
    a = 1
    b = 52259530098387149819562511889780651425271270942919542722038553712464420235875
    x = 14539175448068301073584752148116082765715462525899666138074034449285211025933
    y = 8328801466633898282311029798556417767141491055036399348346324804478619400451
    curve = EllipticCurve(a, b)
    point = Point(x, y)
    q = q
    d = prv_unmarshal(os.urandom(64)) # Private key
    Q = multiply(point, d, curve.a, p) # Public key
    print('[+] a = ', hex(curve.a))
    print('[+] b = ', hex(curve.b))
    # print('[+] x = ', hex(point.x))
    # print('[+] y = ', hex(point.y))
    print('[+] p = ', hex(p))
    print('[+] r = ', hex(q))
    # print('[+] d = ', hex(d))
    print('[+] P.x = ', hex(Q.x))
    print('[+] P.y = ', hex(Q.y))
    return p, q, curve, point, d, Q

# ASN.1
def encode_signature(Q, prime, curve, P, group_order, signature_r, signature_s, ksi):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(b'\\x80\\x06\\x07\\x00', asn1.Numbers.OctetString)
    encoder.write(b'GOST 34.10-2018', asn1.Numbers.UTF8String)
    # Public key Q(x,y)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(Q.x, asn1.Numbers.Integer) # Qx
    encoder.write(Q.y, asn1.Numbers.Integer) # Qy
    encoder.leave()
    # Cryptosystem parameters
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(prime, asn1.Numbers.Integer)
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(curve.a, asn1.Numbers.Integer) # A parameter
    encoder.write(curve.b, asn1.Numbers.Integer) # B parameter
    encoder.leave()
    # P(x,y)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(P.x, asn1.Numbers.Integer) # Px
    encoder.write(P.y, asn1.Numbers.Integer) # Py
    encoder.leave()
    # Group order (r)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(group_order, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    # Sugnature
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(signature_r, asn1.Numbers.Integer)
    # First part of signature (r)
    encoder.write(signature_s, asn1.Numbers.Integer)
    # Second part of signature (s)
    encoder.leave()
    encoder.leave()
    # Files parameters
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()
    encoder.leave()
    encoded_bytes = encoder.output()
    return encoded_bytes

params = []
params_dict = { 'Qx': 0, 'Qy': 1, 'p': 2, 'a': 3, 'b': 4, 'Px': 5, 'Py': 6, 'q': 7, 'r': 8, 's': 9 }

# Decode asn1 file format
def parse_ans1(decoder):
    while not decoder.eof():
        tag = decoder.peek()
        if tag.nr == asn1.Numbers.Null:
            break
        if tag.typ == asn1.Types.Primitive:
            tag, value = decoder.read()
            if tag.nr == asn1.Numbers.Integer:
                params.append(value)
        else:
            decoder.enter()
            parse_ans1(decoder)
            decoder.leave()

# Sign file using El-Gamal
def elgamal_ecc_sign(src_file, sign_file):
    global p, q, curve, point, d, Q
    p, q, curve, point, d, Q = ProcessParameter()
    with open(src_file, mode='rb') as file:
        data = file.read()

# First step
    dgst = sha256(data).digest() # Used sha256, but standard use stribog.
    with open("hash", mode='wb') as file:
        data = file.write(dgst)
# Second step
    alfa = int.from_bytes(dgst, byteorder='big')
    e = alfa % q
    print('[+] e = ', hex(e))
    if e == 0:
        e = 1
    k = 0
    r = 0
    s = 0
    C = Origin
    while True:
        # Third step
        k = rand(q)
        # Fourth step
        C = multiply(point, k, curve.a, p)
        r = C.x % q
        if r == 0:
            continue
        # Fifth step
        s = (r * d + k * e) % q
        if s == 0:
            continue
        break
    r_bin = [int(k) for k in bin(r)[2:]]
    s_bin = [int(k) for k in bin(s)[2:]]

    # Sixth step
    ksi = str(r_bin) + str(s_bin)
    encoded_bytes = encode_signature(Q, p, curve, point, q, r, s, ksi)
    with open(sign_file, mode='wb') as file:
        file.write(encoded_bytes)
    print('[+] File successfully signed!')

# Check file sign using El-Gamal
def elgamal_ecc_verify(src_file, sign_file):
    with open(sign_file, mode='rb') as file:
        encoded_data = file.read()

    decoder = asn1.Decoder()
    decoder.start(encoded_data)
    parse_ans1(decoder)
    Qx = params[params_dict['Qx']]
    Qy = params[params_dict['Qy']]
    p = params[params_dict['p']]
    a = params[params_dict['a']]
    # b = params[params_dict['b']]
    Px = params[params_dict['Px']]
    Py = params[params_dict['Py']]
    q = params[params_dict['q']]
    r = params[params_dict['r']]
    s = params[params_dict['s']]


# First step
    r = int(r)
    s = int(s)

    print('[+] a = ', hex(a))
    print('[+] x = ', hex(Px))
    print('[+] y = ', hex(Py))
    print('[+] p = ', hex(p))
    print('[+] r = ', hex(q))
    print('[+] P.x = ', hex(Qx))
    print('[+] P.y = ', hex(Qy))
    if r <= 0 or r >= q or s <= 0 or s >= q:
        print('[-] Invalid signature! r <= 0 || r >= q || s <= 0 || s >= q ! ')

    with open(src_file, mode='rb') as file:
        data = file.read()
# Second step
    # Used sha256, but standard use stribog
    dgst = sha256(data).digest()
# Third step
    alfa = int.from_bytes(dgst, byteorder='big')
    e = alfa % q
    print('[+] e = ', hex(e))
    if e == 0:
        e = 1
# Fourth step
    v = invert(e, q)
# Fifth step
    z1 = s * v % q z2 = -r * v % q
# Sixth step
    c1 = multiply(Point(Px, Py), z1, a, p)
    c2 = multiply(Point(Qx, Qy), z2, a, p)

    C = add(c1, c2, a, p) R = C.x % q

# Seventh step
    if R == r:
        print('[+] Signature is valid!')
    else:
        print('[-] Invalid signature!')

def main():
    if len(sys.argv) < 4:
        print( "[-] Error! Usage: python <program name> [sign] [verify] <message filename> <sign filename>")
    if sys.argv[1] == 'sign':
        elgamal_ecc_sign(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == 'verify':
        elgamal_ecc_verify(sys.argv[2], sys.argv[3])
    else:
        print( "[-] Error! Usage: python <program name> [sign] [verify]' <message filename> <sign filename>")

if __name__ == '__main__':
    main()
