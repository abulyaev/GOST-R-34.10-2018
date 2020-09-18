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
# Generate random number from 1 to r-1 \par
# Und return only mutually prime number with r \par
def rand(r): \par
\tab while True: \par
\tab\tab k = randint(1, r - 1) \par
\tab\tab if math.gcd(k, r) == 1: \par
\tab\tab\tab return k \par
\par
# Let's init vars in global scope \par
p = q = d = 0 \par
Q = Origin \par
point = Origin \par
curve = Origin \par
\par
# Here is a function to multiply point to some number \par
# From theory \par
def multiply(point, x, a, p): \par
\tab if x == 0: \par
\tab\tab return None \par
\tab x_bin = [int(k) for k in bin(x)[2:]] \par
\tab result = Origin \par
\tab for k in x_bin: \par
\tab\tab result = add(result, result, a, p) \par
\tab\tab if k != 0: \par
\tab\tab\tab result = add(result, point, a, p) \par
\tab return result \par
\par
# Points addition from theory \par
def add(point_a, point_b, a, p): \par
\tab if point_a is Origin: \par
\tab\tab return point_b \par
\tab elif point_b is Origin: \par
\tab\tab return point_a \par
\tab s = slope(point_a, point_b, a, p) \par
\tab\par
\tab if s is None: \par
\tab\tab return None \par
\tab else: \par
\tab\tab s = int(s) \par
\tab x = (s ** 2 - point_a.x - point_b.x) % p \par
\tab y = (s * (point_a.x - x) - point_a.y) % p \par
\tab return Point(x, y) \par
\par
def slope(point_a, point_b, a, p): \par
\tab if point_a.x != point_b.x:\fs24\par
\fs20\tab\tab s = (point_b.y - point_a.y) * invert((point_b.x - point_a.x), p) \par
\tab elif point_a.y == point_b.y: \par
\tab\tab s = (3 * point_a.x ** 2 + a) * invert((2 * point_a.y), p) \par
\tab else: \par
\tab\tab return None \par
\tab return s % p \par
\par
# Get random point in [1, n) \par
def random_point(n): \par
\tab x = randint(1, n - 1) \par
\tab y = randint(1, n - 1) \par
\tab return Point(x, y) \par
\par
# Check equation \par
def is_curve_params_correct(a, b): \par
\tab return True if 4 * a ** 3 + 27 * b ** 2 != 0 else False \par
\par
# Generate elliptic curve \par
def random_elliptic_curve(n): \par
\tab while True: \par
\tab\tab point = random_point(n) \par
\tab\tab a = randint(1, n - 1) \par
\tab\tab b = (point.y ** 2 - point.x ** 3 - a * point.x) % n \par
\tab\tab if is_curve_params_correct(a, b) is True: \par
\tab\tab\tab break \par
\tab return EllipticCurve(a, b), point \par
\par
def prv_unmarshal(prv): \par
\i\tab """Unmarshal private key \par
\b\tab :param \b0 bytes prv: serialized private key \par
\tab\b :rtype\b0 : long \par
\tab """ \par
\tab\i0 return bytes2long(prv[::-1]) \par
\par
# Process parameters from given numbers \par
def ProcessParameter(): \par
\tab p = 57896044620753384133869303843568937902752767818974600847634902975134129543643 \par
\tab q = 28948022310376692066934651921784468951377218528270520403696863131129758387393 \par
\tab a = 1 \par
\tab b = 52259530098387149819562511889780651425271270942919542722038553712464420235875 \par
\tab x = 14539175448068301073584752148116082765715462525899666138074034449285211025933 \par
\tab y = 8328801466633898282311029798556417767141491055036399348346324804478619400451 \tab curve = EllipticCurve(a, b) \par
\tab point = Point(x, y) \par
\tab q = q \par
\tab d = prv_unmarshal(os.urandom(64)) # Private key \par
\tab Q = multiply(point, d, curve.a, p) # Public key \par
\tab print('[+] a = ', hex(curve.a)) \par
\tab print('[+] b = ', hex(curve.b)) \par
\tab # print('[+] x = ', hex(point.x)) \par
\tab # print('[+] y = ', hex(point.y)) \par
\tab print('[+] p = ', hex(p))\fs24\par
\fs20\tab print('[+] r = ', hex(q)) \par
\tab # print('[+] d = ', hex(d)) \par
\tab print('[+] P.x = ', hex(Q.x)) \par
\tab print('[+] P.y = ', hex(Q.y)) \par
\tab return p, q, curve, point, d, Q \par
\par
# ASN.1 \par
def encode_signature(Q, prime, curve, P, group_order, signature_r, signature_s, ksi): \par
\tab encoder = asn1.Encoder() \par
\tab encoder.start() \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.enter(asn1.Numbers.Set) \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.write(b'\\x80\\x06\\x07\\x00', asn1.Numbers.OctetString) \par
\tab encoder.write(b'GOST 34.10-2018', asn1.Numbers.UTF8String) \par
\tab # Public key Q(x,y) \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.write(Q.x, asn1.Numbers.Integer) # Qx \par
\tab encoder.write(Q.y, asn1.Numbers.Integer) # Qy \par
\tab encoder.leave() \par
\tab # Cryptosystem parameters \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.write(prime, asn1.Numbers.Integer) \par
\tab encoder.leave() \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.write(curve.a, asn1.Numbers.Integer) # A parameter \par
\tab encoder.write(curve.b, asn1.Numbers.Integer) # B parameter \par
\tab encoder.leave() \par
\tab # P(x,y) \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.write(P.x, asn1.Numbers.Integer) # Px \par
\tab encoder.write(P.y, asn1.Numbers.Integer) # Py \par
\tab encoder.leave() \par
\tab # Group order (r) \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.write(group_order, asn1.Numbers.Integer) \par
\tab encoder.leave() \par
\tab encoder.leave() \par
\tab # Sugnature \par
\tab encoder.enter(asn1.Numbers.Sequence) \par
\tab encoder.write(signature_r, asn1.Numbers.Integer) # First part of signature (r) \tab encoder.write(signature_s, asn1.Numbers.Integer) # Second part of signature (s) \tab encoder.leave() \par
\tab encoder.leave() \par
\tab # Files parameters \par
\tab encoder.enter(asn1.Numbers.Sequence) \tab\par
\tab encoder.leave() \par
\tab encoder.leave() \par
\tab encoded_bytes = encoder.output() \par
\tab return encoded_bytes \par
\par
params = [] \par
params_dict = \{ 'Qx': 0, 'Qy': 1, 'p': 2, 'a': 3, 'b': 4, 'Px': 5, 'Py': 6, 'q': 7, 'r': 8, 's': 9 \} \par
\par
# Decode asn1 file format \par
def parse_ans1(decoder): \par
\tab while not decoder.eof(): \par
\tab\tab tag = decoder.peek() \par
\tab\tab if tag.nr == asn1.Numbers.Null: \par
\tab\tab\tab break \par
\tab\tab if tag.typ == asn1.Types.Primitive: \par
\tab\tab\tab tag, value = decoder.read() \par
\tab\tab\tab if tag.nr == asn1.Numbers.Integer: \par
\tab\tab\tab\tab params.append(value) \par
\tab\tab else: \par
\tab\tab\tab decoder.enter() \par
\tab\tab\tab parse_ans1(decoder) \par
\tab\tab\tab decoder.leave() \par
\par
# Sign file using El-Gamal \par
def elgamal_ecc_sign(src_file, sign_file): \par
\tab global p, q, curve, point, d, Q \par
\tab p, q, curve, point, d, Q = ProcessParameter() \par
\tab with open(src_file, mode='rb') as file: \par
\tab\tab data = file.read() \par

\pard # First step \par
\tab dgst = sha256(data).digest() # Used sha256, but standard use stribog. \par
\tab with open("hash", mode='wb') as file: \par
\tab\tab data = file.write(dgst) \par
# Second step \par
\tab alfa = int.from_bytes(dgst, byteorder='big') \par
\tab e = alfa % q \par
\tab print('[+] e = ', hex(e)) \par
\tab if e == 0: \par
\tab\tab e = 1 \par
\tab k = 0 \par
\tab r = 0 \par
\tab s = 0 \par
\tab C = Origin \par
\tab while True: \par
\tab\tab # Third step \par
\tab\tab k = rand(q) \par
\tab\tab # Fourth step \par
\tab\tab C = multiply(point, k, curve.a, p) \par
\tab\tab r = C.x % q \par
\tab\tab if r == 0: \par
\tab\tab\tab continue \par
\tab\tab # Fifth step \par
\tab\tab s = (r * d + k * e) % q \par
\tab\tab if s == 0: \par
\tab\tab\tab continue \par
\tab\tab break \par
\tab r_bin = [int(k) for k in bin(r)[2:]] \par
\tab s_bin = [int(k) for k in bin(s)[2:]]\fs24\par

\pard\pagebb\fs20\tab # Sixth step \par
\tab ksi = str(r_bin) + str(s_bin) \par
\tab encoded_bytes = encode_signature(Q, p, curve, point, q, r, s, ksi) \par
\tab with open(sign_file, mode='wb') as file: \par
\tab\tab file.write(encoded_bytes) \par
\tab print('[+] File successfully signed!') \par
\par
# Check file sign using El-Gamal \par
def elgamal_ecc_verify(src_file, sign_file): \par
\tab with open(sign_file, mode='rb') as file: \par
\tab\tab encoded_data = file.read() \par
\par
\tab decoder = asn1.Decoder() \par
\tab decoder.start(encoded_data) \par
\tab parse_ans1(decoder) \par
\tab Qx = params[params_dict['Qx']] \par
\tab Qy = params[params_dict['Qy']] \par
\tab p = params[params_dict['p']] \par
\tab a = params[params_dict['a']] \par
\tab # b = params[params_dict['b']] \par
\tab Px = params[params_dict['Px']] \par
\tab Py = params[params_dict['Py']] \par
\tab q = params[params_dict['q']] \par
\tab r = params[params_dict['r']] \par
\tab s = params[params_dict['s']] \par

\pard\par
# First step \par
\tab r = int(r) \par
\tab s = int(s) \par
\tab\par
\tab print('[+] a = ', hex(a)) \par
\tab print('[+] x = ', hex(Px)) \par
\tab print('[+] y = ', hex(Py)) \par
\tab print('[+] p = ', hex(p)) \par
\tab print('[+] r = ', hex(q)) \par
\tab print('[+] P.x = ', hex(Qx)) \par
\tab print('[+] P.y = ', hex(Qy)) \par
\tab if r <= 0 or r >= q or s <= 0 or s >= q: \par
\tab\tab print('[-] Invalid signature! r <= 0 || r >= q || s <= 0 || s >= q ! ') \par
\tab\par
\tab with open(src_file, mode='rb') as file: \par
\tab\tab data = file.read() \par
# Second step \par
\tab # Used sha256, but standard use stribog \par
\tab dgst = sha256(data).digest() \par
# Third step \par
\tab alfa = int.from_bytes(dgst, byteorder='big') \par
\tab e = alfa % q \par
\tab print('[+] e = ', hex(e)) \par
\tab if e == 0: \par
\tab\tab e = 1 \par
# Fourth step \par
\tab v = invert(e, q) \par
# Fifth step \par
\tab z1 = s * v % q z2 = -r * v % q \par
# Sixth step \par
\tab c1 = multiply(Point(Px, Py), z1, a, p) \par
\tab c2 = multiply(Point(Qx, Qy), z2, a, p)\fs24\par

\pard\pagebb\fs20\tab C = add(c1, c2, a, p) R = C.x % q \par

\pard # Seventh step \par
\tab if R == r: \par
\tab\tab print('[+] Signature is valid!') \par
\tab else: \par
\tab\tab print('[-] Invalid signature!') \par
\par
def main(): \par
\tab if len(sys.argv) < 4: \par
\tab\tab print( "[-] Error! Usage: python <program name> [sign] [verify] <message filename> <sign filename>") \par
\tab if sys.argv[1] == 'sign': \par
\tab\tab elgamal_ecc_sign(sys.argv[2], sys.argv[3]) \par
\tab elif sys.argv[1] == 'verify': \par
\tab\tab elgamal_ecc_verify(sys.argv[2], sys.argv[3]) \par
\tab else: \par
\tab\tab print( "[-] Error! Usage: python <program name> [sign] [verify]' <message filename> <sign filename>") \par
\par
if __name__ == '__main__': \par
\tab main() \f2\fs22\par
}
�
