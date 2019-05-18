"""
Misc stuff for elliptic curve crypto
"""

import ecdsa
from ecdsa.ellipticcurve import Point, INFINITY
from ecdsa.numbertheory import jacobi

G = ecdsa.SECP256k1.generator
order = G.order()
fieldsize = ecdsa.SECP256k1.curve.p()

def point_to_ser(P, comp = True):
    """ Convert Point to serialized format """
    #WEAKNESS - to_bytes not constant time (this is used in ECDH)
    if P == INFINITY:
        return b'\x00'
    if comp:
        return bytes((2 + (P.y()&1),)) + P.x().to_bytes(32, 'big')
    else:
        return b'\x04' + P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')

def ser_to_point(Aser, allow_infinity=False):
    """Convert secp256k1 serialized point (compressed or uncompressed) to a
    Point object.

    Ensures point coordinate are in field, and that point is on curve.

    See "Octet-String-to-Elliptic-Curve-Point Conversion"
    http://www.secg.org/sec1-v2.pdf#page=17
    """
    #WEAKNESS (kinda) -- generally don't care since input is public
    p = fieldsize
    n = order
    if Aser == b'\x00':
        # point at infinity
        assert allow_infinity
        return INFINITY
    elif len(Aser) == 33:
        # compressed point
        firstbyte = Aser[0]
        assert firstbyte in (2,3)

        x = int.from_bytes(Aser[1:], 'big')
        assert x < p

        # reconstruct square of y coordinate
        y2 = (x*x*x + 7) % p
        # attempt to get square root of y2 using trick for p%4==3
        y  = pow(y2, (p+1)>>2, p)
        # for quadratic non-residue the result is nonsense, so check its square
        # actually not necessary since the Point constructor checks if it's on curve.
        #assert pow(y, 2, p) == y2

        # flip y if needed to match the encoded parity
        if firstbyte-2 != y&1:
            y = p - y
    elif len(Aser) == 65:
        # uncompressed point
        assert Aser[0] == 0x04
        x = int.from_bytes(Aser[1:33], 'big')
        assert x < p
        y = int.from_bytes(Aser[33:], 'big')
        assert y < p

        # Not necessary since the Point constructor checks if it's on curve.
        # assert ecdsa.ecdsa.point_is_valid(SECP256k1.generator, x, y)
    else:
        raise AssertionError("cannot decode point")

    return Point(ecdsa.SECP256k1.curve, x, y, n)
