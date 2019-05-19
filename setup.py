#!/usr/bin/env python3

import os, sys
import json
import ecdsa
import cashaddr
from bitcoin import hash160, SimpleTx
from ecc import ser_to_point, point_to_ser, G, order, fieldsize, INFINITY

G = ecdsa.SECP256k1.generator

prefix="bitcoincash"

class ProtoProblem(Exception):
    pass

def setup():
    myprivate = ecdsa.util.randrange(order)
    privkeyhex = myprivate.to_bytes(32,'big').hex()
    mypubpoint = myprivate*G
    mypubkey = point_to_ser(mypubpoint)

    mypubkeyhash = hash160(mypubkey)

    print("==Setup phase 1==")
    print("Share your pubkey hash:::\n  ", mypubkeyhash.hex())
    response = input("Enter pubkey hashes of other players, separated by spaces:\n")

    try:
        otherhashes = [bytes.fromhex(hhex.strip()) for hhex in response.split()]
    except:
        raise ProtoProblem("Could not convert from hex.")

    for h in otherhashes:
        if len(h) != 20:
            raise ProtoProblem("Incorrect length", h.hex())
        if h == mypubkeyhash:
            raise ProtoProblem("One of the others' hashes is same as yours.")

    print("Total players: ", len(otherhashes) + 1)

    print()
    print("==Setup phase 2==")
    print("Share your pubkey:::\n  ", mypubkey.hex())
    while True:
        response = input("Enter pubkeys of other players, separated by spaces:\n")
        try:
            otherpubkeys = [bytes.fromhex(phex.strip()) for phex in response.split()]
        except:
            raise ProtoProblem("Could not convert from hex.")

        if len(otherpubkeys) == len(otherhashes):
            break
        print("Incorrect number of pubkeys")

    # will have all keys added in to aggpoint
    aggpoint = mypubpoint

    for pub in otherpubkeys:
        h = hash160(pub)

        try:
            otherhashes.remove(h)
        except ValueError:
            raise ProtoProblem("Unannounced pubkey: ", pub.hex())

        try:
            P = ser_to_point(pub)
        except Exception as e:
            raise
            raise ProtoProblem("Bad pubkey: ", pub.hex())

        aggpoint = aggpoint + P

    assert len(otherhashes) == 0
    assert aggpoint != INFINITY, "agg pubkey at infinity, should never happen!"

    aggpub = point_to_ser(aggpoint)
    aggpubhash = hash160(aggpub)
    aggaddress = cashaddr.encode_full(prefix, cashaddr.PUBKEY_TYPE, aggpubhash)

    print()
    print("==Setup results==")
    print("Aggregate pubkey: ", aggpub.hex())
    print("Aggregate address:", aggaddress)
    print("Please confirm the above address with each other, before continuing.")
    response = input("Add a note to self (optional): ")

    return dict(
        privatekey = privkeyhex,
        otherpubkeys = [pub.hex() for pub in otherpubkeys],
        # this is stored just to double check.
        aggaddress = aggaddress,
        note = response,
        )

if __name__ == "__main__":
    print("""\
********************
Schnorr multisigger!
********************
Warning: this is for DEMONSTRATION and does not necessarily use safe/secure
techniques. Beware, funds can be easily lost!
""")
    if len(sys.argv)>1 and sys.argv[1]:
        datafilename = sys.argv[1]
    else:
        datafilename="mysigningdata.json"
    try:
        if not os.path.exists(datafilename):
            setupdata = setup()
            with open(datafilename, 'w') as f:
                json.dump(setupdata, f, indent=2)
            print()
            print("Wrote setup data to %s."%(datafilename))
            print("Back it up and keep it private if you care about the funds involved.")
        else:
            print("Setup data exists already in %s. Rename first (or delete if not needed)."%(datafilename))
    except ProtoProblem as e:
        print("Aborting from protocol problem: ", e.args)
