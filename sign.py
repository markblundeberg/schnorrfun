#!/usr/bin/env python3

import os, sys
import json
import ecdsa
import base64

import cashaddr
import schnorr
from bitcoin import hash160, sha256, SimpleTx, minpush
from ecc import ser_to_point, point_to_ser, G, order, fieldsize, INFINITY, jacobi

prefix="bitcoincash"

class ProtoProblem(Exception):
    pass

def signtx(setupdata):
    myprivbytes = bytes.fromhex(setupdata['privatekey'])
    myprivkey = int.from_bytes(myprivbytes,'big')
    mypubpoint = myprivkey * G
    mypubkey = point_to_ser(mypubpoint)
    otherpubkeys = [bytes.fromhex(x) for x in setupdata['otherpubkeys']]
    otherpubpoints = {k:ser_to_point(k) for k in otherpubkeys}
    aggpub = sum(otherpubpoints.values(), mypubpoint)
    aggpubser = point_to_ser(aggpub, comp=True)

    note = setupdata['note']
    print('Data note: %r'%(note))

    addprefix,kind,pubkeyhash = cashaddr.decode(setupdata['aggaddress'])
    assert addprefix == prefix
    assert kind == cashaddr.PUBKEY_TYPE
    assert hash160(point_to_ser(aggpub)) == pubkeyhash

    # Get the tx to sign

    txhex = input("Enter raw transaction hex:\n")
    try:
        tx = SimpleTx.from_bytes(bytes.fromhex(txhex))
    except Exception as e:
        print("Could not parse transaction:", repr(e))
        return
    if len(tx.inputs) == 1:
        inputnum = 0
    else:
        while True:
            response = input("Which input to sign (0 to %d inclusive)? "%(len(tx.inputs)-1))
            inputnum = int(response)
            if 0 <= inputnum < len(tx.inputs):
                break
    inp = tx.inputs[inputnum]
    print("Signing %s:%d"%(inp['prevout_hash'].hex(), inputnum))
    response = input("Enter the value (in satoshis) of this input: ")
    sats = int(response)
    if sats < 0:
        print("Bad value")
        return
    inp['prevout_value'] = sats

    scriptcode = b'\x76\xa9\x14' + pubkeyhash + b'\x88\xac'
    nhashtype = 0x41
    digest = tx.digestInput(inputnum, nhashtype, scriptcode)

    print("Signing digest:", digest.hex())

    # Initiate the collaborative signing process!

    myk = ecdsa.util.randrange(order)
    myRpoint = myk * G
    myRser = point_to_ser(myRpoint)
    myRhash = hash160(myRser)

    promiseprefix = b"Promise for Mark's Schnorr aggregator demo:"

    mymessage = mypubkey + digest + myRhash  # 85 bytes
    mysig = schnorr.sign(myprivbytes, sha256(promiseprefix+mymessage))
    mypromise = mymessage + mysig  # 149 bytes

    print()
    print("==Sign phase 1==")
    print("Share your promise:\n" + base64.urlsafe_b64encode(mypromise).decode('ascii'))
    print("Enter promises of other players, one per line:")

    # We will build map of Rhash -> pubkey
    Rhashmap = dict()

    remainingpubs = list(otherpubkeys)
    while remainingpubs:
        response = input()
        try:
            data = base64.urlsafe_b64decode(response.encode('ascii'))
        except:
            print("Bad input.")
            continue
        if len(data) != 149:
            print("Wrong length.")
            continue
        inppub = data[:33]
        inpdigest = data[33:65]
        inpRhash = data[65:85]
        inpsig = data[85:149]
        if inppub not in remainingpubs:
            print("ERROR: Pubkey not expected or already promised:", inppub.hex())
            continue
        if not schnorr.verify(inppub, inpsig, sha256(promiseprefix+inppub+inpdigest+inpRhash)):
            print("ERROR: Promise is incorrectly signed!")
            continue
        if inpdigest != digest:
            print("ERROR: Disagreement over digest! Trying to sign different txns?")
            continue
        if inpRhash in Rhashmap:
            print("ERROR: This hash already promised by %s!"%(Rhashmap[inpRhash].hex()))
            continue
        remainingpubs.remove(inppub)
        Rhashmap[inpRhash] = inppub
        print("Promise received from %s: %s"%(inppub.hex(), inpRhash.hex()))

    print("Promises complete.")

    print()
    print("==Sign phase 2==")
    print("Share your R:\n", myRser.hex())
    print("Enter R of other players, one per line:")

    # now we want to associate
    pubtoRmap = dict()
    while Rhashmap:
        response = input("(%d remaining) "%(len(Rhashmap)))
        try:
            inpRbytes = bytes.fromhex(response)
        except:
            print("ERROR: bad R")
            continue
        inpRhash = hash160(inpRbytes)
        try:
            pub = Rhashmap.pop(inpRhash)
        except:
            print("ERROR: wrong point or already seen")
            continue
        try:
            inpR = ser_to_point(inpRbytes)
        except:
            raise ProtoProblem("Bad point value, need restart.")
        pubtoRmap[pub] = inpR

    R = sum(pubtoRmap.values(), myRpoint)

    if R == INFINITY:
        raise ProtoProblem("Infinite R, try again :-(")

    # if R has the wrong sign, we will multiply all k values.
    sign = jacobi(R.y(), fieldsize)

    print("Combined point (%+d): %s"%(sign, point_to_ser(R).hex()))

    rbytes = R.x().to_bytes(32,'big')
    ebytes = sha256(rbytes + aggpubser + digest)
    e = int.from_bytes(ebytes, 'big')

    mys = (sign*myk + e*myprivkey) % order

    print()
    print("==Sign phase 3==")
    print("Share your key:s :\n", mypubkey.hex()+":"+hex(mys))
    print("Enter key:s of other players, one per line:")

    ssum = mys

    while pubtoRmap:
        response = input("(%d remaining) "%(len(pubtoRmap)))
        try:
            inppub, inps = response.strip().split(':')
            inppub = bytes.fromhex(inppub)
            inps = int(inps.strip(), 16)
        except:
            print("ERROR: expecting `pubkey:hexadecimal`")
            continue
        # We now verify the gotten s value.
        verR = pubtoRmap.get(inppub)
        if verR is None:
            print("ERROR: unrecognized or already used pubkey")
            continue
        verpubpoint = otherpubpoints[inppub]
        if inps*G != sign*verR + e*verpubpoint:
            print("ERROR: incorrect s!")
            continue
        del pubtoRmap[inppub]
        ssum += inps
    ssum = ssum % order

    print()
    print("==Results==")
    schnorrsig = rbytes + ssum.to_bytes(32,'big') + bytes([nhashtype])
    print("Transaction Schnorr signature:\n"+schnorrsig.hex())

    tx.inputs[inputnum]['scriptsig'] = (
            minpush(schnorrsig) +
            minpush(aggpubser)
            )
    print("Transaction result:")
    print(tx.to_bytes().hex())


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
        print("Defaulting to load %s"%(datafilename))

    try:
        if not os.path.exists(datafilename):
            print("File not found: %s"%(datafilename))
            print("Usage: %s [file.json]"%(sys.argv[0]))
            sys.exit(1)
        with open(datafilename, 'r') as f:
            setupdata = json.load(f)
        signtx(setupdata)

    except ProtoProblem as e:
        print("Aborting from protocol problem: ", e.args)
