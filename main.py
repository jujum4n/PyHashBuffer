__author__ = 'juju'
import hashlib, time, os, uuid
from secretsharing import SecretSharer

# Random Data
def randSeed(TEST):
    return os.urandom(TEST)
def randuuid():
    return str(uuid.uuid4())
def gettime():
    ts = int(time.time())
    return ts

# Secret Sharing
def secretsplit(SECRET):
    shares = secretstripper(SecretSharer.split_secret(SECRET, 2, 3))
    while len(shares[0] + shares[1] + shares[2]) != 192:
        shares = secretstripper(SecretSharer.split_secret(SECRET, 2, 3))
    return shares
def secretrecover(shares):
    return str(SecretSharer.recover_secret(shares))
def secretstripper(shares):
    nushare = []
    for share in shares:
        nushare.append(share[2:])
    return nushare
def sharefixer(shares):
    i = 1
    nushares = []
    for share in shares:
        nushares.append(str(i) + '-' + share)
        i += 1
    return nushares

# Hash Buffing
def sha256(HASHME):
    return str(hashlib.sha256(HASHME).hexdigest())
def hashbuff256():
    # Initialize our empty storage
    buffer = ''
    # Hash(Seed)+Hash(uuid_buffer)+Hash(ts_buffer)
    buffer += sha256(randSeed(1024)) + sha256(randuuid()) + sha256(str(gettime()))
    # Last 64 Bytes are Hash of the 192 Byte Buffer
    return str(buffer + sha256(buffer))
def hashbuff64():
    # Returns the last 64 of hashbuff256 which is a sha256(random 1024 seed+random uuid+hash of timestamp)
    return str(hashbuff256()[:64])
def hashbuff1():
    return str(hashbuff64()[:1])

#Tries to rule out invalid input, shift larger than 64 or tries saving secret in same spot
def inpvalidator(FIRSTSECRET, SECONDSECRET, THRIRDSECRET):
    valid = False
    if(FIRSTSECRET[0] != SECONDSECRET[0] or FIRSTSECRET[0] != THRIRDSECRET[0] or SECONDSECRET[0] != THRIRDSECRET[0]):
        if(FIRSTSECRET[1] <= 64 and SECONDSECRET[1] <= 64 and THRIRDSECRET[1] <= 64 ):
            valid = True
    return valid

#Current implementation of gencert, which takes in pairs of integers to give an offset and a shift
def gencert(FIRSTSECRET, SECONDSECRET, THRIRDSECRET, SHARES):
    if len(SHARES) == 3:
        if inpvalidator(FIRSTSECRET,SECONDSECRET,THRIRDSECRET) == True:
            f = open("cert.key", "wb")
            i = 0
            # Write data to file
            while i < 16384:
                if i == FIRSTSECRET[0]:
                    shifted = 0
                    while shifted < FIRSTSECRET[1]:
                        f.write(hashbuff1())
                        shifted += 1
                    f.write(SHARES[0])
                    shifted = 0
                    while shifted < (64 - FIRSTSECRET[1]):
                        f.write(hashbuff1())
                        shifted += 1
                    i += 2
                if i == SECONDSECRET[0]:
                    shifted = 0
                    while shifted < SECONDSECRET[1]:
                        f.write(hashbuff1())
                        shifted += 1
                    f.write(SHARES[1])
                    shifted = 0
                    while shifted < (64 - SECONDSECRET[1]):
                        f.write(hashbuff1())
                        shifted += 1
                    i += 2
                if i == THRIRDSECRET[0]:
                    shifted = 0
                    while shifted < THRIRDSECRET[1]:
                        f.write(hashbuff1())
                        shifted += 1
                    f.write(SHARES[2])
                    shifted = 0
                    while shifted < (64 - THRIRDSECRET[1]):
                        f.write(hashbuff1())
                        shifted += 1
                    i += 2
                else:
                    f.write(hashbuff64())
                    i += 1
            f.close()
    return 1

def recoverKey(FIRSTSECRET, SECONDSECRET, THRIRDSECRET):
    f = open("cert.key", "rb")
    i = 0
    shares = ['', '', '']
    while i < 16384:
        if i == FIRSTSECRET[0]:
            shifted = 0
            while shifted < FIRSTSECRET[1]:
                shifted += 1
                f.read(1)
            shares[0] = f.read(64)
            shifted = 0
            while shifted < (64 - FIRSTSECRET[1]):
                shifted += 1
                f.read(1)
            i += 2
        if i == SECONDSECRET[0]:
            shifted = 0
            while shifted < SECONDSECRET[1]:
                shifted += 1
                f.read(1)
            shares[1] = f.read(64)
            shifted = 0
            while shifted < (64 - SECONDSECRET[1]):
                shifted += 1
                f.read(1)
            i += 2
        if i == THRIRDSECRET[0]:
            shifted = 0
            while shifted < THRIRDSECRET[1]:
                shifted += 1
                f.read(1)
            shares[2] = f.read(64)
            shifted = 0
            while shifted < (64 - THRIRDSECRET[1]):
                shifted += 1
                f.read(1)
            i += 2
        else:
            i += 1
            f.read(64)
    f.close()
    return shares

#Tests most everything to veriify things are not breaking quickly
def testall(secret,FIRSTSECRET,SECONDSECRET,THIRDSECRET):
    print 'Running Strong Tests:'
    if os.path.isfile('cert.key'):
        os.remove('cert.key')
    totalpassed = 0
    totalfailed = 0
    shares = secretsplit(secret)
    gencert(FIRSTSECRET, SECONDSECRET, THIRDSECRET, shares)
    recovered_shares = recoverKey(FIRSTSECRET, SECONDSECRET, THIRDSECRET)
    if os.path.isfile('cert.key'):
        if shares == recovered_shares:
            print 'Share Test Passed'
            totalpassed += 1
            if secret == secretrecover(sharefixer(shares)):
                print 'Secret Test Passed'
                totalpassed += 1
            else:
                totalfailed += 1
                print 'Secret Test Failed'
        else:
            print 'Share Test Failed'
            totalfailed += 1
        if os.path.getsize('cert.key') == 1048576:
            print 'Key Test Passed'
            totalpassed += 1
        else:
            totalfailed += 1
            print 'Key Test Failed'
        print 'Total Passed: ' + str(totalpassed) + '/' + str(totalfailed + totalpassed)

def calc():
    firstchunkpool = 16384
    secondchunkpool = 16382
    thirdchunkpool = 16380
    shifts = 64
    poss = (firstchunkpool * shifts)
    poss = poss * (secondchunkpool * shifts)
    poss = poss * (thirdchunkpool * shifts)
    return poss

FIRSTSECRET = [10, 12]
SECONDSECRET = [1322, 42]
THIRDSECRET = [15123, 61]
testall('c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a', FIRSTSECRET, SECONDSECRET, THIRDSECRET)
current_probability = str(calc())
print 'Probability: 1/' + current_probability
