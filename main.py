__author__ = 'juju'
import hashlib, time, os, random, string, uuid
from secretsharing import SecretSharer

#Available Hash Functions
hs = hashlib
if hasattr(hashlib, 'algorithms_available'):
    hs_funcs = hashlib.algorithms_available
else:
    hs_funcs = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')

def sha1(HASHME):
    return str(hs.sha1(HASHME).hexdigest())
def sha256(HASHME):
    return str(hs.sha256(HASHME).hexdigest())
def md5(HASHME):
    return str(hashlib.md5(HASHME).hexdigest())
def sha224(HASHME):
    return str(hs.sha224(HASHME).hexdigest())
def sha384(HASHME):
    return str(hs.sha384(HASHME).hexdigest())
def sha512(HASHME):
    return str(hs.sha512(HASHME).hexdigest())

def randSeed(TEST):
    return os.urandom(TEST)
def randomword(length):
   return ''.join(random.choice(string.hexdigits) for i in range(length))
def randuuid():
    return str(uuid.uuid4())
#Returns time as Unix timestamp
def gettime():
    ts = int(time.time())
    return ts

def secretsplit(SECRET):
    shares = SecretSharer.split_secret(SECRET, 2, 3)
    shares = secretstripper(shares)
    while len(shares[0]+shares[1]+shares[2]) != 192:
        shares = SecretSharer.split_secret(SECRET, 2, 3)
        shares = secretstripper(shares)
    return shares

def secretrecover(shares):
    return str(SecretSharer.recover_secret(shares))
def secretstripper(shares):
    nushare = []
    for share in shares:
        nushare.append(share[2:])
    return nushare
def sharefixer(shares):
    i=1
    nushares = []
    for share in shares:
        nushares.append(str(i)+'-'+share)
        i+=1
    return nushares
def hashbuff256():
    #Initialize our empty storage
    buffer = ''
    ts_buffer = []
    uuid_buffer = []

    #Add timestamp and random uuid
    uuid_buffer.append(randuuid())
    ts_buffer.append(gettime())
    #Generate random 1024 seed
    seed = randSeed(1024)
    #Hash(Seed)+Hash(uuid_buffer)+Hash(ts_buffer)
    buffer += sha256(seed)
    buffer += sha256(uuid_buffer[0])
    buffer += sha256(str(ts_buffer[0]))

    #Hash(currentbuffer)
    #Last 64 Bytes are Hash of the 192 Byte Buffer
    buffer = buffer + sha256(buffer)
    return str(buffer)

def hashbuff64():
    #Initialize our empty storage
    buffer = ''
    ts_buffer = []
    uuid_buffer = []

    #Add timestamp and random uuid
    uuid_buffer.append(randuuid())
    ts_buffer.append(gettime())
    #Generate random 1024 seed
    seed = randSeed(1024)
    #Hash(Seed)+Hash(uuid_buffer)+Hash(ts_buffer)
    buffer += sha256(seed)
    buffer += sha256(uuid_buffer[0])
    buffer += sha256(str(ts_buffer[0]))

    #Hash(currentbuffer)
    #Last 64 Bytes are Hash of the 192 Byte Buffer
    buffer = buffer + sha256(buffer)
    return str(buffer[:64])

def hashbuff1024():
    block = hashbuff256()
    block += hashbuff256()
    toshuffle = hashbuff256() + hashbuff256()
    shuffled = ''.join(random.sample(toshuffle, len(toshuffle)))
    return str(block+shuffled)

#print 'Buffer: ' + str(hashbuff1024())
#print 'Buffer: ' + str(len(hashbuff1024()))

def sharetest():
    secret = 'c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a'
    print 'Secret: ' + secret
    shares = secretsplit(secret)
    print 'Before Strip: ' + str(shares)
    shares = secretstripper(shares)
    print 'After Strip: ' + str(shares)
    shares = sharefixer(shares)
    print 'Fix Shares: ' + str(shares)
    print str(secretrecover(shares))
    if secret == str(secretrecover(shares)):
        print 'Pass'
    else:
        print 'Fail'

def gencert(FIRSTSECRET,SECONDSECRET,THRIRDSECRET, SHARES):
    if len(SHARES) == 3:
        if(FIRSTSECRET!=SECONDSECRET or FIRSTSECRET!=THRIRDSECRET or SECONDSECRET!=THRIRDSECRET):
            f = open("cert.key", "wb")
            i = 0
            #Write data to file
            while i < 1024:
                if i == FIRSTSECRET:
                    f.write(SHARES[0])
                    #print 'Writing first share'
                    i+=1
                if i == SECONDSECRET:
                    f.write(SHARES[1])
                    #print 'Writing second share'
                    i+=1
                if i == THRIRDSECRET:
                    f.write(SHARES[2])
                    #print 'Writing third share'
                    i+=1
                else:
                    f.write(hashbuff64())
                    i+=1
            f.close()
    return 1

def recoverKey(FIRSTSECRET,SECONDSECRET,THRIRDSECRET):
    f = open("cert.key", "rb")
    i = 0
    shares = []
    #Read data from file
    while i < 1024:
        if i == FIRSTSECRET:
            temp = f.read(64)
            print 'First share: ' + str(temp)
            shares.append(str(temp))
            i+=1
        elif i == SECONDSECRET:
            temp = f.read(64)
            print 'Second share: ' + str(temp)
            shares.append(str(temp))
            i+=1
        elif i == THRIRDSECRET:
            temp = f.read(64)
            print 'Third share: ' + str(temp)
            shares.append(str(temp))
            i+=1
        else:
            i+=1
            f.read(64)
    f.close()
    return shares

def printcert():
    with open("cert.key") as f:
        content = f.readlines()
        print content
    f.close()
    return 1

secret = 'c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a'
print 'Secret: ' + secret
shares = secretsplit(secret)
gencert(19,23,59, shares)
#printcert()
recshares = recoverKey(19,23,59)

if shares == recshares:
    print 'Share Test Passed'
    if secret == secretrecover(sharefixer(shares)):
        print 'Secret Test Passed'
