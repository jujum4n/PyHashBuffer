__author__ = 'juju'
import hashlib, time, os, random, string, uuid
from secretsharing import SecretSharer

#Hash Functions
def sha256(HASHME):
    return str(hashlib.sha256(HASHME).hexdigest())

#Random Data
def randSeed(TEST):
    return os.urandom(TEST)
def randomword(length):
   return ''.join(random.choice(string.hexdigits) for i in range(length))
def randuuid():
    return str(uuid.uuid4())
def gettime():
    ts = int(time.time())
    return ts

#Secret Sharing
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

#Hash Buffers
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

def sharetest(secret):
    print 'Secret: ' + secret
    shares = secretsplit(secret)
    gencert(19,23,59, shares)
    recshares = recoverKey(19,23,59)
    if shares == recshares:
        print 'Share Test Passed'
        if secret == secretrecover(sharefixer(shares)):
            print 'Secret Test Passed'

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

def printkey():
    with open("cert.key") as f:
        content = f.readlines()
        print content
    f.close()
    return 1

secret = 'c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a'
sharetest(secret)
