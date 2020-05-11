#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import my_rsa as rsa
import hashlib

def get_str_sha1_secret_str(res):
    """
    使用sha1加密算法，返回bytes加密后的hex字符串
    """
    sha = hashlib.sha1(res)
    encrypts = sha.hexdigest()
    return encrypts

def encode(n,e,m,l=b''):
# m : bytes ; n,e : numbers
    n_hex = hex(n)[2:]
    if len(n_hex)&1 == 1:
        n_hex = '0' + n_hex
    #m:bytes
    mm = oeap_encode(n,e,m,l)
    c = rsa.encode(n,e,int(mm,16))
    k = (len(bytes.fromhex(n_hex))+1)//2
    return "%0*x" %(k*2,c)

def decode(k,k_flag,c,l=b''):
    if k_flag == 1:
        n = k[0] * k[1]
    else:
        n = k[0]
    n_hex = hex(n)[2:]
    if len(n_hex)&1 == 1:
        n_hex = '0' + n_hex

    k = (len(bytes.fromhex(n_hex))+1)//2
    hLen = 20
    if len(c)!= k or (k<2*hLen +2 ):
        return 'Wrong c!\n'
    cc = c.hex()
    if k_flag:
        em = rsa.decode2(k[0], k[1], k[2], k[3], k[4],int(cc,16))
    else:
        em = rsa.decode1(k[0], k[1], int(cc,16))
    EM = bytearray.fromhex('%0*x' %(k*2,em))
    return bytearray.fromhex(oeap_decode(EM,k,hLen,l))

def oeap_encode(n,e,m,l=b''):
    n_hex = hex(n)[2:]
    if len(n_hex)&1 == 1:
        n_hex = '0' + n_hex
    k = (len(bytes.fromhex(n_hex))+1)//2
    hLen = 20
    mLen = len(m)
    if mLen>(k-2-2*hLen):
        return 'Too long message!\n'
    
    lhash = get_str_sha1_secret_str(l)
    if (k - mLen - 2*hLen - 2)>0:
        ps = '00' * (k - mLen - 2*hLen - 2) + '01'
    else:
        ps = '01'
    DB = lhash + ps + m.hex()
    seed = g_seed(hLen)
    dbMask = MGF(seed,k - hLen -1,hLen)
    maskedDB = hex_xor(dbMask,DB,(k-hLen-1)*2) 
    seedMask = MGF (maskedDB, hLen,hLen)
    maskedSeed = hex_xor(seed ,seedMask ,hLen*2)
    EM = '00' + maskedSeed + maskedDB
    return EM

def oeap_decode(EM,k,hLen,l=b''):
    lhash = get_str_sha1_secret_str(l)
    Y = lhash[:2]
    if Y!='00':
        return 'Wrong Y!\n'
    maskedSeed = lhash[:2+2*hLen]
    maskedDB = lhash[2+2*hLen:]
    seedMask = MGF(maskedDB,hLen,hLen)
    seed = hex_xor(seedMask, maskedSeed, 2*hLen)
    dbMask = MGF(seed,k - hLen - 1,hLen)
    DB = hex_xor(dbMask, maskedDB, (k - hLen - 1)*2)
    index = 2*hLen
    llhash = DB[:index]
    if lhash!=llhash:
        return 'Wrong hash!\n'
    while DB[index:index+2] == '00':
        index+=2
    if DB[index:index+2] !='01':
        return 'Wrong PS!\n'
    index = index+2
    m = DB[index:]
    return m

def MGF(x,maskLen,hLen):
    T=bytearray(b'')
    k = maskLen // hLen
    if len(x)&1 == 1:
        x= '0'+x
    X = bytearray.fromhex(x)
    if maskLen%hLen == 0:
        k -= 1
    for i in range(k+1):
        tmp = X + bytearray.fromhex('%08x'%i)
        T = T + bytearray.fromhex(get_str_sha1_secret_str(tmp))
    mask = T[:maskLen*2]
    return mask.hex()


def g_seed(hLen):
    b = bytearray(hLen)
    for i in range(hLen):
        b[i] = random.randint(0,255)
    return b.hex()

def hex_xor(a,b,l):
    return "%0*x" %(l,int(a,16)^int(b,16))

if __name__ == '__main__':
    e = 65537
    n = 21378032245774894186324720788457768851857953294637267751313371903474996018902810092972224806315945430514626988743400353365786674788848003569698586194388463460699531620948408197942261177369324808332585418351947368544183614904162658914539989430070735676083960582943505227316151479174351490943931346982185481068889458087344890907035731467000101100009111593455801160870652558847164438348031498067369123608755518383163346962891967964682970251625764813457371461595048927486942272152822570449609158417324070867001419543608370026546341531367233199832189762919523227554947408242727690461831545997600374969434706782376320559561
    m = bytes.fromhex("666c61677b7273615f6f3465705f69735f74337272696231657d")
    c = encode(n, e, m)
    d = 13085102850405329895940153649208766646679432053055210927814587187939575969334380946175257120108607885616731724467899991987963542311668962802613624160423864736904359544115910805381019345850330276964971412664144174157825068713331109139842487999112829255389047329358923488846912437792391102853729375052922599258215311601018992134762683570752403675370812499995354701024990414541327012769030147878934713424171374951602988478984432403148854042370903764361797455965930292322795814453835335323397068237664481359506461188857661605832041501219728374514303209642746672993156029099655958158717907546664548938973389857200804582177
    mm = decode((n,d),0, c)
    print(c)
    print()
    print(m)
