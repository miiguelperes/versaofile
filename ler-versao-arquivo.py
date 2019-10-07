import pefile
import sys
import json
import functools
import hashlib


def LOWORD(dword):
    return str(dword & 0x0000ffff)


def HIWORD(dword):
    return str(dword >> 16)


def main():
    from pefile import PE
    pename = sys.argv[1]

    pe = PE(pename)

    ms = pe.VS_FIXEDFILEINFO[0].FileVersionMS

    ls = pe.VS_FIXEDFILEINFO[0].FileVersionLS

    verinfo = HIWORD(ms)+"_"+LOWORD(ms)+"_"+HIWORD(ls)+"_"+LOWORD(ls)

    md5_hash = hashlib.md5()
    
    with open(pename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)

    result = {
        "versao": verinfo,
        "md5": md5_hash.hexdigest()
    }
    json_mylist = json.dumps(result, separators=(',', ':'))
    
    if json_mylist:
        print(json_mylist)
        sys.exit(0)
    else:
        sys.exit(0)

    sys.exit(0)


main()
