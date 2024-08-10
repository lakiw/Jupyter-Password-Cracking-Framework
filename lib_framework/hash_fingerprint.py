"""
Used to identify hash types

Really I should make use of hashcat/jtr functions, but
might as well re-invent the wheel in python
"""


def hash_fingerprint(raw_hash, length_helper={}):
    """
    Used to identify a hash by type and return JtR and Hashcat modes

    This is a work in progress. I'll add to it as needed

    Inputs:
        raw_hash: (String) The raw hash to identify

        length_helper: (Dict) A length indexed dictionary with
        the value to return if the length matches. Used to deconflict
        all the 32 byte long hashes like raw-md5, raw-md4, NT, etc. Has
        the following format:
        {
            32:"raw-md5"
        }
    """
    
    hash_info = {
        'jtr_mode':None,
        'jtr_hash':raw_hash,
        'hc_mode':None,
        'hc_hash': raw_hash,
        'type':None,
        'cost':None
    }

    # Uggg, bcrypt
    if raw_hash.startswith("$2a$"):
        hash_info['jtr_mode'] = "bcrypt"
        hash_info['hc_mode'] = "3200"
        hash_info['type'] = "bcrypt"
        hash_info['cost'] = "high"

    if raw_hash.startswith("$2k$"):
        hash_info['jtr_mode'] = "unknown"
        hash_info['hc_mode'] = "unknown"
        hash_info['type'] = "bkr256"
        hash_info['cost'] = "high"

    if raw_hash.startswith("$2b$"):
        hash_info['jtr_mode'] = "bcrypt"
        hash_info['hc_mode'] = "3200"
        hash_info['type'] = "bcr256"
        hash_info['cost'] = "high"

    if raw_hash.startswith("v1;PPH1_MD4"):
        hash_info['jtr_mode'] = "unknown"
        hash_info['hc_mode'] = "unknown"
        hash_info['type'] = "adsync"
        hash_info['cost'] = "high"
    
    if raw_hash.startswith("$radmin3$"):
        hash_info['jtr_mode'] = "unknown"
        hash_info['hc_mode'] = "29200"
        hash_info['type'] = "radmin3"
        hash_info['cost'] = "medium"

    if raw_hash.startswith("{x-isSHA512, 15000}"):
        hash_info['jtr_mode'] = "unknown"
        hash_info['hc_mode'] = "unknown"
        hash_info['type'] = "saph512"
        hash_info['cost'] = "high"
    
    elif raw_hash.startswith("$shiro2$"):
        hash_info['jtr_mode'] = "unknown"
        hash_info['hc_mode'] = "unknown"
        hash_info['type'] = "shiro2"
        hash_info['cost'] = "high"

    elif raw_hash.startswith("$sm3$"):
        hash_info['jtr_mode'] = "unknown"
        hash_info['hc_mode'] = "unknown"
        hash_info['type'] = "sm3crypt"
        hash_info['cost'] = "high"

    elif raw_hash.startswith("$RC2$"):
        hash_info['jtr_mode'] = "unknown"
        hash_info['hc_mode'] = "unknown"
        hash_info['type'] = "rc2"
        hash_info['cost'] = "medium"

    elif raw_hash.startswith("$NT$"):
        hash_info['jtr_mode'] = "NT"
        hash_info['hc_mode'] = "1000"
        hash_info['type'] = "nt"
        hash_info['cost'] = "low"

    elif raw_hash.startswith("$5$"):
        hash_info['jtr_mode'] = "sha256crypt"
        hash_info['hc_mode'] = "7400"
        hash_info['type'] = "sha256crypt"
        hash_info['cost'] = "high"
    
    elif raw_hash.startswith("$sha1$"):
        hash_info['jtr_mode'] = "sha1crypt"
        hash_info['hc_mode'] = "15100"
        hash_info['type'] = "sha1crypt"
        hash_info['cost'] = "high"

    elif raw_hash.startswith("$1$"):
        hash_info['jtr_mode'] = "md5crypt"
        hash_info['hc_mode'] = "500"
        hash_info['type'] = "md5crypt"
        hash_info['cost'] = "high"

    # LDAP SSHA512 (there are other salting modes)
    elif raw_hash.startswith("{ssha512}"):
        hash_info['jtr_mode'] = "SSHA512"
        hash_info['hc_mode'] = "1711"
        hash_info['type'] = "ssha512"
        hash_info['cost'] = "medium"

    # LDAP SSHA1
    elif raw_hash.startswith("{SSHA}"):
        hash_info['jtr_mode'] = "Salted-SHA1"
        hash_info['hc_mode'] = "111"
        hash_info['type'] = "nsldaps"
        hash_info['cost'] = "medium"

    # mysql CRAM hashes    
    elif raw_hash.startswith("$mysqlna$"):
        hash_info['jtr_mode'] = "Salted-SHA1"
        hash_info['hc_mode'] = "11200"
        hash_info['type'] = "mysqlna"
        hash_info['cost'] = "low"

    # mssql05 hashes    
    elif raw_hash.startswith("0x0100"):
        hash_info['jtr_mode'] = "mssql05"
        hash_info['hc_mode'] = "132"
        hash_info['type'] = "mssql05"
        hash_info['cost'] = "low"
    
    # Zip hash
    elif "$pkzip$1*1*2*0" in raw_hash:
        hash_info['jtr_mode'] = "pkzip"
        # HC has multiple possible modes. Just picking what seems to work
        # for KoreLogic contests
        hash_info['hc_mode'] = "17200"
        hash_info['type'] = "pkzip"
        hash_info['cost'] = "low"

    # Potentially raw_sha256
    elif len(raw_hash) in length_helper:
        hash_info_lookup = _get_hash_info(length_helper[len(raw_hash)], raw_hash)
        if hash_info_lookup:
            hash_info = hash_info_lookup

    return hash_info


def get_len_for_type(type):
    """
    Returns the length of common hash types

    Inputs:
        type: (String) The Hashing algorithm

    Returns:
        length: (int) The length of the hash
        None, if not specified
    """
    if type.lower() == "half-md5":
        return 16
    elif type.lower() == "raw-md4":
        return 32
    elif type.lower() == "striphash33":
        return 33
    elif type.lower() == "striphash34":
        return 34
    elif type.lower() == "striphash35":
        return 35
    elif type.lower() == "striphash36":
        return 36
    elif type.lower() == "striphash37":
        return 37
    elif type.lower() == "striphash38":
        return 38
    elif type.lower() == "striphash39":
        return 39     
    elif type.lower() == "raw-md5":
        return 32
    elif type.lower() == "raw-sha1":
        return 40
    elif type.lower() == "raw-sha256":
        return 64
    elif type.lower() == "raw-sha384":
        return 96

    return None


def _get_hash_info(type, raw_hash):
    """
    Returns all the other fixups for common hash types that have the
    same length. E.g. raw-md5, raw-md4, etc

    Inputs:
        type: (String) The hashing algorithm

        raw_hash: (String) The raw hash to identify
    
    Returns:
        hash_info: (Dict) A dictionary containing info about the hash

        None: If a problem occured
    """ 

    hash_info = None
    if type.lower() == "half-md5":
        hash_info = {
            'jtr_mode':None,
            'jtr_hash':None,
            'hc_mode':"5100",
            'type':"half-md5",
            'cost':"low"
        }
    elif type.lower() == "striphash33":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"striphash33",
            'cost':"low"
        }
    elif type.lower() == "striphash34":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"striphash34",
            'cost':"low"
        }
    elif type.lower() == "striphash35":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"striphash35",
            'cost':"low"
        }
    elif type.lower() == "striphash36":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"striphash36",
            'cost':"low"
        }
    elif type.lower() == "striphash37":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"striphash37",
            'cost':"low"
        }
    elif type.lower() == "striphash38":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"striphash38",
            'cost':"low"
        }
    elif type.lower() == "striphash39":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"striphash39",
            'cost':"low"
        }
    elif type.lower() == "raw-md5":
        hash_info = {
            'jtr_mode':"raw-MD5",
            'jtr_hash':f"$dynamic_0${raw_hash}",
            'hc_mode':"0",
            'type':"raw-md5",
            'cost':"low"
        }
    elif type.lower() == "raw-sha1":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'type':"raw-sha1",
            'cost':"low"
        }
    elif type.lower() == "raw-sha256":
        hash_info = {
            'jtr_mode':"raw-SHA256",
            'jtr_hash':f"$SHA256${raw_hash}",
            'hc_mode':"1400",
            'type':"raw-sha256",
            'cost':"low"
        }
    elif type.lower() == "raw-sha384":
        hash_info = {
            'jtr_mode':"raw-SHA384",
            'jtr_hash':f"$SHA384${raw_hash}",
            'hc_mode':"10800",
            'type':"raw-sha384",
            'cost':"low"
        }
    
    return hash_info

    
    


