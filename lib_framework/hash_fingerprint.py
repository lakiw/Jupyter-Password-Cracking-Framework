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
        'type':"unknown",
        'cost':None
    }

    # Uggg, bcrypt
    if raw_hash.startswith("$2a$"):
        hash_info['jtr_mode'] = "bcrypt"
        hash_info['hc_mode'] = "3200"
        hash_info['type'] = "bcrypt"
        hash_info['cost'] = "high"
    
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
    # I don't know if JtR supports this
    # Need to capitalize the ssha512 for HC
    elif raw_hash.startswith("{ssha512}"):
        hash_info['jtr_mode'] = None
        hash_info['hc_mode'] = "1711"
        hash_info['hc_hash'] = raw_hash.replace("{ssha512}","{SSHA512}")
        hash_info['type'] = "ssha512"
        hash_info['cost'] = "medium"

    # LDAP SSHA1
    # I don't know if JtR supports this
    elif raw_hash.startswith("{SSHA}"):
        hash_info['jtr_mode'] = None
        hash_info['hc_mode'] = "111"
        hash_info['type'] = "ssha"
        hash_info['cost'] = "medium"

    # LDAP SSHA1
    # I don't know if JtR supports this
    elif raw_hash.startswith("{SSHA}"):
        hash_info['jtr_mode'] = None
        hash_info['hc_mode'] = "111"
        hash_info['type'] = "ssha512"
        hash_info['cost'] = "medium"

    # Potentially raw_sha256
    elif len(raw_hash) in length_helper:
        hash_info = _get_hash_info(length_helper[len(raw_hash)], raw_hash)

    return hash_info


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

    if type.lower() == "raw-md5":
        hash_info = {
            'jtr_mode':"raw-MD5",
            'jtr_hash':f"$dynamic_0${raw_hash}",
            'hc_mode':"0",
            'hc_hash': raw_hash,
            'type':"raw-md5",
            'cost':"low"
        }
    elif type.lower() == "raw-sha1":
        hash_info = {
            'jtr_mode':"raw-SHA1",
            'jtr_hash':f"$dynamic_26${raw_hash}",
            'hc_mode':"100",
            'hc_hash': raw_hash,
            'type':"raw-sha1",
            'cost':"low"
        }
    elif type.lower() == "raw-sha256":
        hash_info = {
            'jtr_mode':"raw-SHA256",
            'jtr_hash':f"$SHA256${raw_hash}",
            'hc_mode':"1400",
            'hc_hash': raw_hash,
            'type':"raw-sha256",
            'cost':"low"
        }
    
    return hash_info

    
    


