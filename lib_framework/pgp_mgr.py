"""
Responsible for managing PGP submissions and team communication

Basically trying to figure out PGP is a significant challenge for
many of the street teams, so this is a class to help make that
more accessible.

Using PGPy. Many examples copied from: https://pgpy.readthedocs.io/en/latest/examples.html
"""


import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import os
import warnings 


def generate_read_pgp_private_key(filename, email_address, team_name="JupyterLabFramework"):
    """
    A multi-use function that I created to generate/save a
    PGP private key to a file. If the file exists it will NOT
    overwrite it.

    Inputs:
        filename: (String) The full filename + path to save the PGP
        private key to

        email_address: (String) The e-mail address to associate
        with the PGP private key

        team_name: (String) The name of the team/(or user) for the key

    Returns:
        private_key: (String) The private key, either read from a
        file or generated when this is run
    """

    # Try to read in an existing key
    try:
        with open(filename) as key_file:
            key_blob= key_file.read()
            key, _ = pgpy.PGPKey.from_blob(key_blob)
            private_key = str(key)
    
    # The keyfile does not exist
    except FileNotFoundError:
        # we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

        # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
        uid = pgpy.PGPUID.new(team_name, email=email_address)

        # now we must add the new user id to the key. We'll need to specify all of our preferences at this point
        # because PGPy doesn't have any built-in key preference defaults at this time
        # this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
        key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

        private_key = str(key)

        # Now save the results back to a file
        with open(filename, "x") as key_file:
            key_file.write(private_key)

    # Some other error happened, (such as a permission issue)
    # This can also include errors if the pgp key is not valid
    except Exception as msg:
        print(f"Error trying to open keyfile {filename}. Error: {msg}")
        raise msg from None
    
    return private_key


def read_pgp_key(filename):
    """
    Just reads a pgp key. Mostly using this to read KoreLogic's public
    keys from a file

    Inputs:
        filename: (String) The full filename + path to save the PGP
        private key to


    Returns:
        key_string: (String) The key
    """
     # Try to read in an existing key
    try:
        with open(filename) as key_file:
            key_blob= key_file.read()
            key, _ = pgpy.PGPKey.from_blob(key_blob)
            key_string = str(key)
    
    # The keyfile does not exist
    except FileNotFoundError:
        print(f"Could not find key file {filename}. Error: {msg}")
        raise msg from None

    # Some other error happened, (such as a permission issue)
    # This can also include errors if the pgp key is not valid
    except Exception as msg:
        print(f"Error trying to open keyfile {filename}. Error: {msg}")
        raise msg from None
    
    return key_string


class PGPMgr:
    """
    Manages encrypting/decrypting messages using PGP

    Making this a class to make it easier to call when
    using a Jupyter Notebook
    """

    def __init__(self, my_private_key, their_public_key, default_attachment=None):
        """
        Inputs:
            my_private_key: (String) My PRIVATE key

            their_public_key: (String) The PUBLIC key I want to communicate with

            default_attachment: (String) The filename of the default encrypted file to create
            to attach to e-mails vs. copy/pasting it into the body
        """
        self.my_private_key, _ = pgpy.PGPKey.from_blob(my_private_key)
        self.their_public_key, _ = pgpy.PGPKey.from_blob(their_public_key)
        self.default_attachment = default_attachment
       
        # pgpy was creating warnings for depricated crypto algorithms I wasn't even using
        # so I'm hiding them since it is annoying
        warnings.filterwarnings(action='ignore',module='.*pgpy.*')

    def register_team(self, team_name, attachment_filename=None):
        """
        Creates the text for the initial KoreLogic team registration e-mail

        Inputs:
            team_name: (String) The name of your team.

            attachment_filename: (String) Overrides default attachment to write the file
        """
        # Create the message
        message = pgpy.PGPMessage.new(f"Team: {team_name}\n\n{str(self.my_private_key.pubkey)}")
        
        # Sign the message
        message |= self.my_private_key.sign(message)

        # Encrypt the message
        encrypted_message = self.their_public_key.encrypt(message)

        print(str(encrypted_message))

        if attachment_filename or self.default_attachment:
            if attachment_filename:
                filename = attachment_filename
            else:
                filename = self.default_attachment

            with open(filename, "w") as pgp_attachment:
                pgp_attachment.write(str(encrypted_message))

        return encrypted_message
    
    def encrypt_msg(self, msg, attachment_filename=None):
        # Create the message
        message = pgpy.PGPMessage.new(msg)
        
        # Sign the message
        message |= self.my_private_key.sign(message)

        # Encrypt the message
        encrypted_message = self.their_public_key.encrypt(message)

        print(str(encrypted_message))

        if attachment_filename or self.default_attachment:
            if attachment_filename:
                filename = attachment_filename
            else:
                filename = self.default_attachment

            with open(filename, "w") as pgp_attachment:
                pgp_attachment.write(str(encrypted_message))

        return encrypted_message

    def decrypt_msg(self, attachment_filename=None):
        """
        Decrypts a message sent by KoreLogic

        Inputs:
            attachment_filename: (String) Overrides default attachment to read from to decrypt

        Returns:
            plaintext: (String) The plaintext message
        """
        if not(attachment_filename or self.default_attachment):
            print("Error, you need to have either a default attachement, or specify it when calling this function")
            raise Exception
        
        if attachment_filename:
            filename = attachment_filename
        else:
            filename = self.default_attachment
        
        encrypted_message = pgpy.PGPMessage.from_file(filename)

        plaintext = self.my_private_key.decrypt(encrypted_message).message.decode()
        print(plaintext)

        return plaintext