import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from getpass import getpass
from Crypto.Hash import SHA256

class AESFileCipher:
    def __init__(self, password):
        self.password = password.encode('utf-8')
        self.salt_size = 32
        self.key_size = 32
        self.iterations = 210000
        self.block_size = AES.block_size
        self.hmac_size = hashlib.sha256().digest_size
        self.chunk_size = 1024 * 1024

    def _derive_key(self, salt):
        return PBKDF2(
            self.password,
            salt,
            dkLen=self.key_size,
            count=self.iterations,
            hmac_hash_module=SHA256
        )

    def encrypt_file(self, input_file, output_file):
        salt = get_random_bytes(self.salt_size)
        key = self._derive_key(salt)
        iv = get_random_bytes(self.block_size)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        hmac_obj = hmac.new(key, digestmod=hashlib.sha256)

        try:
            with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
                fout.write(salt)
                fout.write(iv)
                
                while True:
                    chunk = fin.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    if len(chunk) % self.block_size != 0:
                        chunk = pad(chunk, self.block_size)
                    
                    encrypted_chunk = cipher.encrypt(chunk)
                    fout.write(encrypted_chunk)
                    hmac_obj.update(encrypted_chunk)
                
                fout.write(hmac_obj.digest())
                
        except Exception as e:
            if os.path.exists(output_file):
                os.remove(output_file)
            raise e

    def decrypt_file(self, input_file, output_file):
        try:
            with open(input_file, 'rb') as fin:
                salt = fin.read(self.salt_size)
                iv = fin.read(self.block_size)
                key = self._derive_key(salt)
                
                hmac_obj = hmac.new(key, digestmod=hashlib.sha256)
                
                file_size = os.path.getsize(input_file)
                data_size = file_size - self.salt_size - self.block_size - self.hmac_size
                
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                with open(output_file, 'wb') as fout:
                    remaining = data_size
                    
                    while remaining > 0:
                        chunk_size = min(self.chunk_size, remaining)
                        chunk = fin.read(chunk_size)
                        if not chunk:
                            break
                        
                        hmac_obj.update(chunk)
                        remaining -= len(chunk)
                        
                        decrypted_chunk = cipher.decrypt(chunk)
                        
                        if remaining <= 0:
                            decrypted_chunk = unpad(decrypted_chunk, self.block_size)
                        
                        fout.write(decrypted_chunk)
                    
                    stored_hmac = fin.read(self.hmac_size)
                    if not hmac.compare_digest(hmac_obj.digest(), stored_hmac):
                        raise ValueError("HMAC verification failed - file may be corrupted or tampered with")
                        
        except Exception as e:
            if os.path.exists(output_file):
                os.remove(output_file)
            raise e

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Secure File Encryption Tool (AES-256-CBC with HMAC-SHA256)"
    )
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('input_file', help="Input file path")
    parser.add_argument('output_file', help="Output file path")
    parser.add_argument('-p', '--password', help="Encryption password (optional)", default=None)
    
    args = parser.parse_args()
    
    password = args.password if args.password else getpass("Enter password: ")
    
    try:
        cipher = AESFileCipher(password)
        
        if args.action == 'encrypt':
            cipher.encrypt_file(args.input_file, args.output_file)
            print(f"File encrypted successfully: {args.output_file}")
        else:
            cipher.decrypt_file(args.input_file, args.output_file)
            print(f"File decrypted successfully: {args.output_file}")
            
    except Exception as e:
        print(f"\nError: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()