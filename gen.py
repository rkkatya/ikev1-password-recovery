import hmac
import hashlib
import argparse
import binascii

class IKEv1DataGenerator:
    def __init__(self, data_file):
        self.load_from_file(data_file)
    
    def load_from_file(self, filename):
        data = {}
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    data[key] = value
        
        #hex-строки в бинарные 
        self.Ni = binascii.unhexlify(data.get('Ni', ''))
        self.Nr = binascii.unhexlify(data.get('Nr', ''))
        self.g_x = binascii.unhexlify(data.get('g_x', ''))
        self.g_y = binascii.unhexlify(data.get('g_y', ''))
        self.Ci = binascii.unhexlify(data.get('Ci', ''))
        self.Cr = binascii.unhexlify(data.get('Cr', ''))
        self.SAi = binascii.unhexlify(data.get('SAi', ''))
        self.IDr = binascii.unhexlify(data.get('IDr', ''))

    def generate_hash(self, password, algorithm):
        hash_func = getattr(hashlib, algorithm)
        
        #SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
        skeyid = hmac.new(
            password.encode(), 
            self.Ni + self.Nr, 
            hash_func
        ).digest()
        
        #HASH_I = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
        hash_data = (self.g_y + self.g_x + self.Cr + self.Ci + self.SAi + self.IDr)
        
        hash_value = hmac.new(
            skeyid, 
            hash_data, 
            hash_func
        ).hexdigest()
        
        return hash_value

    def generate_output(self, password, algorithm):
        hash_value = self.generate_hash(password, algorithm)
        
        #Ni*Nr*g_x*g_y*Ci*Cr*SAi*IDr*HASH
        output = '*'.join([
            binascii.hexlify(self.Ni).decode(),
            binascii.hexlify(self.Nr).decode(),
            binascii.hexlify(self.g_x).decode(),
            binascii.hexlify(self.g_y).decode(),
            binascii.hexlify(self.Ci).decode(),
            binascii.hexlify(self.Cr).decode(),
            binascii.hexlify(self.SAi).decode(),
            binascii.hexlify(self.IDr).decode(),
            hash_value
        ])
        
        return output

def main():
    parser = argparse.ArgumentParser(description='IKEv1 Aggressive Mode Data Generator')
    parser.add_argument('-m', '--algorithm', choices=['md5', 'sha1'], required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-f', '--file', required=True)
    parser.add_argument('-o', '--output', help='Output file name')
    args = parser.parse_args()

    generator = IKEv1DataGenerator(args.file)
    output = generator.generate_output(args.password, args.algorithm)
    
    if args.output:

        #сохранили в файл
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Данные сохранены в файл: {args.output}")
    else:
        #вывели на экран
        print(output)

if __name__ == '__main__':
    main()