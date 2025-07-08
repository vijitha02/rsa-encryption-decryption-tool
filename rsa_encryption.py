import random
import math

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
    # Write n-1 as d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    # Test k times
    for _ in range(k):
        a = random.randint(2, n-2)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number with specified number of bits"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Set highest and lowest bit
        if is_prime(p):
            return p

def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Modular inverse using extended Euclidean algorithm"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keys(bits=1024):
    """Generate RSA public and private keys"""
    # Generate two large prime numbers
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    # Calculate n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 65537  # Common choice for e
    while math.gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    
    # Calculate d, the modular inverse of e
    d = modinv(e, phi)
    
    return ((e, n), (d, n))

def encrypt(message, public_key):
    """Encrypt a message using RSA public key"""
    e, n = public_key
    # Convert message to integer
    if isinstance(message, str):
        message = int.from_bytes(message.encode(), 'big')
    return pow(message, e, n)

def decrypt(ciphertext, private_key):
    """Decrypt a ciphertext using RSA private key"""
    d, n = private_key
    # Decrypt and convert back to string
    decrypted = pow(ciphertext, d, n)
    return decrypted.to_bytes((decrypted.bit_length() + 7) // 8, 'big').decode()

def main():
    # Generate keys
    public_key, private_key = generate_keys()
    print("Public Key (e, n):", public_key)
    print("Private Key (d, n):", private_key)
    
    # Example message
    message = "Hello, RSA Encryption!"
    print("\nOriginal Message:", message)
    
    # Encrypt
    ciphertext = encrypt(message, public_key)
    print("Encrypted:", ciphertext)
    
    # Decrypt
    decrypted = decrypt(ciphertext, private_key)
    print("Decrypted:", decrypted)

if __name__ == "__main__":
    main() 