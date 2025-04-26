from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
import gmpy2
from gmpy2 import mpz
import time

rand_state = gmpy2.random_state()

def gen_hash(data: bytes) -> bytes:
    sha512 = SHA512.new(data)
    return sha512.digest()

def gen_mask(n: mpz) -> mpz:
    return gmpy2.mpz_random(rand_state, n - 1)

def gen_keys() -> RSA.RsaKey:
    return RSA.generate(2048)

def import_keys(file, pw) -> tuple[RSA.RsaKey | None, bool]:
    rsakey = None
    data = bytes()
    with open(file, "rb") as f:
        data = f.read()
    try:
        rsakey = RSA.import_key(data, pw)
        return (rsakey, True)
    # Не удалось импортировать ключ
    except (ValueError, IndexError, TypeError):
        return (None, False)
    
def import_public_key(file) -> RSA.RsaKey:
    data = bytes()
    with open(file, "rb") as f:
        data = f.read()
    rsakey = RSA.import_key(data)
    return rsakey

# Используемые здесь p, e, d — из ключа Боба
# r генерирует Алиса
# Алиса
def mask_data(data: bytes, n: mpz, e: mpz) -> mpz:
    sha = SHA512.new()
    sha.update(data)
    m = mpz(int.from_bytes(sha.digest()))
    n = mpz(n)
    e = mpz(e)
    r = gen_mask(n)
    m_temp = m * gmpy2.powmod(r, e, n)
    assert isinstance(m_temp, mpz)
    m_prime = m_temp % n
    return m_prime

# Боб 
def gen_sign(m_prime: bytes, d: int, n: int) -> mpz:
    m_prime = mpz(int.from_bytes(m_prime))
    d = mpz(d)
    n = mpz(n)
    s_prime = gmpy2.powmod(m_prime, d, n)
    return s_prime

# Алиса
def verify_sign(m: mpz, s_prime: mpz, r: mpz, e: mpz, n: mpz) -> bool:
    s_temp = s_prime * gmpy2.invert(r, n)
    assert isinstance(s_temp, mpz)
    s = s_temp % n
    test = gmpy2.powmod(s, e, n)
    return m == test