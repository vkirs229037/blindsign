from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
import gmpy2
from gmpy2 import mpz

rand_state = gmpy2.random_state()

class UserInfo:
    p: mpz
    e: mpz
    d: mpz

class DocInfo:
    r: mpz
    sign: mpz

def gen_coprime(n: mpz) -> mpz:
    while True:
        r = gmpy2.mpz_random(rand_state, gmpy2.isqrt(n))
        if gmpy2.gcd(r, n) == 1:
            return r

def gen_keys():
    return RSA.generate(2048)

# Используемые здесь p, e, d — из ключа Боба
# r генерирует Алиса
# Алиса
def send_data_to_sign(data: bytes, p: mpz, e: mpz) -> mpz:
    sha = SHA512.new()
    sha.update(data)
    m = mpz(int.from_bytes(sha.digest()))
    p = mpz(p)
    e = mpz(e)
    r = gen_coprime(p)
    m_temp = m * gmpy2.powmod(r, e, p)
    assert isinstance(m_temp, mpz)
    m_prime = m_temp % p
    return m_prime

# Боб 
def gen_sign(m_prime: mpz, d: mpz, p: mpz) -> mpz:
    s_prime = gmpy2.powmod(m_prime, d, p)
    return s_prime

# Алиса
def verify_sign(m: mpz, s_prime: mpz, r: mpz, e: mpz, p: mpz) -> bool:
    s_temp = s_prime * gmpy2.invert(r, p)
    assert isinstance(s_temp, mpz)
    s = s_temp % p
    test = gmpy2.powmod(s, e, p)
    return m == test