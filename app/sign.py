from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
import gmpy2
from gmpy2 import mpz

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

# Используемые здесь p, e, d — из ключа нотариуса
# r генерирует отправитель документа (А)
# А
def mask_data(data: int, n: int, e: int) -> tuple[mpz, mpz]:
    sha = SHA512.new()
    sha.update(data)
    m = mpz.from_bytes(sha.digest())
    n = mpz(n)
    e = mpz(e)
    r = gen_mask(n)
    m_temp = m * gmpy2.powmod(r, e, n)
    assert isinstance(m_temp, mpz)
    m_prime = m_temp % n
    return m, m_prime

# Нотариус
def gen_sign(m_prime: int, d: int, n: int) -> mpz:
    m_prime = mpz(m_prime)
    d = mpz(d)
    n = mpz(n)
    s_prime = gmpy2.powmod(m_prime, d, n)
    return s_prime

# А
def get_sign(m: int, s_prime: int, r: int, e: int, n: int) -> mpz:
    m = mpz(m)
    s_prime = mpz(s_prime)
    r = mpz(r)
    e = mpz(e)
    n = mpz(n)
    s_temp = s_prime * gmpy2.invert(r, n)
    assert isinstance(s_temp, mpz)
    s = s_temp % n
    return s