import hashlib
import random
import math


def get_prime_divisors(n):
    divisors = []
    while n % 2 == 0:
        divisors.append(2)
        n //= 2
    for divisor_cand in range(3, int(math.sqrt(n)) + 1, 2):
        while n % divisor_cand == 0:
            divisors.append(divisor_cand)
            n //= divisor_cand
    if n > 2:
        divisors.append(n)
    return list(set(divisors))


def generate_primes(low_bound: int, high_bound: int) -> list:
    if high_bound < 2:
        return []

    is_prime = [True] * (high_bound + 1)
    is_prime[0] = is_prime[1] = False

    for prime_cand in range(2, int(high_bound ** 0.5) + 1):
        if is_prime[prime_cand]:
            for idx in range(prime_cand * prime_cand, high_bound + 1, prime_cand):
                is_prime[idx] = False

    return [prime_num for prime_num, is_prime_flag in enumerate(is_prime) if is_prime_flag and prime_num >= low_bound]


PRIMES = generate_primes(1000, 10_000)


def get_random_prime():
    return random.choice(PRIMES)


def is_square(num) -> bool:
    return num == math.floor(num ** .5) ** 2


def inverse_mod(k: int, _p: int) -> int:
    """Compute the modular inverse of k modulo p.
        P MUST BE PRIME
    """
    if k == 0:
        raise ZeroDivisionError("Division by zero")
    return pow(k, _p - 2, _p)


def point_add(p1: tuple, p2: tuple) -> tuple:
    """Add two points on the elliptic curve."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2 or y1 == 0:
        return None  # нулевая точка "O": Q + O = O + Q = Q

    if x1 == x2:
        _m = (3 * x1 ** 2 + a) * inverse_mod(2 * y1, p)
    else:
        _m = (y2 - y1) * inverse_mod(x2 - x1, p)

    x3 = _m ** 2 - x1 - x2
    y3 = _m * (x1 - x3) - y1

    return (x3 % p, y3 % p)


def scalar_mult(k: int, point: tuple) -> tuple:
    """Multiply a point on the elliptic curve by a scalar."""
    result = None
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def calc_J():
    return (1728 * 4 * a ** 3 * inverse_mod(4 * a ** 3 + 27 * b ** 2, p)) % p


# Пример параметров (для обучения)
# p = 57896044618658097711785492504343953926634992332820282019728792003956564821041  # Модуль конечного поля
# a = 7    # Коэффициент a эллиптической кривой
# b = 43308876546767276905765904595650931995942111794451039583252968842033849580414    # Коэффициент b эллиптической кривой
# while (4 * a ** 3 + 27 * b ** 2) % p == 0 or calc_J() in [0, 1728]:
#     a, b = random.randint(1, 1000), random.randint(1, 1000)
#
# P_x = 2   # x-координата базовой точки P
# P_y = 4018974056539037503335449422937059775635739389905545080690979365213431566280   # y-координата базовой точки P
# q = 57896044618658097711785492504343953927082934583725450622380973592137631069619   # Порядок базовой точки P
# P = (P_x, P_y)

# Пример параметров (для обучения)
p = get_random_prime()  # Модуль конечного поля
if p <= 3: raise Exception('p <= 3')

a = 0  # Коэффициент a эллиптической кривой
b = 0  # Коэффициент b эллиптической кривой
while (4 * a ** 3 + 27 * b ** 2) % p == 0 or calc_J() in [0, 1728]:
    a, b = random.randint(1, 1000), random.randint(1, 1000)

P_x = 0  # x-координата базовой точки P
P_y = 0  # y-координата базовой точки P
P = None
m, q = None, None

while P is None:
    m = random.randint(math.ceil(p + 1 - 2 * math.sqrt(p)), math.floor(p + 1 + 2 * math.sqrt(p)))
    if m == p: continue
    q = random.choice(get_prime_divisors(m))  # Порядок базовой точки P

    for P_x in range(1, 2 * p):
        P_y_squared = (P_x ** 3 + a * P_x + b) % p
        if P_y_squared == 0:
            continue
        for _ in range(10):
            if is_square(P_y_squared):
                break
            P_y_squared += p
        if not is_square(P_y_squared):
            continue

        P = (P_x, int(P_y_squared ** .5))
        if scalar_mult(q, P) is None and scalar_mult(1, P) is not None: # check that qP = O
            break
        P = None

print(f"p={p}, a={a}, b={b}, m={m}, q={q}, P={P}, qP={scalar_mult(q, P)}, y_square={(P_x ** 3 + a * P_x + b) % p}")

# Private key (example)
d = random.randint(1, q - 1)  # Private key (must be kept secret)

# Public key (example)
Q = scalar_mult(d, P)  # Q = d * P


def gost_hash(message: str) -> int:
    """Simulate the GOST R 34.11-2012 hash function."""
    hash_value = hashlib.sha256(message.encode()).hexdigest()
    return int(hash_value, 16)


def sign_message(message: str, private_key: int) -> tuple:
    """Form a digital signature for the message."""
    # Step 1: Compute the hash of the message
    hash_value = gost_hash(message)

    # Step 2: Convert hash to integer and reduce modulo q
    e = hash_value % q
    if e == 0:
        e = 1

    while True:
        # Step 3: Generate a random number k
        k = random.randint(1, q - 1)

        # Step 4: Compute the point C = kP
        C = scalar_mult(k, P)
        if C is None: continue
        x_C, _ = C
        # Step 5: Compute r = x_C mod q
        r = x_C % q
        if r == 0:
            continue

        # Step 6: Compute s = (r * d + k * e) mod q
        s = (r * private_key + k * e) % q
        if s == 0:
            continue

        # Step 7: Form the signature (r, s)
        return (r, s)


def verify_signature(message: str, signature: tuple, public_key: tuple) -> bool:
    """Verify the digital signature for the message."""
    r, s = signature

    # Step 1: Check if 0 < r < q and 0 < s < q
    if not (0 < r < q and 0 < s < q):
        return False

    # Step 2: Compute the hash of the message
    hash_value = gost_hash(message)

    # Step 3: Convert hash to integer and reduce modulo q
    e = hash_value % q
    if e == 0:
        e = 1

    # Step 4: Compute the modular inverse of e
    v = inverse_mod(e, q)

    # Step 5: Compute intermediate values
    z1 = (s * v) % q
    z2 = (-r * v) % q

    # Step 6: Compute the point C = z1 * P + z2 * Q
    C1 = scalar_mult(z1, P)
    C2 = scalar_mult(z2, public_key)
    C = point_add(C1, C2)

    # Step 7: Extract R = x_C mod q
    x_C, _ = C
    R = x_C % q

    # Step 8: Validate the signature
    return R == r


if __name__ == '__main__':
    # Example usage
    message = "Hello, world!"

    for i in range(1000):
        if i % 10 == 0:
            print(f"running test: {i}")
        # Step 1: Sign the message
        signature = sign_message(message, d)
        # print(f"Signature (r, s): {signature}")

        # Step 2: Verify the signature
        is_valid = verify_signature(message, signature, Q)
        if not is_valid:
            print(f"fail on test: {i}")
        # print(f"Signature is valid: {is_valid}")
