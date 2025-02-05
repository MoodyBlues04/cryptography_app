import hashlib
import random
import math


class Math:
    PRIMES = []

    @classmethod
    def get_prime_divisors(cls, num: int) -> list:
        divisors = []
        while num % 2 == 0:
            divisors.append(2)
            num //= 2
        for divisor_cand in range(3, int(math.sqrt(num)) + 1, 2):
            while num % divisor_cand == 0:
                divisors.append(divisor_cand)
                num //= divisor_cand
        if num > 2:
            divisors.append(num)
        return list(set(divisors))

    @classmethod
    def generate_primes(cls, low_bound: int, high_bound: int) -> list:
        if high_bound < 2:
            return []

        is_prime = [True] * (high_bound + 1)
        is_prime[0] = is_prime[1] = False

        for prime_cand in range(2, int(high_bound ** 0.5) + 1):
            if is_prime[prime_cand]:
                for idx in range(prime_cand * prime_cand, high_bound + 1, prime_cand):
                    is_prime[idx] = False

        return [prime_num for prime_num, is_prime_flag in enumerate(is_prime) if
                is_prime_flag and prime_num >= low_bound]

    @classmethod
    def get_random_prime(cls):
        return random.choice(cls.PRIMES)

    @classmethod
    def is_prime(cls, num: int) -> bool:
        if num <= 1: return False
        if num <= 3: return True
        if num % 2 == 0 or num % 3 == 0: return False
        for i in range(5, int(math.sqrt(num)) + 1, 6):
            if num % i == 0 or num % (i + 2) == 0:
                return False
        return True

    @classmethod
    def is_square(cls, num: int) -> bool:
        return num == math.floor(num ** .5) ** 2

    @classmethod
    def inverse_mod(cls, k: int, mod: int) -> int:
        """ mod must be prime ! """
        if k == 0:
            raise ZeroDivisionError("Division by zero")
        return pow(k, mod - 2, mod)


Math.PRIMES = Math.generate_primes(1000, 10_000)


class LinearAlgebra:
    ZERO_POINT = None
    """ нулевая точка "O": Q + O = O + Q = Q """

    def __init__(self, a: int, b: int, p: int) -> None:
        self.__a, self.__b, self.__p = a, b, p

    @classmethod
    def is_zero_point(cls, point) -> bool:
        return point is cls.ZERO_POINT

    def point_add(self, point1: tuple, point2: tuple) -> tuple:
        if self.is_zero_point(point1):
            return point2
        if self.is_zero_point(point2):
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2 or y1 == 0:
            return self.ZERO_POINT

        if x1 == x2:
            _lambda = (3 * x1 ** 2 + self.__a) * Math.inverse_mod(2 * y1, self.__p)
        else:
            _lambda = (y2 - y1) * Math.inverse_mod(x2 - x1, self.__p)

        x3 = _lambda ** 2 - x1 - x2
        y3 = _lambda * (x1 - x3) - y1

        return (x3 % self.__p, y3 % self.__p)

    def scalar_mult(self, k: int, point: tuple) -> tuple:
        result = None
        addend = point

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result


class Params:
    p = 0
    a, b = 0, 0
    P = None
    m, q = None, None

    private_key = None
    public_key = None

    def __str__(self):
        return f"p={self.p}, (a, b)=({self.a}, {self.b}), P={self.P}, m={self.m}, q={self.q}"

    @classmethod
    def from_dict(cls, raw_params: dict):
        params = Params()
        params.p = cls.to_int_if_not_empty(raw_params.get('p'))
        params.a = cls.to_int_if_not_empty(raw_params.get('a'))
        params.b = cls.to_int_if_not_empty(raw_params.get('b'))
        params.P = raw_params.get('P')
        if params.P is not None: params.P = (int(params.P[0]), int(params.P[1]))
        params.m = cls.to_int_if_not_empty(raw_params.get('m'))
        params.q = cls.to_int_if_not_empty(raw_params.get('q'))
        params.private_key = cls.to_int_if_not_empty(raw_params.get('private_key', random.randint(1, params.q - 1) if params.q and params.q > 1 else None))
        algebra: LinearAlgebra = LinearAlgebra(params.a, params.b, params.p)
        params.public_key = raw_params.get('public_key', algebra.scalar_mult(params.private_key, params.P) if params.private_key and params.P else None)
        return params

    @classmethod
    def to_int_if_not_empty(cls, val) -> int | None:
        return val if val is None else int(val)


def calc_j(a: int, b: int, p: int) -> int:
    return (1728 * 4 * a ** 3 * Math.inverse_mod(4 * a ** 3 + 27 * b ** 2, p)) % p


class ParamsGenerator:
    __params: Params | None = None

    def generate_params(self) -> Params:
        self.__params = Params()
        self.__generate_p()
        self.__generate_elips_params()

        self.__algebra: LinearAlgebra = LinearAlgebra(self.__params.a, self.__params.b, self.__params.p)

        self.__generate_base_elips_point()
        self.__params.private_key = random.randint(1, self.__params.q - 1)
        self.__params.public_key = self.__algebra.scalar_mult(self.__params.private_key, self.__params.P)
        return self.__params

    def __generate_base_elips_point(self) -> None:
        trials = 100
        while self.__params.P is None and trials > 0:
            trials -= 1
            self.__generate_m()
            if self.__params.m == self.__params.p:
                continue

            self.__generate_q()

            for P_x in range(1, 2 * self.__params.p):
                P_y_squared = (P_x ** 3 + self.__params.a * P_x + self.__params.b) % self.__params.p
                if P_y_squared == 0:
                    continue

                for _ in range(10):
                    if Math.is_square(P_y_squared):
                        break
                    P_y_squared += self.__params.p
                if not Math.is_square(P_y_squared):
                    continue

                self.__params.P = (P_x, int(P_y_squared ** .5))
                if self.__algebra.scalar_mult(self.__params.q, self.__params.P) is None and \
                        self.__algebra.scalar_mult(1, self.__params.P) is not None:
                    return

                self.__params.P = None

    def __generate_q(self) -> None:
        self.__params.q = random.choice(Math.get_prime_divisors(self.__params.m))

    def __generate_m(self) -> None:
        _p = self.__params.p
        self.__params.m = random.randint(math.ceil(_p + 1 - 2 * math.sqrt(_p)), math.floor(_p + 1 + 2 * math.sqrt(_p)))

    def __generate_p(self):
        self.__params.p = Math.get_random_prime()  # Модуль конечного поля
        if self.__params.p <= 3:
            raise Exception('p <= 3')

    def __generate_elips_params(self) -> None:
        a, b = 0, 0
        while (4 * a ** 3 + 27 * b ** 2) % self.__params.p == 0 or calc_j(a, b, self.__params.p) in [0, 1728]:
            a, b = random.randint(1, 1000), random.randint(1, 1000)
        self.__params.a, self.__params.b = a, b


class GostHasher:
    def __init__(self, params: Params):
        self.__params: Params = params
        self.__algebra = LinearAlgebra(params.a, params.b, params.p)

    def __gost_hash(self, message: str) -> int:
        """Simulate the GOST R 34.11-2012 hash function."""
        hash_value = hashlib.sha256(message.encode()).hexdigest()
        return int(hash_value, 16)

    def sign_message(self, message: str) -> tuple:
        """Form a digital signature for the message."""
        # Step 1: Compute the hash of the message
        hash_value = self.__gost_hash(message)

        # Step 2: Convert hash to integer and reduce modulo q
        e = self.__get_e(hash_value)

        for trials in range(100):
            # Step 3: Generate a random number k
            k = random.randint(1, self.__params.q - 1)

            # Step 4: Compute the point C = kP
            C = self.__algebra.scalar_mult(k, self.__params.P)
            if C is None:
                continue
            x_C, _ = C

            # Step 5: Compute r = x_C mod q
            r = x_C % self.__params.q
            if r == 0:
                continue

            # Step 6: Compute s = (r * d + k * e) mod q
            s = (r * self.__params.private_key + k * e) % self.__params.q
            if s == 0:
                continue

            # Step 7: Form the signature (r, s)
            return (r, s)
        raise Exception('cant sign')

    def verify_signature(self, message: str, signature: tuple) -> bool:
        """Verify the digital signature for the message."""
        r, s = signature

        # Step 1: Check if 0 < r < q and 0 < s < q
        if not (0 < r < self.__params.q and 0 < s < self.__params.q):
            return False

        # Step 2: Compute the hash of the message
        hash_value = self.__gost_hash(message)

        # Step 3: Convert hash to integer and reduce modulo q
        e = self.__get_e(hash_value)

        # Step 4: Compute the modular inverse of e
        v = Math.inverse_mod(e, self.__params.q)

        # Step 5: Compute intermediate values
        z = self.__get_z(r, s, v)

        # Step 6: Compute the point C = z1 * P + z2 * Q
        C = self.__get_C(self.__params.public_key, z)

        # Step 7: Extract R = x_C mod q
        x_C, _ = C
        R = x_C % self.__params.q

        # Step 8: Validate the signature
        return R == r

    def __get_C(self, public_key: tuple, z: tuple) -> tuple:
        z1, z2 = z
        return self.__algebra.point_add(
            self.__algebra.scalar_mult(z1, self.__params.P),
            self.__algebra.scalar_mult(z2, public_key)
        )

    def __get_z(self, r: int, s: int, v: int) -> tuple:
        z1 = (s * v) % self.__params.q
        z2 = (-r * v) % self.__params.q
        return z1, z2

    def __get_e(self, hash_value: int) -> int:
        e = hash_value % self.__params.q
        if e == 0:
            e = 1
        return e


def validate_params(raw_params: dict):
    errors = []
    params = Params.from_dict(raw_params)
    if params.p is None: return errors
    if not Math.is_prime(params.p):
        errors.append({'key': 'p', 'message': 'P должно быть простым числом'})
    if params.a is None or params.b is None: return errors
    if (4 * params.a ** 3 + 27 * params.b ** 2) % params.p == 0 or calc_j(params.a, params.b, params.p) in [0, 1728]:
        msg = 'a и b задают некорректную кривую'
        errors.append({'key': 'a', 'message': msg})
        errors.append({'key': 'b', 'message': msg})

    if params.m is None: return errors
    if not (math.ceil(params.p + 1 - 2 * math.sqrt(params.p)) <= params.m <= math.floor(params.p + 1 + 2 * math.sqrt(params.p))):
        errors.append({'key': 'm', 'message': 'M должно удовлетворять: p + 1 - 2 * sqrt(p) <= m <= p + 1 + 2 * sqrt(p)'})
    if params.q is None: return errors
    if not Math.is_prime(params.q) or params.m % params.q != 0:
        errors.append({'key': 'q', 'message': 'q должно быть простым делителем m'})

    if params.P is None: return errors
    P_x, P_y = params.P
    if (P_y ** 2) % params.p != (P_x ** 3 + P_x * params.a + params.b) % params.p:
        errors.append({'key': 'P', 'message': 'P должно быть точкой на кривой'})
    linear_alg = LinearAlgebra(params.a, params.b, params.p)
    if linear_alg.scalar_mult(params.q, params.P) is not None:
        errors.append({'key': 'P', 'message': 'qP != O'})
    if linear_alg.scalar_mult(1, params.P) is None:
        errors.append({'key': 'P', 'message': 'P == O'})

    if params.private_key is None: return errors
    if not (1 <= params.private_key < params.q):
        errors.append({'key': 'private_key', 'message': 'private_key должен удовлетворять: 1 <= key < q'})
    expected = linear_alg.scalar_mult(params.private_key, params.P)
    if params.public_key is None: return errors
    if params.public_key[0] != expected[0] or params.public_key[1] != expected[1]:
        errors.append({'key': 'public_key', 'message': 'public_key != private_key * P'})

    return errors
