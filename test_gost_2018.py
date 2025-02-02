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
        return num in cls.PRIMES

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
class Params:
    p = 0
    a, b = 0, 0
    P = None
    m, q = None, None

    private_key = None
    public_key = None

    def __str__(self):
        return f"p={self.p}, (a, b)=({self.a}, {self.b}), P={self.P}, m={self.m}, q={self.q}"


class ParamsGenerator:
    __params: Params | None = None

    def generate_params(self) -> Params:
        self.__params = Params()
        self.__generate_p()
        self.__generate_elips_params()

        self.__algebra: LinearAlgebra = LinearAlgebra(self.__params.a, self.__params.b, self.__params.p)

        self.__generate_base_elips_point()
        self.__params.d = random.randint(1, self.__params.q - 1)
        self.__params.Q = self.__algebra.scalar_mult(self.__params.d, self.__params.P)  # Q = d * P
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
        while (4 * a ** 3 + 27 * b ** 2) % self.__params.p == 0 or self.__calc_j(a, b) in [0, 1728]:
            a, b = random.randint(1, 1000), random.randint(1, 1000)
        self.__params.a, self.__params.b = a, b

    def __calc_j(self, a: int, b: int) -> int:
        p = self.__params.p
        return (1728 * 4 * a ** 3 * Math.inverse_mod(4 * a ** 3 + 27 * b ** 2, p)) % p


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


def test_params(hasher: GostHasher) -> bool:
    message = "Hello, world!"
    try:
        for i in range(100):
            if i % 10 == 0:
                print(f"running test: {i}")
            # Step 1: Sign the message
            signature = hasher.sign_message(message)

            # Step 2: Verify the signature
            if not hasher.verify_signature(message, signature):
                return False
        return True
    except Exception as e:
        print(f"Error: {e.__str__()}")
        return False


if __name__ == '__main__':
    cool_params = []
    for i in range(100):
        print(i)
        params = ParamsGenerator().generate_params()
        hasher = GostHasher(params)
        if test_params(hasher):
            cool_params.append(params.__str__())

    print(*cool_params)
