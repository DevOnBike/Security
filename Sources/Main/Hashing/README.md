NIST's primary recommendation for hash algorithms this year remains the SHA-2 and SHA-3 families of standards. These are considered secure and robust for a wide variety of cryptographic applications. 🛡️

Secure Hash Algorithm (SHA) Families
The current standards endorsed by NIST include several algorithms with varying output sizes to accommodate different security needs.

SHA-2
This family, specified in FIPS 180-4, is the most widely used hash algorithm family in the world. It includes:

SHA-256: a popular choice for many applications, including digital signatures and blockchain technology.
SHA-384: offers a higher level of security.
SHA-512: provides the highest security level in the SHA-2 family.
SHA-224, SHA-512/224, and SHA-512/256.
SHA-3
Defined in FIPS 202, the SHA-3 family is based on the Keccak algorithm and was developed to be a secure alternative to SHA-2. It includes:

SHA3-256
SHA3-384
SHA3-512
SHA3-224
In addition to these, the SHA-3 standard also introduced two other functions called SHAKE128 and SHAKE256 (eXtendable-Output Functions), which can produce a hash of any desired length.

Post-Quantum Cryptography and Hashing
It's important to note that while NIST is actively standardizing new post-quantum cryptographic algorithms (for things like digital signatures), these new standards continue to rely on the security of existing hash functions like SHA-2 and SHA-3. The threat from quantum computers is primarily to public-key cryptography (like RSA and Elliptic Curve Cryptography), not to symmetric algorithms like hash functions.

Therefore, for hashing purposes in 2025, the recommendation is to continue using a member of the SHA-2 or SHA-3 families with a security strength appropriate for your application. For most new applications, SHA-256 or SHA3-256 are excellent starting points

NIST Recommendation for Password Hashing
NIST's primary guidance for password hashing is found in Special Publication 800-63B, section 5.1.1.2. The core recommendation is to use a key derivation function (KDF) specifically designed for password hashing.

These functions are intentionally slow and memory-intensive to make brute-force and dictionary attacks computationally expensive for an attacker.

Key Requirements:
Use an Approved Algorithm: NIST recommends one-way, salted, and stretched password hashing algorithms. The top recommendations are:

Argon2 (The winner of the Password Hashing Competition, often considered the strongest).
PBKDF2 (Password-Based Key Derivation Function 2).
bcrypt.
scrypt.
Use a Unique Salt: A new, unique, and cryptographically random salt must be generated for every password that is hashed. This ensures that two users with the same password will have completely different hashes. NIST recommends a salt of at least 32 bytes.

Use a High Work Factor (Iteration Count): The algorithm must be iterated to make it slow. The number of iterations (or "work factor") should be configured to be as high as your server can tolerate without causing unacceptable login delays (typically aiming for a verification time between 100-500 milliseconds). For PBKDF2, NIST requires a minimum of 10,000 iterations, but a much higher value is strongly recommended.

Store the Hash and Parameters: The final hash, the unique salt, and all the parameters used to generate it (like the algorithm and iteration count) must be stored together for each user. This allows you to verify the password later.