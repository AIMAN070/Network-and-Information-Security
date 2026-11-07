Vigenere–Progressive Affine Hybrid Cipher
Course: Network and Information Security (CT-486)
University: NED University of Engineering & Technology
Project Type: Complex Computing Problem (CCP)
Project Overview
This project designs and implements a custom hybrid cipher by combining two classical encryption techniques:
1. Vigenere Cipher — the first encryption stage.
2. Progressive Affine Cipher — the second encryption stage.
The project also implements a Known-Plaintext Attack to recover the encryption key and decrypt the complete message using a known plaintext prefix and its corresponding ciphertext. The program compares the hybrid cipher's execution time with a single-stage Shift Cipher and displays time-complexity information.
This is an educational implementation of classical cryptography. It is not intended for protecting real-world sensitive information.

Group Members
- Aiman Nasir (CR-23049)
- Atika Imam (CR-23008)
- Soha (CR-23027)
- Ramaize Shahab (CR-23035)
Cipher Design
1. Vigenere Cipher
The first stage encrypts the plaintext using the repeating key:
- Vigenere key: NETWORKSAFE
- Key length: 11 characters
For each character:
\[
V_i = (P_i + K_{i \bmod 11}) \bmod 26
\]
Where:
- \(P_i\) is the plaintext character value.
- \(K_i\) is the corresponding key character value.
- \(V_i\) is the output of the Vigenere stage.
- The alphabet is represented using values A = 0 through Z = 25.
2. Progressive Affine Cipher
The second stage applies a position-dependent Affine transformation.
- A: 5
- B: 8
Encryption formula:
\[
C_i = (5V_i + 8(i+1)) \bmod 26
\]
The value of the shift changes according to the character's position.
Combined Encryption
The program performs the stages in this order:
1. Encrypt the plaintext using the Vigenere Cipher.
2. Encrypt the intermediate result using the Progressive Affine Cipher.
3. Produce the final ciphertext.
Decryption
Decryption reverses the encryption stages.

The modular inverse of 5 modulo 26 is 21:
\[
5^{-1} \bmod 26 = 21
\]
First, reverse the Progressive Affine stage:
\[
V_i = 21(C_i - 8(i+1)) \bmod 26
\]
Then reverse the Vigenere stage:
\[
P_i = (V_i - K_{i \bmod 11}) \bmod 26
\]
The program displays whether the recovered plaintext matches the original input.
Known-Plaintext Attack
The attack assumes that an attacker knows:
- A portion (prefix) of the original plaintext.
- The corresponding ciphertext.
- The Vigenere key length (11 characters).
The attack does not receive the original encryption key as an input.
Attack procedure
1. Generate all valid Affine A values for which gcd(A, 26) = 1.
2. Test all 26 possible B values.
3. Reverse the Progressive Affine transformation for the known plaintext positions.
4. Derive Vigenere key characters from the known plaintext and corresponding ciphertext.
5. Check consistency at repeated Vigenere key positions.
6. Verify each candidate against the complete known plaintext portion.
7. Decrypt the full ciphertext only after a candidate has been verified.
There are 12 valid values of A and 26 possible values of B:
\[
12 \times 26 = 312
\]
Therefore, the attack tests 312 candidate Affine parameter pairs.

The attack requires at least 11 known characters to derive all Vigenere key positions. The program recommends a longer known prefix; its benchmark uses 55 known characters.
Shift Cipher Baseline
A traditional Shift Cipher with a fixed shift value of 3 is implemented as a baseline. The program compares encryption and decryption timings for the hybrid cipher and Shift Cipher.
Performance Evaluation
The program measures encryption and decryption for these message lengths:
- 1,000 characters
- 10,000 characters
- 100,000 characters
Each timing measurement uses repeated runs and reports the median time.

The known-plaintext attack benchmark tests each ciphertext length five times, using a 55-character known plaintext prefix. It reports:
- Success rate
- Number of matching candidates
- Median attack time
- Character checks
The report's benchmark results show a 100% success rate and one matching candidate for each of the three tested ciphertext lengths (five trials per length). Execution times depend on the machine and runtime environment, so they may differ between runs.
Time Complexity
Algorithm	Time Complexity
Vigenere encryption	\(O(N)\)
Progressive Affine encryption	\(O(N)\)
Hybrid encryption	\(O(N)\)
Hybrid decryption	\(O(N)\)
Shift encryption	\(O(N)\)
Shift decryption	\(O(N)\)
Known-plaintext attack	\(O(K \times L + S \times N)\)


Where:
- N = plaintext or ciphertext length.
- K = number of candidate Affine parameter pairs (312).
- L = known plaintext length.
- S = number of matching candidate keys requiring full decryption.
Security Analysis
The project demonstrates that the hybrid cipher can be recovered through the implemented known-plaintext attack under the tested conditions.

Identified limitations include:
- The Vigenere key is repeated.
- The same key and Affine parameters are reused.
- The Progressive Affine transformation is mathematically predictable.
- The cipher does not provide modern authenticated-encryption protections or secure randomized initialization.
Suggested improvements discussed in the report include using randomly generated keys, introducing a random starting offset, avoiding key reuse, and using modern authenticated encryption such as AES-GCM or ChaCha20-Poly1305 for real-world applications.
Requirements
- Python 3.x
- No third-party Python packages are required; the program uses Python standard-library modules:
  - time
  - random
  - string
  - math
How to Run
1. Clone or download this repository.
2. Open a terminal in the project directory.
3. Run:
python NIS_Project.py
4. Enter a plaintext containing English letters A–Z. The program converts lowercase letters to uppercase; do not include internal spaces or symbols.
5. When prompted, enter a known plaintext prefix that matches the beginning of the plaintext. At least 11 characters are required; 55 or more are recommended.
The program then displays the encryption stages, decryption result, known-plaintext attack results, Shift Cipher baseline, performance comparison, and time-complexity analysis.
Input Format
The program converts the entered text to uppercase automatically and accepts non-empty English alphabetic text (A–`Z`) only. Internal spaces, numbers, and symbols are not accepted.

Disclaimer
This project is intended for academic learning and demonstration of classical cryptographic techniques and a known-plaintext attack. Classical ciphers are not secure for modern applications. Do not use this implementation to protect confidential or sensitive data.
