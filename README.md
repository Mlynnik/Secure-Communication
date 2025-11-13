# Secure-Communication

## instruction
1. run ca (Certification authority)
2. run server
3. run client
* note1: The first step is required to sign the server certificate. it only needs to be executed for the first launch, or in the case of a change in the server's public key.
* note2: You should configure FindGMP.cmake for gmp library. The default settings may also work if you have used the standard Linux installation of the library.
* note3: If the internal terminal of the IDE does not wait for input when exchanging messages between server and client, use the system terminal to launch them.
* note4: This is an educational example and is not safe for real use.
