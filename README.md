# Cryptosytem-implementation-Secure-Socker-Layer-Implementation
Implementation of Cryptosystem for secure communication between two entities on a network.

In this Project,I have implemented a complete cryptosystem to provide end-to-
end security between different entities on network. Have implemented different cryptographic mechanisms including confidentiality, integrity, authentication (user aswell as data) and non-repudiation. This will be done into three stages:

Stage 1:

In stage 1, whenever two entities start communication, their communication
will start with handshaking. During handshaking process, they will share their
cipher suite to each other. This cipher suite includes all the cryptographic
mechanisms included on their sides. Both entities will negotiate and
select/agree on subset of cryptographic mechanism they will use for further
secure communication.
Stage 1 is very important and requires a complete
dialogue for sharing and agreement of cipher suite. Have defined a
complete protocol for this process: Utilized RSA, AES, Diffie Hellman, DS and HMAC as the cipher suite in one peer. And AES, DS and Diffie Hellman in the other. 


Remember 1: A cipher suite is a set of algorithms that help secure a network
connection. This includes mechanisms for key exchange, confidentiality,
authentication, message authentication, digital signature etc.

Stage 2:

In stage 2, each entity will generate their respective and required security
credentials (Security Keys, IV etc.). These credentials will be exchanged
between the both and will be used for establishing a secure session.

Stage 3:

In stage 3, secure transactions (transmission of data) will be done between
both entities by using security mechanisms agreed in stage 1 and security
credentials generated in stage 2. After successful transaction, secure session
will be closed.

Remember 2: Stage 1 is used only once, but stage 2 and 3 can be repeated for
multiple transactions.
