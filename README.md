# GoPass

GoPass is a simple password manager for the command line.

## Installation

```bash
go install -v github.com/vitalvas/gopass@latest
```

## GoPass vs Pass

GoPass is a simple password manager written in Go. It is inspired by [Pass](https://www.passwordstore.org/), but is not compatible with it for the storage layer.

Cli commands are as compatible as possible (about 90%), to preserve user experience

| Feature | GoPass | Pass |
| --- | --- | --- |
| Storage | Plugin backend | Encrypted files |
| Encryption | ML-KEM-768 + AES-256-GCM | GPG |
| Post-quantum secure | Yes | No |
| Encryption key | Yes | No |
| Encryption value | Yes | Yes |
| Password generation | Yes | Yes |
| Written in | Go | Shell |

### Storage

* `file` - stores data in a tree structure of keys. Each file is an independent key. File names are encoded using lowercase base32.

## Key Format

Keys must follow a filepath-like format:

* Must start with `/`
* Length: 3-128 characters
* Allowed characters: `a-z`, `A-Z`, `0-9`, `-`, `_`, `.`, `/`
* No double slashes (`//`) or trailing slashes

Examples of valid keys:

* `/key`
* `/me/example/key`
* `/social/github.com/username`

## Security

GoPass uses post-quantum encryption with `ML-KEM-768` (FIPS 203) for key encapsulation and `AES-256-GCM` for symmetric encryption. The system represents itself as a key-value store.

Encryption and decryption occurs on the CLI side, which allows you to protect data during transmission and storage.

### Encryption scheme

1. ML-KEM-768 key pair is generated during vault initialization
2. For each encryption operation, a fresh shared secret is encapsulated using the public key
3. The 32-byte shared secret is used directly as the AES-256-GCM key
4. Values are encrypted with additional authenticated data (AAD) bound to the key name

This provides:

* Post-quantum security against future quantum computer attacks
* Forward secrecy - each encryption uses a unique shared secret
* Authenticated encryption with associated data (AEAD)
