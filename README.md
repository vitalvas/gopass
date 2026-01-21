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
| Encryption | Symmetric (AES-256-GCM) | Asymmetric (GPG) |
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

GoPass uses the `AES-256-GCM` algorithm for encryption with `BLAKE2b-256` for key derivation. The system represents itself as a key-value store.

Encryption and decryption occurs on the cli side, which allows you to protect data during transmission and storage.

The key and values are encrypted in a special way. The key is encrypted using a hash from the passphrase. The values are encrypted using a hash of the key and passphrase combination, which reduces the ability for an attacker to track key movements.
