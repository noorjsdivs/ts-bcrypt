# ts-bcrypt

**Optimized, zero-dependency `bcrypt`-compatible password hashing for TypeScript and Node.js.**

`ts-bcrypt` provides a drop-in replacement API for `bcrypt` and `bcryptjs` while being built entirely on Node.js native `crypto` (using PBKDF2), making it extremely lightweight, secure, and requiring **no native compilation**.

[![npm version](https://badge.fury.io/js/ts-bcrypt.svg)](https://badge.fury.io/js/ts-bcrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg)](http://www.typescriptlang.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/☕-Buy%20me%20a%20coffee-orange.svg?style=flat&logo=buy-me-a-coffee)](https://buymeacoffee.com/reactbd)

## Why ts-bcrypt?

- **📦 Zero Dependencies**: Built using only Node.js built-in `crypto` module.
- **🔄 Bcrypt API Compatible**: Switch from `bcrypt` or `bcryptjs` instantly.
- **🛠️ Fully Typed**: Written in TypeScript with complete type definitions included.
- **⚡ Async & Sync**: Full support for both Promise-based and synchronous usage.
- **🔒 Secure Defaults**: Uses industry-standard PBKDF2 with SHA-256.

## Comparison

| Feature                | **ts-bcrypt**           | **bcrypt**              | **bcryptjs**            | **argon2**            |
| :--------------------- | :---------------------- | :---------------------- | :---------------------- | :-------------------- |
| **Algorithm**          | PBKDF2 (SHA-256)        | Blowfish                | Blowfish                | Argon2                |
| **Native Compilation** | ✅ **Not Required**     | ⚠️ **Required** (gyp)   | ✅ **Not Required**     | ⚠️ **Required** (gyp) |
| **Dependencies**       | **0**                   | ~14                     | ~0                      | ~10                   |
| **Package Size**       | **~10 KB**              | ~500 KB                 | ~300 KB                 | ~800 KB               |
| **Environment**        | Node.js                 | Node.js                 | Node.js / Browser       | Node.js               |
| **TypeScript**         | Native                  | `@types/bcrypt`         | `@types/bcryptjs`       | Native                |
| **API Style**          | Promise, Callback, Sync | Promise, Callback, Sync | Promise, Callback, Sync | Promise               |

> **Note**: `ts-bcrypt` uses **PBKDF2** (Password-Based Key Derivation Function 2) instead of the Blowfish-based algorithm used by standard `bcrypt`. This ensures smaller size and native performance without C++ bindings, but means hashes are **not compatible** with standard bcrypt hashes (you cannot verify a standard bcrypt hash with this library). However, the **API is identical**, making it perfect for new projects or complete migrations.

## Installation

```bash
npm install ts-bcrypt
```

Or using yarn/pnpm/bun:

```bash
yarn add ts-bcrypt
pnpm add ts-bcrypt
bun add ts-bcrypt
```

## Usage

The API is designed to be a drop-in replacement for `bcrypt`.

### Hashing Passwords (Async)

```typescript
import bcrypt from "ts-bcrypt";

// Using Promises (Recommended)
async function registerUser(password: string) {
  const hash = await bcrypt.hash(password, 10);
  // Store hash in database...
}

// Using Callbacks
bcrypt.hash("myPassword", 10, (err, hash) => {
  if (err) throw err;
  console.log(hash);
});
```

### Verifying Passwords (Async)

```typescript
import bcrypt from "ts-bcrypt";

async function loginUser(password: string, hashFromDb: string) {
  const isMatch = await bcrypt.compare(password, hashFromDb);

  if (isMatch) {
    // Login successful
  } else {
    // Invalid credentials
  }
}
```

### Synchronous Usage

Useful for scripts or seeding where blocking the event loop is acceptable.

```typescript
import bcrypt from "ts-bcrypt";

const hash = bcrypt.hashSync("myPassword", 10);
const isMatch = bcrypt.compareSync("myPassword", hash);
```

### Auto-generating Salts

```typescript
import bcrypt from "ts-bcrypt";

// Separate salt generation
const salt = await bcrypt.genSalt(10);
const hash = await bcrypt.hash("password", salt);
```

## Extra Features

`ts-bcrypt` includes bonus utilities for password strength and generation.

### Password Strength Analysis

```typescript
import { isStrongPassword, calculatePasswordStrength } from "ts-bcrypt";

if (!isStrongPassword("weak")) {
  console.log("Password is too weak!");
}

const strength = calculatePasswordStrength("My$ecureP@ssw0rd");
console.log(strength.score); // 95
```

### Secure Password Generation

```typescript
import { generateSecurePassword } from "ts-bcrypt";

const newPassword = generateSecurePassword(16);
```

## API Reference

### Core Methods (Bcrypt Compatible)

- `hash(data, saltOrRounds, [cb])`: Asynchronously generates a hash for the given string.
- `hashSync(data, saltOrRounds)`: Synchronously generates a hash.
- `compare(data, encrypted, [cb])`: Asynchronously compares data with the hash.
- `compareSync(data, encrypted)`: Synchronously compares data with the hash.
- `genSalt(rounds, [cb])`: Asynchronously generates a salt.
- `genSaltSync(rounds)`: Synchronously generates a salt.
- `getRounds(encrypted)`: Returns the number of rounds used for validation.

### Utility Methods

- `isStrongPassword(password, [options])`: Validates password complexity.
- `generateSecurePassword([length, options])`: Generates a random strong password.
- `calculatePasswordStrength(password)`: Returns a score (0-100) and feedback.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Inspired by:

- [bcrypt](https://www.npmjs.com/package/bcrypt)
- [bcryptjs](https://www.npmjs.com/package/bcryptjs)

## 📞 Support

If you have any questions or need help, please:

- Open an issue on [GitHub](https://github.com/noorjsdivs/ts-bcrypt/issues)

## 🎉 Show Your Support

If this library helped you, please give it a ⭐️ on GitHub!

You can also support the development of this project by buying me a coffee:

<a href="https://buymeacoffee.com/reactbd" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" >
</a>

---

[Made with ❤️ by Noor Mohammad](https://reactbd.com)
