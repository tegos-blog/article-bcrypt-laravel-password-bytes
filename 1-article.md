I expected bcrypt to silently drop characters past 72. I did not expect it to bake in half an emoji.

That's what happens with a specific password combination I tested. The original password still works. But strip the emoji (a password manager, a different keyboard, a Unicode normalizer) and you're locked out. Your Laravel validator passed it as valid the whole time.

## The 72-Byte Rule

bcrypt has a hard input limit of 72 bytes. Not characters - bytes.

When you call `password_hash($password, PASSWORD_BCRYPT)`, PHP silently truncates anything past byte 72. Most developers know this in theory. But for ASCII-only apps, it never bites. 72 ASCII characters is already a very long password, and the silent clip is harmless in practice.

The trouble starts with multi-byte scripts.

## How Many Characters Fit?

| Character set | Bytes per char | Effective bcrypt limit |
|---|---|---|
| ASCII | 1 | 72 chars |
| Cyrillic | 2 | 36 chars |
| CJK (Chinese, Japanese, Korean, common block) | 3 | 24 chars |
| Emoji | 4 | 18 chars |

Past the byte limit, a longer password adds no security at all. A 200-character Cyrillic password hashes identically to its own first 36 characters. Byte 73 and beyond simply do not exist from bcrypt's point of view. So "longer always produces a stronger bcrypt hash" is not true.

A Cyrillic user with a 37-character password gets silently truncated at char 36. The hash is still consistent. The user logs in fine, but any variation past character 36 doesn't matter to bcrypt. Annoying from a security standpoint, but it does not break login.

## The Split-Byte Trap

The 72-byte limit cuts at a byte boundary, not a character boundary. If a multi-byte character falls on that cut, bcrypt bakes in an incomplete UTF-8 sequence.

```php
// 35 Cyrillic chars = 70 bytes, emoji = 4 bytes, total = 74 bytes
$password = str_repeat('А', 35) . '🔑';
$hash = password_hash($password, PASSWORD_BCRYPT);

password_verify($password, $hash);           // ?
password_verify(str_repeat('А', 35), $hash); // ?
password_verify(str_repeat('А', 36), $hash); // ?
```

```plaintext
// PHP 8.4, Laravel sandbox:
verify(original 74 bytes):          bool(true)
verify(trimmed 35 Cyrillic, 70 bytes): bool(false)
verify(36 Cyrillic, 72 bytes):      bool(false)
```

The original full string still verifies. bcrypt truncates it to the same 72 bytes on both sides. But every other attempt fails.

What happened: bcrypt stored 70 Cyrillic bytes plus the first 2 bytes of the 4-byte emoji (F0 9F from the sequence F0 9F 94 91). That's the effective password now. The trailing emoji looks like decoration, but it's load-bearing.

I tested this in my Laravel sandbox across several character sets:

| Input | Total bytes | Original verifies? | Cyrillic-only verifies? |
|---|---|---|---|
| 36x Cyrillic + extra chars | 72+2 | yes | yes |
| 24x CJK + extra chars | 72+3 | yes | yes |
| 18x emoji + extra chars | 72+4 | yes | yes |
| 35x Cyrillic + 1 emoji | 74 | yes | **no** |

For most overflow cases both the original and any Cyrillic-only variant work - the clip is harmless. With the split-byte case, only the exact original string works. A user who enters "35 Cyrillic chars" thinking the emoji was decoration is locked out. That happens when a password manager strips the emoji, a keyboard can't type it, or the app normalizes Unicode on input.

## What Laravel Does About It

Laravel's `Password::max()` uses `mb_strlen()` under the hood. That counts characters, not bytes.

```php
// Looks safe. Is not.
'password' => Password::min(8)->max(72),
```

A 37-char Cyrillic password: `mb_strlen` = 37, passes your validator. `strlen` = 74. bcrypt gets 74 bytes and clips at 72. Depending on where the boundary lands, the user either gets silent truncation or the split-byte lockout.

Laravel 12 added a `BCRYPT_LIMIT` config option in `config/hashing.php`:

```php
// config/hashing.php
'bcrypt' => [
    'rounds' => env('BCRYPT_ROUNDS', 12),
    'limit'  => env('BCRYPT_LIMIT', 72),
],
```

Heads up: `BCRYPT_LIMIT` was introduced in Laravel 12. On Laravel 11 and below, you need to handle this yourself.

When set, Laravel's bcrypt driver throws an `InvalidArgumentException` if the password exceeds 72 bytes. That prevents silent truncation. But it does not close the validation gap: `Password::max(72)` still accepts passwords that exceed 72 bytes, and `BCRYPT_LIMIT` then throws at hash time. Without explicit exception handling, that bubbles as a 500. Your user submitted a valid form and hits an error.

## Fix Options

Validate at the form layer, before hashing. bcrypt is intentionally slow: one unauthenticated request triggers a full key schedule regardless of input length. Without an upper bound, that cost is fixed per request whether the input is 10 bytes or 10 000. Rate limiting is still essential; the byte cap just removes wasted work on input bcrypt would ignore anyway.

### Option 1: Validate byte length directly

```php
'password' => [
    'required',
    'string',
    'min:8',
    function ($attribute, $value, $fail) {
        if (strlen($value) > 72) {
            $fail('The password is too long.');
        }
    },
],
```

`strlen()` in PHP counts bytes, not characters. This catches both the silent truncation and the split-byte case before hashing happens.

### Option 2: Switch to Argon2id

```php
// config/hashing.php
'driver' => 'argon2id',
```

No 72-byte limit. For existing users registered with bcrypt, rehash on first successful login:

```php
if (Hash::needsRehash($user->password)) {
    $user->update(['password' => Hash::make($plaintext)]);
}
```

PHP's `password_verify()` reads the algorithm from the hash directly, so existing bcrypt users can still log in after you change the default driver. Users log in fine throughout.

### Option 3: Pre-hash with SHA-256 before bcrypt

OWASP's [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) covers this pattern. Their recommended form uses HMAC with a server-side pepper:

```php
// Always produces 64 ASCII bytes - fits bcrypt comfortably
$prehashed = hash_hmac('sha256', $password, $pepper);
$stored    = password_hash($prehashed, PASSWORD_BCRYPT);

// Verify:
password_verify(hash_hmac('sha256', $input, $pepper), $stored);
```

Plain `hash('sha256', $password)` without a pepper has a known weakness: if bcrypt is cracked, the attacker gets the raw SHA-256 hash and can crack it without bcrypt's cost (password shucking). The HMAC form closes that gap. Either way, this is non-standard and adds complexity to your auth layer.

---

If you're starting a new app, use Argon2id and skip this entire problem (check `defined('PASSWORD_ARGON2ID')` first - some shared hosts and older builds lack it). If you're maintaining an existing bcrypt app, add the byte-length validator today and plan a migration to Argon2id when you have the runway.

That user from the intro (the one locked out with a valid password) hit the split-byte case. The fix is one validator rule.

## TL;DR

- bcrypt truncates at 72 **bytes**, not characters. Cyrillic caps at 36 chars, CJK at 24, emoji at 18
- If the cut falls inside a multi-byte char, the trailing emoji becomes load-bearing: original verifies, anything that strips the emoji does not
- `Password::max(72)` uses `mb_strlen` (characters, not bytes), so it does not catch this
- Laravel 12 `BCRYPT_LIMIT=72` throws at hash time but does not block invalid input at the form level
- Fix: validate with `strlen($password) > 72`, switch to Argon2id, or pre-hash with `hash_hmac('sha256', ...)`

💡 Use `strlen()` to validate password byte length. `mb_strlen()` won't catch the dangerous cases.

---

- [PHP: password_hash](https://www.php.net/manual/en/function.password-hash.php)
- [PHP: password_verify](https://www.php.net/manual/en/function.password-verify.php)
- [OWASP: Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## Author's Note

Thanks for sticking around!
Find me on [dev.to](https://dev.to/tegos), [linkedin](https://www.linkedin.com/in/ivan-mykhavko/), or check out my work on [github](https://github.com/tegos).

**Laravel, after the happy path.**
