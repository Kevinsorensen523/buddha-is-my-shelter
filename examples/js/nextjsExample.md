# Next.js Usage Example

Two separate pieces, because they run in two different places.

## Client Component (`'use client'`) — browser-safe subset only

```tsx
'use client';

import { isValidEmail, escapeHtml } from '@kevinsorensen523/buddha-is-my-shelter/browser';

export function SignupForm() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!isValidEmail(email)) {
      setError('Enter a valid email address');
      return;
    }
    // client-side email format check is UX only -- the server action
    // below re-validates; never trust client-side validation alone.
    submitAction(email);
  }

  // ...
}
```

## Server Action (`'use server'`, Node.js runtime) — main export

```ts
'use server';

import { PasswordHasher, isValidEmail } from '@kevinsorensen523/buddha-is-my-shelter';

const hasher = new PasswordHasher();

export async function signup(email: string, password: string) {
  if (!isValidEmail(email)) {
    throw new Error('Invalid email');
  }
  const passwordHash = await hasher.hash(password);
  // ... store email + passwordHash in your database
}
```

Server Actions run in the Node.js runtime by default, so the main export
(which needs Node's `crypto` and the native `argon2` addon) works fine
here. It would **not** work if this action were forced onto the Edge
Runtime -- see [../README.md](../README.md) (or the JS package's own
README, "Browser & Next.js Usage") for why, and what to use instead.

## What NOT to do

```tsx
'use client';
// ❌ This will fail to bundle (Node built-ins aren't available in the
// browser) even if it somehow did run, you'd be hashing passwords and
// holding secrets in code any visitor can read via devtools.
import { PasswordHasher } from '@kevinsorensen523/buddha-is-my-shelter';
```
