const { PasswordHasher } = require('../src/passwordHasher');

test('round trip', async () => {
  const hasher = new PasswordHasher();
  const hash = await hasher.hash('correct horse battery staple');
  expect(await hasher.verify('correct horse battery staple', hash)).toBe(true);
});

test('rejects wrong password', async () => {
  const hasher = new PasswordHasher();
  const hash = await hasher.hash('correct-password');
  expect(await hasher.verify('wrong-password', hash)).toBe(false);
});

test('needs rehash detects weaker params', async () => {
  const weak = new PasswordHasher({ memoryCostKiB: 8 * 1024, timeCost: 2, parallelism: 1 });
  const hash = await weak.hash('password');

  const strong = new PasswordHasher();
  expect(await strong.needsRehash(hash)).toBe(true);
});

test('rejects empty password', async () => {
  await expect(new PasswordHasher().hash('')).rejects.toThrow(TypeError);
});
