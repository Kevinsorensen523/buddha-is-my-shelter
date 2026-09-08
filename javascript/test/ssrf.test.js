const { isPrivateOrReservedIp, isPublicHttpUrl } = require('../src/ssrf');

test('isPrivateOrReservedIp flags private/reserved addresses', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '::1', 'fe80::1']) {
    expect(isPrivateOrReservedIp(ip)).toBe(true);
  }
});

test('isPrivateOrReservedIp allows public addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1']) {
    expect(isPrivateOrReservedIp(ip)).toBe(false);
  }
});

test('isPublicHttpUrl rejects non-http(s) scheme without DNS lookup', async () => {
  expect(await isPublicHttpUrl('javascript:alert(1)')).toBe(false);
});

test('isPublicHttpUrl rejects localhost', async () => {
  expect(await isPublicHttpUrl('http://localhost/')).toBe(false);
  expect(await isPublicHttpUrl('http://127.0.0.1/')).toBe(false);
});
