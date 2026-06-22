import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A05:2021 – Security Misconfiguration / XXE
// Verifies that the XML order endpoint rejects external entity declarations
// and does not resolve them (data access) or use them to exhaust resources (DoS).
//
// NOTE: The Juice Shop companion guide states that both XXE challenges are
// unavailable when Juice Shop runs in Docker (segfault from aggressive XML parsing).
// These tests assert the BLOCKED state; against a hardened deployment both must pass.

test.describe('XXE – XML External Entity Injection (OWASP A05:2021)', () => {

  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // XXE Data Access
  test('XXE Data Access: XML order endpoint must not resolve external entity file references', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const xxePayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<batchRequest>
  <order>
    <quantity>1</quantity>
    <product>&xxe;</product>
    <price>1.99</price>
  </order>
</batchRequest>`;

    const res = await client.postRaw('/b2b/v2/orders', xxePayload, 'application/xml', userToken);
    const body = await res.text();

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'XXE entity must not be resolved — /etc/passwd content must not appear in the response'
    ).not.toMatch(/root:x:|\/bin\/bash|nobody:x:/);
  });

  // XXE DoS
  test('XXE DoS: billion-laughs XML payload must be rejected before causing resource exhaustion', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const billionLaughs = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<batchRequest><order><quantity>&lol4;</quantity><product>Juice</product><price>1</price></order></batchRequest>`;

    const startMs = Date.now();
    const res = await client.postRaw('/b2b/v2/orders', billionLaughs, 'application/xml', userToken);
    const elapsedMs = Date.now() - startMs;

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 413, 422, 503].includes(res.status()),
      'Billion-laughs payload must be rejected before processing; must not return 200'
    ).toBe(true);

    expect(
      elapsedMs,
      'Server must reject the DoS payload quickly — not hang for >10 seconds'
    ).toBeLessThan(10_000);
  });

});
