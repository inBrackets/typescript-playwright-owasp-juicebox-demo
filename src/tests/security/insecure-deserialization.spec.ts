import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A08:2021 – Software and Data Integrity Failures (Insecure Deserialization)
// Verifies that the server rejects malformed serialised payloads that could
// cause denial-of-service via memory exhaustion or remote code execution.

const BASE = 'http://localhost:3000';

test.describe('Insecure Deserialization (OWASP A08:2021)', () => {

  let adminToken: string;
  let userToken: string;
  let userId: number = 0;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    [adminToken, userToken] = await Promise.all([
      auth.loginAsAdmin(),
      auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!'),
    ]);
    userId = AuthHelper.getUserId(userToken) ?? 0;
  });

  // Blocked RCE DoS — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/insecure-deserialization.html#_perform_a_remote_code_execution_that_would_keep_a_less_hardened_application_busy_forever
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_remote_code_execution_that_would_keep_a_less_hardened_application_busy_forever
  test('Blocked RCE DoS: node-serialize IIFE payload in B2B order must not be executed', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The actual attack surface is the B2B XML/JSON order endpoint which deserialises the
    // order body using node-serialize — a library that evaluates _$$ND_FUNC$$_ IIFEs.
    // Sending the payload as the 'quantity' field triggers deserialisation.
    const rceJson = JSON.stringify({
      orderLines: [
        {
          productId: 1,
          quantity: '_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()',
          customerReference: 'rce-test',
        },
      ],
    });
    const res = await client.postRaw('/b2b/v2/orders', rceJson, 'application/json', userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // A 200 means the RCE payload was deserialised and the order accepted — node-serialize is unpatched.
    expect(
      res.status(),
      'node-serialize IIFE in B2B order must be rejected — a 200 means RCE is exploitable'
    ).not.toBe(200);
  });

  // Memory Bomb — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/insecure-deserialization.html#_drop_some_explosive_data_into_a_vulnerable_file_handling_endpoint
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_drop_some_explosive_data_into_a_vulnerable_file_handling_endpoint
  test('Memory Bomb: large zip upload must be rejected before causing memory exhaustion', async ({ request }) => {
    // The Memory Bomb challenge targets the file-upload endpoint, not the login endpoint.
    // Upload a 5 MB file (well above Juice Shop's ~100 KB limit) to verify the server rejects
    // it before attempting decompression — a real zip bomb exploits the compression ratio.
    const largeBuf = Buffer.alloc(5 * 1024 * 1024, 0);
    const startMs = Date.now();
    const res = await request.post(`${BASE}/file-upload`, {
      headers: { Authorization: `Bearer ${adminToken}` },
      multipart: { file: { name: 'bomb.zip', mimeType: 'application/zip', buffer: largeBuf } },
    });
    const elapsedMs = Date.now() - startMs;
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [400, 413, 422, 500].includes(res.status()),
      'Oversized zip upload must be rejected (413) before causing a memory issue — not return 200'
    ).toBe(true);
    expect(elapsedMs, 'Server must not hang while processing a large upload').toBeLessThan(30_000);
  });

  // Successful RCE DoS — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/insecure-deserialization.html#_perform_a_remote_code_execution_that_occupies_the_server_for_a_while_without_using_infinite_loops
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_perform_a_remote_code_execution_that_occupies_the_server_for_a_while_without_using_infinite_loops
  test('Successful RCE DoS: node-serialize RCE via profile image URL must be blocked', async ({ request }) => {
    expect(userId, 'userId must be non-zero to test the RCE endpoint').toBeGreaterThan(0);
    const client = new JuiceShopApiClient(request);
    const rceUrl = '_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()';
    const res = await client.put(`/api/Users/${userId}`, { profileImage: rceUrl }, userToken);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'RCE payload as profileImage URL must be rejected or sanitised'
    ).not.toBe(200);
  });

});
