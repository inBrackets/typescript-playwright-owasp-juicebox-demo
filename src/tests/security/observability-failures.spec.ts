import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';

// OWASP A09:2021 – Security Logging and Monitoring Failures
// Verifies that internal server logs and operational metrics are not
// exposed to unauthenticated external users.

const BASE = 'http://localhost:3000';

test.describe('Observability Failures (OWASP A09:2021)', () => {

  // Access Log
  test('Access Log: server access logs must not be publicly downloadable', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    const res = await client.get('/support/logs');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'Server access logs must not be served to unauthenticated requests'
    ).toBe(true);
  });

  // Exposed Metrics
  test('Exposed Metrics: Prometheus /metrics endpoint must not be publicly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    const res = await client.get('/metrics');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Prometheus metrics endpoint must require authentication — not return 200 to anonymous requests'
    ).not.toBe(200);
  });

  // Leaked Access Logs
  test('Leaked Access Logs: access logs must not be accessible via the FTP directory', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    const res = await client.get('/ftp/');
    const body = await res.text();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'FTP directory listing must not expose access log files'
    ).not.toMatch(/access.*\.log|server\.log/i);
  });

  // Misplaced Signature File
  test('Misplaced Signature File: signature file must not be publicly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request, BASE);
    const res = await client.get('/ftp/suspicious_errors.yml');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Misplaced signature or error-log file must not be publicly downloadable'
    ).not.toBe(200);
  });

});
