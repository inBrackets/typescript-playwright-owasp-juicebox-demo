import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';

// OWASP A09:2021 – Security Logging and Monitoring Failures
// Verifies that internal server logs and operational metrics are not
// exposed to unauthenticated external users.

test.describe('Observability Failures (OWASP A09:2021)', () => {

  // Access Log — https://pwning.owasp-juice.shop/companion-guide/latest/part2/observability-failures.html#_gain_access_to_any_access_log_file_of_the_server
  test('Access Log: server access logs must not be publicly downloadable', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/support/logs');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'Server access logs must not be served to unauthenticated requests'
    ).toBe(true);
  });

  // Exposed Metrics — https://pwning.owasp-juice.shop/companion-guide/latest/part2/observability-failures.html#_find_the_endpoint_that_serves_usage_data_to_be_scraped_by_a_popular_monitoring_system
  test('Exposed Metrics: Prometheus /metrics endpoint must not be publicly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/metrics');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403, 404].includes(res.status()),
      'Prometheus metrics endpoint must require authentication — not return 200 to anonymous requests'
    ).toBe(true);
  });

  // Leaked Access Logs — https://pwning.owasp-juice.shop/companion-guide/latest/part2/observability-failures.html#_dumpster_dive_the_internet_for_a_leaked_password_and_log_in_to_the_original_user_account_it_belongs_to
  test('Leaked Access Logs: access logs must not be accessible via the FTP directory', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
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
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/ftp/suspicious_errors.yml');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Misplaced signature or error-log file must not be publicly downloadable'
    ).not.toBe(200);
  });

});
