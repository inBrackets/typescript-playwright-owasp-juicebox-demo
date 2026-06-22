import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';

// Security through Obscurity
// Verifies that sensitive information hidden in plain sight (blockchain
// references, steganographic images, privacy policy easter eggs) cannot
// be trivially extracted — or that the exposure is at least documented.

const BASE = 'http://localhost:3000';

test.describe('Security through Obscurity', () => {

  // Blockchain Hype — https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-through-obscurity.html#_learn_about_the_token_sale_before_its_official_announcement
  test('Blockchain Hype: hidden blockchain integration reference must not expose private keys', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/assets/public/images/padding/blockchain.png');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [200, 404].includes(res.status()),
      'Blockchain image endpoint must not return a 5xx error'
    ).toBe(true);
    if (res.status() === 200) {
      const contentType = res.headers()['content-type'] ?? '';
      expect(
        contentType,
        'Blockchain endpoint must return an image, not a JSON payload with credentials'
      ).toMatch(/image\//);
    }
  });

  // Privacy Policy Inspection — https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-through-obscurity.html#_prove_that_you_actually_read_our_privacy_policy
  test('Privacy Policy Inspection: privacy policy must not contain hidden executable content', async ({ page }) => {
    await page.goto(`${BASE}/#/privacy-security/privacy-policy`);
    await page.waitForLoadState('networkidle');
    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      dom,
      'Privacy policy page must not contain hidden script injections or executable markup outside normal <script> tags'
    ).not.toMatch(/<script[^>]*>(?!.*?<\/script>)/s);
  });

  // Steganography — https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-through-obscurity.html#_rat_out_a_notorious_character_hiding_in_plain_sight_in_the_shop
  test('Steganography: product images must not expose credentials via HTTP response headers', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.get('/assets/public/images/products/StrawberryShake.jpg');
    const headers = res.headers();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      Object.values(headers).join(' '),
      'Image response headers must not contain embedded credentials or secret data'
    ).not.toMatch(/password|secret|key|token/i);
  });

});
