import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';

// Security through Obscurity
// Verifies that sensitive information hidden in plain sight (blockchain
// references, steganographic images, privacy policy easter eggs) cannot
// be trivially extracted — or that the exposure is at least documented.

const BASE = 'http://localhost:3000';

test.describe('Security through Obscurity', () => {

  // Blockchain Hype — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-through-obscurity.html#_learn_about_the_token_sale_before_its_official_announcement
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_learn_about_the_token_sale_before_its_official_announcement
  test('Blockchain Hype: hidden blockchain announcement page must not be publicly accessible', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The token sale is announced via a hidden blockchain.png reference — its existence IS the vulnerability.
    const res = await client.get('/assets/public/images/padding/blockchain.png');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // A 200 means the hidden blockchain image (which reveals the premature announcement) is accessible.
    expect(
      res.status(),
      'Hidden blockchain reference image must not be publicly accessible — its existence leaks the token sale'
    ).not.toBe(200);
  });

  // Privacy Policy Inspection — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-through-obscurity.html#_prove_that_you_actually_read_our_privacy_policy
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_prove_that_you_actually_read_our_privacy_policy
  test('Privacy Policy Inspection: privacy policy must not contain hidden executable content', async ({ page }) => {
    await page.goto(`${BASE}/#/privacy-security/privacy-policy`);
    await page.waitForLoadState('networkidle');
    const dom = await page.content();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // The privacy policy contains a hidden clickable element (easter egg) — detect invisible/zero-size interactives.
    expect(
      dom,
      'Privacy policy must not contain hidden interactive elements (invisible text or zero-opacity clickable areas)'
    ).not.toMatch(/cursor\s*:\s*pointer[^"']*opacity\s*:\s*0|opacity\s*:\s*0[^"']*cursor\s*:\s*pointer/i);
  });

  // Steganography — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-through-obscurity.html#_rat_out_a_notorious_character_hiding_in_plain_sight_in_the_shop
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_rat_out_a_notorious_character_hiding_in_plain_sight_in_the_shop
  test('Steganography: product image binary data must not contain embedded plaintext credentials', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    // The 20th-anniversary product image (20th.jpeg) is the steganographic carrier.
    // All other product JPEGs are under 260 KB; this image is ~1.5 MB because steghide
    // has embedded hidden content inside its pixel LSBs. The file size is the only
    // reliable indicator without running the steghide CLI tool.
    const res = await client.get('/assets/public/images/products/20th.jpeg');
    if (res.status() !== 200) return;
    const bodyBytes = await res.body();
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    // A size above 500 KB means the image carries steganographically embedded hidden data —
    // all legitimate product JPEGs are under 260 KB; 20th.jpeg is ~1.5 MB with steghide content.
    expect(
      bodyBytes.length,
      'Product JPEG must not exceed 500 KB — a size above 500 KB indicates steghide-embedded hidden content in the pixel data'
    ).toBeLessThan(500_000);
  });

});
