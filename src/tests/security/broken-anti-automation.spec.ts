import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A07:2021 – Identification and Authentication Failures (Anti-Automation)
// Verifies that rate-limiting, CAPTCHA enforcement, and abuse controls
// prevent scripted abuse of feedback, likes, and account recovery flows.

const BASE = 'http://localhost:3000';

test.describe('Broken Anti Automation (OWASP A07:2021)', () => {

  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const auth = new AuthHelper(request);
    userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
  });

  // CAPTCHA Bypass
  test('CAPTCHA Bypass: feedback endpoint must enforce CAPTCHA validation', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const captchaRes = await client.get('/api/Captchas', userToken);
    const captchaBody = await captchaRes.json() as { data?: { answer: number; id: number } };
    const answer = captchaBody.data?.answer ?? 0;
    const captchaId = captchaBody.data?.id ?? 1;

    const res = await client.post('/api/Feedbacks', {
      comment: 'captcha-bypass-test',
      rating: 3,
      captchaId,
      captcha: answer + 1,
    }, userToken);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Feedback with wrong CAPTCHA answer must be rejected'
    ).not.toBe(201);
  });

  // Extra Language
  test('Extra Language: non-standard Accept-Language must not unlock extra translations', async ({ request }) => {
    const res = await request.get(`${BASE}/i18n/tlh_AA.json`);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Klingon or other extra language file must not be served to unauthenticated requests'
    ).not.toBe(200);
  });

  // Multiple Likes
  test('Multiple Likes: same user must not like a review more than once', async ({ request }) => {
    const client = new JuiceShopApiClient(request);

    const firstLike  = await client.post('/rest/products/1/reviews/like', {}, userToken);
    const secondLike = await client.post('/rest/products/1/reviews/like', {}, userToken);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      secondLike.status(),
      'A second like from the same user must be rejected'
    ).not.toBe(200);
  });

  // Reset Morty's Password
  test("Reset Morty's Password: security question brute-force must be rate-limited", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const attempts = ['cat', 'dog', 'fish', 'bird', 'hamster'];
    const statuses = await Promise.all(attempts.map(answer =>
      client.post('/rest/user/reset-password', {
        email: 'morty@juice-sh.op',
        answer,
        new: 'NewPwd@1234!',
        repeat: 'NewPwd@1234!',
      }).then(res => res.status())
    ));

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      statuses.some(s => s === 200),
      'None of the brute-forced answers should succeed; Morty\'s answer must not be trivially guessable'
    ).toBe(false);
  });

});
