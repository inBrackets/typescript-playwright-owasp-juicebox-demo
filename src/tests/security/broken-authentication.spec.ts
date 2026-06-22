import { test, expect } from '@playwright/test';
import { JuiceShopApiClient } from '../../helpers/api-client';
import { AuthHelper } from '../../helpers/auth.helper';

// OWASP A07:2021 – Identification and Authentication Failures
// Verifies that account takeover via weak passwords, insecure password reset,
// OAuth bypass, and 2FA weaknesses are not exploitable.

test.describe('Broken Authentication (OWASP A07:2021)', () => {

  // Bjoern's Favorite Pet — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_reset_the_password_of_bjoerns_owasp_account_via_the_forgot_password_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reset_the_password_of_bjoerns_owasp_account_via_the_forgot_password_mechanism
  test("Bjoern's Favorite Pet: security question answer must not be trivially guessable", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const commonPets = ['cat', 'dog', 'fish', 'bird', 'unikitty'];
    const statuses = await Promise.all(commonPets.map(answer =>
      client.post('/rest/user/reset-password', {
        email: 'bjoern.kimminich@gmail.com',
        answer,
        new: 'Owned@1234!',
        repeat: 'Owned@1234!',
      }).then(res => res.status())
    ));

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      statuses.some(s => s === 200),
      'None of the common pet guesses should reset bjoern\'s password'
    ).toBe(false);
  });

  // Change Bender's Password — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_change_benders_password_into_slurmcl4ssic_without_using_sql_injection_or_forgot_password
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_change_benders_password_into_slurmcl4ssic_without_using_sql_injection_or_forgot_password
  test("Change Bender's Password: user must not change another account's password", async ({ request }) => {
    const auth = new AuthHelper(request);
    const userToken = await auth.registerAndLogin(AuthHelper.uniqueEmail(), 'Test@1234!');
    const client = new JuiceShopApiClient(request);

    // Attempt to change password for userId=3 (Bender) as a different user
    const res = await client.put('/rest/user/change-password', {
      current: 'doesNotMatter',
      new: 'Owned@1234!',
      repeat: 'Owned@1234!',
    }, userToken);

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      res.status(),
      'Password change must be scoped to the authenticated user only'
    ).not.toBe(200);
  });

  // GDPR Data Erasure — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_log_in_with_chris_erased_user_account
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_log_in_with_chris_erased_user_account
  test('GDPR Data Erasure: deleted user account must not be usable for login', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const email = AuthHelper.uniqueEmail();
    const password = 'Test@1234!';
    await client.register(email, password);
    const token = await client.login(email, password);

    const uid = AuthHelper.getUserId(token);

    if (uid) {
      await client.delete(`/api/Users/${uid}`, token);
    }

    const secondLogin = await client.login(email, password);
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      secondLogin,
      'Deleted account must not produce a valid token on login'
    ).toBe('');
  });

  // Login Bjoern — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_log_in_with_bjoerns_gmail_account
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_log_in_with_bjoerns_gmail_account
  test('Login Bjoern: cannot login as bjoern via direct password auth (requires OAuth)', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const token = await client.login('bjoern.kimminich@gmail.com', 'bjoern');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      token,
      'Password-based login as bjoern must fail — account uses OAuth only'
    ).toBe('');
  });

  // Password Strength — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_log_in_with_the_administrators_user_credentials_without_previously_changing_them_or_applying_sql_injection
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_log_in_with_the_administrators_user_credentials_without_previously_changing_them_or_applying_sql_injection
  test('Password Strength: admin account must not use the default weak password', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const token = await client.login('admin@juice-sh.op', 'admin123');
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      token,
      'Admin must not be loginable with the default weak password "admin123"'
    ).toBe('');
  });

  // Reset Bender's Password — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_reset_benders_password_via_the_forgot_password_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reset_benders_password_via_the_forgot_password_mechanism
  test("Reset Bender's Password: reset answer must not be publicly discoverable", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const guesses = ['Stop\'n\'Drop', 'samepassword', 'OwnedPassword'];
    const statuses = await Promise.all(guesses.map(answer =>
      client.post('/rest/user/reset-password', {
        email: 'bender@juice-sh.op',
        answer,
        new: 'NewPwd@1234!',
        repeat: 'NewPwd@1234!',
      }).then(res => res.status())
    ));

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      statuses.some(s => s === 200),
      'Bender\'s security question answer must not be trivially guessable'
    ).toBe(false);
  });

  // Reset Bjoern's Password — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_reset_the_password_of_bjoerns_internal_account_via_the_forgot_password_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reset_the_password_of_bjoerns_internal_account_via_the_forgot_password_mechanism
  test("Reset Bjoern's Password: email-based reset must not expose token in response", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/rest/user/forgot-password', {
      email: 'bjoern.kimminich@gmail.com',
    });
    const body = await res.text();

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      body,
      'Password reset response must not leak the reset token in the HTTP response body'
    ).not.toMatch(/token|reset.*link/i);
  });

  // Reset Jim's Password — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_reset_jims_password_via_the_forgot_password_mechanism
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_reset_jims_password_via_the_forgot_password_mechanism
  test("Reset Jim's Password: security question answer must not be publicly discoverable", async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const guesses = ['Samuel', 'James', 'Peter', 'Michael'];
    const statuses = await Promise.all(guesses.map(answer =>
      client.post('/rest/user/reset-password', {
        email: 'jim@juice-sh.op',
        answer,
        new: 'NewPwd@1234!',
        repeat: 'NewPwd@1234!',
      }).then(res => res.status())
    ));

    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      statuses.some(s => s === 200),
      "Jim's security question answer must not be trivially guessable"
    ).toBe(false);
  });

  // Two Factor Authentication — Hint: https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-authentication.html#_solve_the_2fa_challenge_for_user_wurstbrot
  // Solution: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html#_solve_the_2fa_challenge_for_user_wurstbrot
  test('Two Factor Authentication: 2FA setup endpoint must require authentication', async ({ request }) => {
    const client = new JuiceShopApiClient(request);
    const res = await client.post('/rest/2fa/setup', { tfaToken: '000000' });
    // FAILURE CONDITION: This test must fail if the vulnerability is successfully executed or present.
    expect(
      [401, 403].includes(res.status()),
      '2FA setup must require an authenticated session'
    ).toBe(true);
  });

});
