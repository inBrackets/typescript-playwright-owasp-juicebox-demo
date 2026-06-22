import { type APIRequestContext } from '@playwright/test';
import { JuiceShopApiClient } from './api-client';

export const ADMIN_EMAIL    = 'admin@juice-sh.op';
export const ADMIN_PASSWORD = 'admin123';

export class AuthHelper {
  private readonly client: JuiceShopApiClient;

  constructor(request: APIRequestContext) {
    this.client = new JuiceShopApiClient(request);
  }

  async loginAsAdmin(): Promise<string> {
    return this.client.login(ADMIN_EMAIL, ADMIN_PASSWORD);
  }

  async registerAndLogin(email: string, password: string): Promise<string> {
    await this.client.register(email, password);
    return this.client.login(email, password);
  }

  static uniqueEmail(): string {
    return `test-${Date.now()}@pwtest.local`;
  }
}
