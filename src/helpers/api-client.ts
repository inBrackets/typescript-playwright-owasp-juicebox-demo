import { type APIRequestContext, type APIResponse } from '@playwright/test';

export class JuiceShopApiClient {
  private readonly base: string;

  constructor(
    private readonly request: APIRequestContext,
    base: string = 'http://localhost:3000'
  ) {
    this.base = base;
  }

  async login(email: string, password: string): Promise<string> {
    const res = await this.request.post(`${this.base}/rest/user/login`, {
      data: { email, password },
    });
    if (!res.ok()) return '';
    const body = await res.json() as { authentication?: { token: string } };
    return body.authentication?.token ?? '';
  }

  async register(
    email: string,
    password: string,
    extra: Record<string, unknown> = {}
  ): Promise<APIResponse> {
    return this.request.post(`${this.base}/api/Users`, {
      data: { email, password, passwordRepeat: password, ...extra },
    });
  }

  async get(path: string, token?: string): Promise<APIResponse> {
    return this.request.get(`${this.base}${path}`, { headers: this.auth(token) });
  }

  async post(path: string, data: unknown, token?: string): Promise<APIResponse> {
    return this.request.post(`${this.base}${path}`, {
      data,
      headers: this.auth(token),
    });
  }

  async postRaw(
    path: string,
    body: string,
    contentType: string,
    token?: string
  ): Promise<APIResponse> {
    return this.request.post(`${this.base}${path}`, {
      data: body,
      headers: { 'Content-Type': contentType, ...this.auth(token) },
    });
  }

  async put(path: string, data: unknown, token?: string): Promise<APIResponse> {
    return this.request.put(`${this.base}${path}`, {
      data,
      headers: this.auth(token),
    });
  }

  async patch(path: string, data: unknown, token?: string): Promise<APIResponse> {
    return this.request.patch(`${this.base}${path}`, {
      data,
      headers: this.auth(token),
    });
  }

  async delete(path: string, token?: string): Promise<APIResponse> {
    return this.request.delete(`${this.base}${path}`, { headers: this.auth(token) });
  }

  private auth(token?: string): Record<string, string> {
    return token ? { Authorization: `Bearer ${token}` } : {};
  }
}
