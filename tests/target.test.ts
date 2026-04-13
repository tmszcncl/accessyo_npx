import { parseTarget } from '../src/target.js';

describe('parseTarget', () => {
  it('parses plain domain', () => {
    const parsed = parseTarget('google.com');
    expect(parsed.host).toBe('google.com');
    expect(parsed.port).toBe(443);
    expect(parsed.normalizedTarget).toBe('google.com:443');
    expect(parsed.httpTarget).toBe('https://google.com:443/');
    expect(parsed.parsedFrom).toBeUndefined();
  });

  it('parses domain with custom port', () => {
    const parsed = parseTarget('google.com:8443');
    expect(parsed.host).toBe('google.com');
    expect(parsed.port).toBe(8443);
    expect(parsed.normalizedTarget).toBe('google.com:8443');
    expect(parsed.httpTarget).toBe('https://google.com:8443/');
  });

  it('parses http URL with default port 80', () => {
    const parsed = parseTarget('http://google.com');
    expect(parsed.host).toBe('google.com');
    expect(parsed.port).toBe(80);
    expect(parsed.normalizedTarget).toBe('google.com:80');
    expect(parsed.httpTarget).toBe('http://google.com:80/');
    expect(parsed.parsedFrom).toBe('http://google.com');
  });

  it('parses https URL with default port 443', () => {
    const parsed = parseTarget('https://google.com');
    expect(parsed.host).toBe('google.com');
    expect(parsed.port).toBe(443);
    expect(parsed.normalizedTarget).toBe('google.com:443');
    expect(parsed.httpTarget).toBe('https://google.com:443/');
  });

  it('parses https URL with custom port and path', () => {
    const parsed = parseTarget('https://api.google.com:8443/v1');
    expect(parsed.host).toBe('api.google.com');
    expect(parsed.port).toBe(8443);
    expect(parsed.normalizedTarget).toBe('api.google.com:8443');
    expect(parsed.httpTarget).toBe('https://api.google.com:8443/v1');
    expect(parsed.parsedFrom).toBe('https://api.google.com:8443/v1');
  });

  it('parses api subdomain with custom port', () => {
    const parsed = parseTarget('api.example.com:8443');
    expect(parsed.host).toBe('api.example.com');
    expect(parsed.port).toBe(8443);
    expect(parsed.normalizedTarget).toBe('api.example.com:8443');
  });

  it('parses IPv4 localhost with port', () => {
    const parsed = parseTarget('127.0.0.1:8080');
    expect(parsed.host).toBe('127.0.0.1');
    expect(parsed.port).toBe(8080);
    expect(parsed.normalizedTarget).toBe('127.0.0.1:8080');
  });

  it('parses localhost with port', () => {
    const parsed = parseTarget('localhost:3000');
    expect(parsed.host).toBe('localhost');
    expect(parsed.port).toBe(3000);
    expect(parsed.normalizedTarget).toBe('localhost:3000');
    expect(parsed.httpTarget).toBe('https://localhost:3000/');
  });

  it('falls back to hostname parsing for invalid URL strings', () => {
    const parsed = parseTarget('https://bad url');
    expect(parsed.host).toBe('https://bad url');
    expect(parsed.port).toBe(443);
    expect(parsed.normalizedTarget).toBe('[https://bad url]:443');
  });
});
