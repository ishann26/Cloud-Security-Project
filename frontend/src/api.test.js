import { afterEach, expect, test, vi } from 'vitest';

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.resetModules(); });
const response = (status, body = {}) => ({ status, ok: status < 400, json: async () => body });

test('asks once for the operator key and reuses it only in memory', async () => {
  const fetch = vi.fn().mockResolvedValueOnce(response(401))
    .mockResolvedValueOnce(response(200, [])).mockResolvedValueOnce(response(200, {}));
  vi.stubGlobal('fetch', fetch);
  const prompt = vi.spyOn(window, 'prompt').mockReturnValue('operator-test-key');
  const api = await import('./api.js');
  await api.getIncidents();
  await api.loadDemo();
  expect(prompt).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0][1].headers['X-API-Key']).toBeUndefined();
  expect(fetch.mock.calls[1][1].headers['X-API-Key']).toBe('operator-test-key');
  expect(fetch.mock.calls[2][1].headers['X-API-Key']).toBe('operator-test-key');
});

test('canceling does not retry or silently change the store', async () => {
  const fetch = vi.fn().mockResolvedValue(response(401, {detail:'Key required'}));
  vi.stubGlobal('fetch', fetch);
  vi.spyOn(window, 'prompt').mockReturnValue(null);
  const api = await import('./api.js');
  await expect(api.loadDemo()).rejects.toThrow('Key required');
  expect(fetch).toHaveBeenCalledTimes(1);
});

test('a wrong key retries at most once', async () => {
  const fetch = vi.fn().mockResolvedValue(response(401));
  vi.stubGlobal('fetch', fetch);
  const prompt = vi.spyOn(window, 'prompt').mockReturnValue('wrong');
  const api = await import('./api.js');
  await expect(api.getIncidents()).rejects.toThrow('401');
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(prompt).toHaveBeenCalledTimes(1);
});

test('classroom view uses public demo routes without an operator prompt', async () => {
  vi.stubEnv('VITE_SHARED_VIEW', 'true');
  const fetch = vi.fn().mockResolvedValue(response(200, [{incident_id:'INC-SHARED'}]));
  vi.stubGlobal('fetch', fetch);
  const prompt = vi.spyOn(window, 'prompt');
  const api = await import('./api.js');
  expect(await api.getIncidents()).toHaveLength(1);
  expect(fetch.mock.calls[0][0]).toContain('/public/incidents');
  await api.loadDemo();
  expect(fetch.mock.calls[1][0]).toContain('/public/demo/load');
  await api.updateStatus('x', 'Investigating');
  expect(fetch.mock.calls[2][0]).toContain('/public/incidents/x/status');
  expect(() => api.postEvent({})).toThrow('operator access');
  expect(prompt).not.toHaveBeenCalled();
  vi.unstubAllEnvs();
});

test('shared view loads the published archive when Render is unavailable', async () => {
  vi.stubEnv('VITE_SHARED_VIEW', 'true');
  const fetch = vi.fn().mockRejectedValueOnce(new Error('sleeping'))
    .mockResolvedValueOnce(response(200, {incidents:[{incident_id:'INC-ARCHIVE'}]}));
  vi.stubGlobal('fetch', fetch);
  const api = await import('./api.js');
  const items = await api.getIncidents();
  expect(items[0].archive_fallback).toBe(true);
  expect(fetch.mock.calls[1][0]).toBe('/review-archive.json');
  vi.unstubAllEnvs();
});
