const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export async function createAudit(file) {
  const form = new FormData();
  form.append('file', file);
  const response = await fetch(`${API_BASE_URL}/api/audits`, { method: 'POST', body: form });
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export async function getAudit(id) {
  const response = await fetch(`${API_BASE_URL}/api/audits/${id}`);
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export function reportUrl(id) {
  return `${API_BASE_URL}/api/audits/${id}/report`;
}

async function readError(response) {
  const text = await response.text();
  try {
    const data = JSON.parse(text);
    return data.detail || text;
  } catch {
    return text || response.statusText;
  }
}
