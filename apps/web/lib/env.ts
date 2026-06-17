export const env = {
  apiBaseUrl: process.env.RELIXQ_API_BASE_URL ?? 'http://localhost:5099',
  appName: process.env.NEXT_PUBLIC_APP_NAME ?? 'Relix-Q OSS',
};

export const SESSION_COOKIE = 'relixq_session';
