/** Como tratar cada tipo de credencial exposta (usado na tela e no HTML de entrega). */
export const SECRET_INFO: Record<string, { risk: 'critical' | 'high' | 'medium' | 'info'; owner: 'Aplicação' | 'Log do WAF'; fix: string }> = {
  'Credencial em HTTP sem TLS': { risk: 'critical', owner: 'Aplicação', fix: 'Credenciais trafegando sem TLS. Forçar HTTPS e redirecionar a porta 80.' },
  'Basic Auth com senha fraca': { risk: 'critical', owner: 'Aplicação', fix: 'Usuário e senha em cada requisição, com senha curta ou previsível. Trocar a senha já e migrar para token.' },
  'Basic Auth': { risk: 'high', owner: 'Aplicação', fix: 'Usuário e senha viajam em toda requisição. Migrar para token (JWT/OAuth) e limitar tentativas.' },
  'Segredo na URL': { risk: 'high', owner: 'Aplicação', fix: 'Token ou senha na query string fica gravado em logs, proxies e histórico. Mover para o cabeçalho Authorization.' },
  'JWT com dados pessoais': { risk: 'medium', owner: 'Aplicação', fix: 'O payload do JWT é legível por qualquer um: tirar nome, e-mail e documentos; guardar só um identificador.' },
  'Cookie de sessão': { risk: 'info', owner: 'Log do WAF', fix: 'Normal na aplicação. Evitar a gravação no log: redigir o cabeçalho Cookie no logging do WAF.' },
  'JWT Bearer': { risk: 'info', owner: 'Log do WAF', fix: 'Normal na aplicação. Redigir o cabeçalho Authorization no logging do WAF.' },
  'Chave de API': { risk: 'info', owner: 'Log do WAF', fix: 'Chave de cliente em cabeçalho. Redigir no logging do WAF.' },
  'Assinatura SigV4': { risk: 'info', owner: 'Log do WAF', fix: 'Assinatura de uso único e curta. Redigir Authorization no logging do WAF.' },
};
export const RISK_STYLE: Record<string, { label: string; color: string }> = {
  critical: { label: 'Crítico', color: '#D13212' },
  high: { label: 'Alto', color: '#EC7211' },
  medium: { label: 'Médio', color: '#B7791F' },
  info: { label: 'Informativo', color: '#5F6B7A' },
};

