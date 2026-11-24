import { GoogleGenAI, type Content } from '@google/genai';
import { createAnonymizer } from './aiAnonymizer.ts';
import type {
  AiChatMessage,
  AiProviderSettings,
  AiProviderType,
  AiPublicConfig,
  AuditOverview,
  FirewallRule,
  NatPolicy,
  SyslogEvent,
} from './types.ts';

export const DEFAULT_AI_SETTINGS: AiProviderSettings = {
  provider: 'gemini',
  model: 'gemini-4-hydrogen',
  baseUrl: '',
  apiKey: '',
  anonymize: true,
};

export function maskSecret(secret: string): string {
  const trimmed = secret.trim();
  if (!trimmed) return '';
  if (trimmed.length <= 8) return '••••••••';
  return `${trimmed.slice(0, 4)}••••${trimmed.slice(-4)}`;
}

export function toPublicAiConfig(settings: AiProviderSettings): AiPublicConfig {
  return {
    provider: settings.provider,
    model: settings.model,
    baseUrl: settings.baseUrl,
    hasCustomKey: settings.apiKey.trim().length > 0,
    hasServerGeminiKey: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim().length > 0),
    maskedKey: maskSecret(settings.apiKey),
    anonymize: settings.anonymize !== false,
  };
}

function buildLogContextSnapshot(
  overview: AuditOverview,
  syslogs: SyslogEvent[],
  rules: FirewallRule[],
  nats: NatPolicy[]
): string {
  const flaggedRules = rules
    .filter((r) => r.status !== 'active')
    .slice(0, 25)
    .map(
      (r) =>
        `- [${r.id}] "${r.name}" (${r.fromZone}->${r.toZone}, ${r.source} -> ${r.destination}, svc=${r.service}, action=${r.action}) | status=${r.status} | hits_sonicos=${r.applianceHits} | hits_syslog=${r.syslogHits} | motivo: ${r.findingReason}`
    );

  const flaggedNats = nats
    .filter((n) => n.status !== 'active')
    .slice(0, 25)
    .map(
      (n) =>
        `- [${n.id}] "${n.name}" (${n.inboundInterface}->${n.outboundInterface}, orig=${n.origSource}->${n.origDestination}:${n.origService} => trans=${n.transSource}->${n.transDestination}:${n.transService}) | status=${n.status} | hits_sonicos=${n.applianceHits} | hits_syslog=${n.syslogHits} | motivo: ${n.findingReason}`
    );

  // Prioritize critical/blocked events plus recent allowed samples
  const blockedOrCritical = syslogs
    .filter(
      (ev) =>
        ev.priority <= 4 ||
        ev.action === 'drop' ||
        ev.action === 'deny' ||
        ev.action === 'reset'
    )
    .slice(0, 30);

  const recentAllow = syslogs.filter((ev) => ev.action === 'allow').slice(0, 12);
  const sampleEvents = [...blockedOrCritical, ...recentAllow].map(
    (ev) =>
      `[${ev.timestamp}] sev=${ev.severity} acao=${ev.action} ${ev.srcIp}:${ev.srcPort ?? '-'}(${ev.srcZone}) -> ${ev.dstIp}:${ev.dstPort ?? '-'}(${ev.dstZone}) proto=${ev.protocol} rule=${ev.ruleRef ?? '-'} nat=${ev.natRuleRef ?? '-'} msg="${ev.message}"`
  );

  const topBlocked = overview.topBlockedSources
    .map((s) => `${s.ip} (${s.zone}): ${s.count} drops`)
    .join('; ');
  const topPorts = overview.topTargetedPorts
    .map((p) => `${p.protocol}/${p.port}: ${p.count} total (${p.blocked} bloqueios)`)
    .join('; ');

  const ap = overview.appliance;
  const telemetry = overview.telemetry;
  const healthParts: string[] = [];
  if (ap.uptimeFormatted) healthParts.push(`Uptime: ${ap.uptimeFormatted}`);
  if (ap.romVersion) healthParts.push(`ROM: ${ap.romVersion}`);
  if (ap.safemodeVersion) healthParts.push(`SafeMode: ${ap.safemodeVersion}`);
  if (ap.haRole) healthParts.push(`HA: ${ap.haRole}`);
  if (ap.cpuPercent !== undefined && ap.cpuPercent !== null) healthParts.push(`CPU: ${ap.cpuPercent}%`);
  if (ap.memoryPercent !== undefined && ap.memoryPercent !== null) healthParts.push(`RAM: ${ap.memoryPercent}%`);
  if (ap.activeConnections !== undefined && ap.activeConnections !== null) {
    healthParts.push(
      `Conexões Ativas: ${ap.activeConnections}${ap.maxConnections ? ` / ${ap.maxConnections}` : ''}`
    );
  }

  const ifaceLines = (telemetry?.interfaces || []).map(
    (i) =>
      `- ${i.name} (${i.zone}, ${i.ip}, ${i.role}): status=${i.linkStatus.toUpperCase()} | link=${i.linkSpeedMbps} Mbps | Rx=${i.rxMbps} Mbps | Tx=${i.txMbps} Mbps | uso=${i.utilizationPercent}% | erros_rx=${i.rxErrors} erros_tx=${i.txErrors}`
  );
  const vpnLines = (telemetry?.vpns || []).map(
    (v) =>
      `- ${v.name} (${v.type.toUpperCase()}, peer=${v.peer}): status=${v.status.toUpperCase()}${v.activeUsers !== undefined ? ` | usuários=${v.activeUsers}` : ''}`
  );
  const licenseLines = (telemetry?.licenses || []).map(
    (l) => `- ${l.service}: ${l.status}${l.expiresAt ? ` (expira ${l.expiresAt})` : ''}`
  );

  const vendorTitle = overview.vendor === 'fortigate' ? 'FORTIGATE (FORTIOS)' : 'SONICWALL (SONICOS)';

  return [
    `=== CONTEXTO ATUAL DO AMBIENTE ${vendorTitle} ===`,
    ...(overview.activeSite
      ? [
          `Localidade Gerenciada: ${overview.activeSite.name}${overview.activeSite.location ? ` (${overview.activeSite.location})` : ''}`,
        ]
      : []),
    `Appliance: ${ap.model} | Serial: ${ap.serialNumber} | Firmware: ${ap.firmware} | Host: ${ap.host}`,
    ...(healthParts.length > 0 ? [`Saúde e Hardware: ${healthParts.join(' | ')}`] : []),
    `Total de syslogs na janela (${overview.retention.retentionDays} dias): ${overview.totalSyslogs} (Permitidos: ${overview.syslogBreakdown.allow}, Bloqueados: ${overview.syslogBreakdown.blocked}, Sistema: ${overview.syslogBreakdown.system}, Críticos/Erro: ${overview.syslogBreakdown.criticalAndError})`,
    `Resumo Regras Firewall: total=${overview.rulesSummary.total}, ativas=${overview.rulesSummary.active}, sem_uso=${overview.rulesSummary.unused}, sombreadas=${overview.rulesSummary.shadowed}, desabilitadas=${overview.rulesSummary.disabled}, permissivas=${overview.rulesSummary.overpermissive}`,
    `Resumo Políticas NAT/VIP: total=${overview.natsSummary.total}, ativas=${overview.natsSummary.active}, sem_uso=${overview.natsSummary.unused}, órfãs=${overview.natsSummary.orphaned}, desabilitadas=${overview.natsSummary.disabled}`,
    `Top IPs Bloqueados: ${topBlocked || 'Nenhum'}`,
    `Top Portas Visadas: ${topPorts || 'Nenhuma'}`,
    ...(ifaceLines.length > 0 ? [``, `Interfaces e Consumo de Link:`, ...ifaceLines] : []),
    ...(vpnLines.length > 0 ? [``, `Túneis VPN e Acesso Remoto:`, ...vpnLines] : []),
    ...(licenseLines.length > 0 ? [``, `Licenças de Serviços de Segurança:`, ...licenseLines] : []),
    ``,
    `Regras de Firewall Irregulares / Sem Uso:`,
    flaggedRules.length > 0 ? flaggedRules.join('\n') : '(Nenhuma regra irregular carregada)',
    ``,
    `Políticas NAT / VIP Irregulares / Sem Uso:`,
    flaggedNats.length > 0 ? flaggedNats.join('\n') : '(Nenhuma política NAT irregular carregada)',
    ``,
    `Amostra de Eventos de Syslog (priorizando alertas e bloqueios):`,
    sampleEvents.length > 0 ? sampleEvents.join('\n') : '(Nenhum syslog carregado ainda)',
  ].join('\n');
}


const metaStr = (v: unknown): string => (v === undefined || v === null ? '' : String(v));

/** Contexto da conta AWS: o que o ALB, o WAF e os VPC Flow Logs mostram, sem nada de firewall de borda. */
export function buildAwsContextSnapshot(overview: AuditOverview, syslogs: SyslogEvent[]): string {
  const alb = syslogs.filter((e) => e.categoryName === 'Application Load Balancer' && e.meta?.method !== undefined);
  const conn = syslogs.filter((e) => e.categoryName === 'Application Load Balancer' && e.meta?.connection === true);
  const waf = syslogs.filter((e) => e.categoryName === 'AWS WAF');
  const flow = syslogs.filter((e) => e.categoryName === 'VPC Flow Logs');

  const top = <T,>(items: T[], key: (t: T) => string, n = 6): string =>
    [...items.reduce((m, it) => m.set(key(it), (m.get(key(it)) ?? 0) + 1), new Map<string, number>()).entries()]
      .filter(([k]) => k)
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([k, c]) => `${k} (${c})`)
      .join('; ') || 'nenhum';

  const status = (e: SyslogEvent) => metaStr(e.meta?.status);
  const errs = alb.filter((e) => status(e).startsWith('5'));
  const times = alb.map((e) => Number(e.meta?.totalTime) || 0).filter((t) => t > 0).sort((a, b) => a - b);
  const p95 = times.length ? times[Math.min(times.length - 1, Math.floor(times.length * 0.95))] : 0;
  const rejected = flow.filter((e) => e.action === 'deny' || e.action === 'drop' || e.action === 'reset');
  const blockedWaf = waf.filter((e) => e.action === 'deny');

  const sample = [
    ...errs.slice(0, 10),
    ...blockedWaf.slice(0, 10),
    ...rejected.slice(0, 8),
    ...alb.filter((e) => Number(e.meta?.totalTime) >= 2).slice(0, 6),
    ...conn.filter((e) => e.action === 'deny').slice(0, 4),
    ...alb.slice(0, 5),
  ].map(
    (e) =>
      `[${e.timestamp}] ${e.categoryName} acao=${e.action} ${e.srcIp}${e.srcPort ? `:${e.srcPort}` : ''} -> ${e.dstIp}${e.dstPort ? `:${e.dstPort}` : ''} msg="${e.message}"`
  );

  return [
    '=== CONTEXTO ATUAL DA CONTA AWS ===',
    `Conta: ${/^\d{12}$/.test(overview.appliance.serialNumber) ? overview.appliance.serialNumber : 'não identificada'} | Região: ${overview.appliance.host && overview.appliance.host !== '-' ? overview.appliance.host : 'não informada'}`,
    `Eventos analisados: ${syslogs.length} (ALB: ${alb.length} requisições + ${conn.length} conexões TLS; WAF: ${waf.length}; VPC Flow Logs: ${flow.length})`,
    '',
    'Application Load Balancer (access logs):',
    `- Erros 5xx: ${errs.length} | latência total p95: ${p95 ? `${p95.toFixed(2)} s` : 'sem dados'}`,
    `- Status mais comuns: ${top(alb, status)}`,
    `- Endpoints com erro 5xx: ${top(errs, (e) => `${metaStr(e.meta?.method)} ${metaStr(e.meta?.host)}${metaStr(e.meta?.pathGroup) || metaStr(e.meta?.path)}`)}`,
    `- Targets com erro: ${top(errs, (e) => metaStr(e.meta?.targetIp))}`,
    `- Clientes: ${top(alb, (e) => metaStr(e.meta?.uaFamily))}`,
    '',
    'AWS WAF:',
    `- Bloqueios: ${blockedWaf.length} de ${waf.length} requisições`,
    `- Regras que mais bloquearam: ${top(blockedWaf, (e) => e.ruleRef ?? '')}`,
    `- Origens bloqueadas: ${top(blockedWaf, (e) => e.srcIp)}`,
    `- Credenciais expostas detectadas (tipo): ${top(waf, (e) => metaStr(e.meta?.secretTop))}`,
    '',
    'VPC Flow Logs:',
    `- Fluxos rejeitados (Security Group/NACL): ${rejected.length} de ${flow.length}`,
    `- Portas mais rejeitadas: ${top(rejected, (e) => (e.dstPort ? String(e.dstPort) : ''))}`,
    `- Origens rejeitadas: ${top(rejected, (e) => e.srcIp)}`,
    '',
    'Alertas ativos: ' + (overview.alerts.length ? overview.alerts.slice(0, 6).map((a) => a.title).join(' | ') : 'nenhum'),
    '',
    'Amostra de eventos (erros, bloqueios, rejeições e requisições lentas primeiro):',
    sample.length > 0 ? sample.join('\n') : '(Nenhum evento carregado ainda)',
  ].join('\n');
}

export function buildSystemInstruction(vendor: string, contextSnapshot: string): string {
  const persona =
    vendor === 'aws'
      ? [
          `Você é um Engenheiro Sênior de Nuvem e Segurança especialista em AWS: Application Load Balancer (access logs e connection logs), AWS WAF (Web ACLs, regras gerenciadas, rate-based), VPC Flow Logs (Security Groups e NACLs), CloudWatch Logs, IAM e TLS.`,
          `Você analisa logs de uma CONTA AWS. Isto NÃO é um firewall SonicWall nem FortiGate: nunca use termos, comandos ou conceitos de SonicOS/FortiOS (zonas, regras de acesso do appliance, NAT de borda etc.).`,
          `Seu objetivo é traduzir esses logs em explicações claras, humanas e acionáveis em português brasileiro, indicando o que verificar ou alterar na AWS (console, CLI ou configuração do recurso).`,
          `Diretrizes obrigatórias:`,
          `1. Baseie-se exclusivamente nos dados do contexto e nas mensagens do usuário. Nunca invente IPs, hosts, regras ou IDs que não apareçam nos dados.`,
          `2. Se não houver eventos carregados, diga isso e oriente a configurar ou sincronizar uma fonte em Contas & Fontes.`,
          `3. Para ALB: explique status (502/503/504 = target indisponível, lento ou conexão fechada), tempos (request_processing = envio pelo cliente, target_processing = aplicação, response_processing = resposta), TLS e ações do WAF. Diferencie lentidão do cliente de lentidão do servidor.`,
          `4. Para WAF: explique a regra (Rule ID, grupo gerenciado), se é falso positivo provável ou ataque real, e sugira ajuste (exclusão de regra, modo COUNT, rate limit, lista de IPs).`,
          `5. Para VPC Flow Logs: REJECT significa bloqueio por Security Group ou NACL; explique a porta e a origem e indique o que revisar.`,
          `6. Credenciais (Authorization, cookies, tokens) nunca devem ser repetidas; se aparecerem, oriente a redigir os campos no logging do WAF.`,
          `7. Seja direto, organizado em listas curtas e cite identificadores exatos (IPs, portas, hosts, endpoints, Rule IDs) quando presentes.`,
        ]
      : [
          vendor === 'fortigate'
            ? `Você é um Engenheiro Sênior de Segurança de Redes especialista em Fortinet FortiGate (FortiOS 7.x), análise de logs, políticas, VIPs/IP Pools e ambientes Linux. O ambiente analisado é um FortiGate: não use conceitos de SonicWall.`
            : `Você é um Engenheiro Sênior de Segurança de Redes especialista em SonicWall (SonicOS 6.5 / 7), análise de syslogs, regras de acesso, políticas NAT e ambientes Linux. O ambiente analisado é um SonicWall: não use conceitos de FortiGate.`,
          `Seu objetivo é traduzir os logs técnicos, drops, alertas de IPS/AV, regras sem uso e NATs/VIPs em explicações claras, humanas, objetivas e acionáveis em português brasileiro.`,
          `Diretrizes obrigatórias:`,
          `1. Baseie-se exclusivamente nos dados reais fornecidos no contexto abaixo e nas mensagens do usuário. Nunca invente IPs, portas ou regras que não apareçam nos dados.`,
          `2. Se não houver logs ou regras carregados, informe claramente e oriente o usuário a carregar o dataset de amostra ou sincronizar/conectar o firewall.`,
          `3. Ao explicar um evento ou risco, destaque: (a) o que aconteceu em linguagem simples, (b) se é tráfego normal ou ameaça/erro real, (c) qual ação prática tomar (ex.: desabilitar política antes de excluir, bloquear IP, revisar VIP/NAT órfão).`,
          `4. Seja direto, organizado com listas curtas e cite os identificadores exatos (IPs, portas, IDs de regra/NAT) quando presentes.`,
        ];
  return [...persona, ``, contextSnapshot].join('\n');
}

async function callGeminiProvider(
  settings: AiProviderSettings,
  systemInstruction: string,
  history: AiChatMessage[],
  userMessage: string
): Promise<{ reply: string; modelUsed: string }> {
  const apiKey = settings.apiKey.trim() || process.env.GEMINI_API_KEY?.trim() || '';
  if (!apiKey) {
    throw new Error(
      'Nenhuma chave Gemini configurada. Adicione sua chave no campo de configuração acima ou defina GEMINI_API_KEY no ambiente do servidor.'
    );
  }

  const validGeminiModels = new Set([
    'gemini-4-hydrogen',
    'gemini-3.1-flash-lite',
    'gemini-4-argon',
    'gemini-4-carbon',
  ]);
  const model = settings.model.trim() || 'gemini-4-hydrogen';
  const resolvedModel = validGeminiModels.has(model) ? model : model;

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  const formattedHistory: Content[] = history.slice(-16).map((msg) => ({
    role: msg.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: msg.content }],
  }));

  const chat = ai.chats.create({
    model: resolvedModel,
    config: {
      systemInstruction,
    },
    history: formattedHistory,
  });

  const response = await chat.sendMessage({ message: userMessage });
  const text = response.text?.trim();
  if (!text) {
    throw new Error('O modelo Gemini retornou uma resposta vazia.');
  }

  return { reply: text, modelUsed: resolvedModel };
}

function getDefaultBaseUrl(provider: AiProviderType): string {
  switch (provider) {
    case 'openrouter':
      return 'https://openrouter.ai/api/v1';
    case 'openai':
      return 'https://api.openai.com/v1';
    case 'local':
      return 'http://127.0.0.1:11434/v1';
    default:
      return '';
  }
}

async function callOpenAiCompatibleProvider(
  settings: AiProviderSettings,
  systemInstruction: string,
  history: AiChatMessage[],
  userMessage: string
): Promise<{ reply: string; modelUsed: string }> {
  const rawBaseUrl = (settings.baseUrl.trim() || getDefaultBaseUrl(settings.provider)).replace(/\/+$/, '');
  if (!rawBaseUrl) {
    throw new Error('Informe a URL base do provedor de IA.');
  }

  const endpoint = rawBaseUrl.endsWith('/chat/completions')
    ? rawBaseUrl
    : `${rawBaseUrl}/chat/completions`;

  const apiKey = settings.apiKey.trim();
  if (settings.provider !== 'local' && !apiKey) {
    throw new Error(
      `Informe sua chave de API para ${settings.provider === 'openrouter' ? 'OpenRouter' : 'OpenAI (GPT)'}.`
    );
  }

  const model =
    settings.model.trim() ||
    (settings.provider === 'openrouter'
      ? 'openai/gpt-4o-mini'
      : settings.provider === 'openai'
        ? 'gpt-4o-mini'
        : 'llama3.1');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }
  if (settings.provider === 'openrouter') {
    const appUrl = (process.env.APP_URL || '').trim();
    headers['HTTP-Referer'] = /^https?:\/\//i.test(appUrl) ? appUrl : 'http://localhost:3000';
    headers['X-Title'] = 'NetAnalyzer';
  }

  const messages = [
    { role: 'system', content: systemInstruction },
    ...history.slice(-16).map((m) => ({
      role: m.role,
      content: m.content,
    })),
    { role: 'user', content: userMessage },
  ];

  const response = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages,
    }),
    signal: AbortSignal.timeout(60_000),
  });

  const rawBody = await response.text();
  let parsed: Record<string, unknown> = {};
  try {
    parsed = rawBody ? (JSON.parse(rawBody) as Record<string, unknown>) : {};
  } catch {
    // Non-JSON response
  }

  if (!response.ok) {
    const errObj = parsed.error as Record<string, unknown> | undefined;
    const detail =
      (typeof errObj?.message === 'string' && errObj.message) ||
      (typeof parsed.message === 'string' && parsed.message) ||
      rawBody.slice(0, 200) ||
      `HTTP ${response.status}`;
    throw new Error(`Erro no provedor (${settings.provider}): ${detail}`);
  }

  const choices = Array.isArray(parsed.choices) ? parsed.choices : [];
  const first = (choices[0] && typeof choices[0] === 'object' ? choices[0] : {}) as Record<
    string,
    unknown
  >;
  const messageObj = (
    first.message && typeof first.message === 'object' ? first.message : {}
  ) as Record<string, unknown>;
  const reply = typeof messageObj.content === 'string' ? messageObj.content.trim() : '';

  if (!reply) {
    throw new Error('O provedor de IA não retornou texto na resposta.');
  }

  return { reply, modelUsed: model };
}

export async function runAiLogAnalysis(params: {
  settings: AiProviderSettings;
  overview: AuditOverview;
  syslogs: SyslogEvent[];
  rules: FirewallRule[];
  nats: NatPolicy[];
  history: AiChatMessage[];
  message: string;
}): Promise<{ reply: string; modelUsed: string; provider: AiProviderType }> {
  const vendor = params.overview.vendor;
  const contextSnapshot =
    vendor === 'aws'
      ? buildAwsContextSnapshot(params.overview, params.syslogs)
      : buildLogContextSnapshot(params.overview, params.syslogs, params.rules, params.nats);
  const anonymizer = params.settings.anonymize !== false ? createAnonymizer() : null;
  const protect = (text: string) => (anonymizer ? anonymizer.mask(text) : text);
  const restore = (text: string) => (anonymizer ? anonymizer.unmask(text) : text);

  const systemInstruction = protect(buildSystemInstruction(vendor, contextSnapshot));
  const history = params.history.map((m) => ({ ...m, content: protect(m.content) }));
  const message = protect(params.message);

  if (params.settings.provider === 'gemini') {
    const result = await callGeminiProvider(params.settings, systemInstruction, history, message);
    return { ...result, reply: restore(result.reply), provider: 'gemini' };
  }

  const result = await callOpenAiCompatibleProvider(
    params.settings,
    systemInstruction,
    history,
    message
  );
  return { ...result, reply: restore(result.reply), provider: params.settings.provider };
}
