/** Ambiente AWS: fontes de log em S3 (VPC Flow Logs, WAF, ALB). */

export type AwsSourceType = 'vpcflow' | 'waf' | 'alb';

export type AwsSourceKind = 's3' | 'cloudwatch';

export const AWS_SOURCE_LABELS: Record<AwsSourceType, string> = {
  vpcflow: 'VPC Flow Logs',
  waf: 'AWS WAF',
  alb: 'Application Load Balancer',
};

/** Estado de leitura de uma fonte (persistido para retomar de onde parou). */
export interface AwsSourceCursor {
  /** Maior LastModified (ms) já processado. */
  lastModifiedMs: number;
  /** Chaves recentes já lidas (evita ler de novo objetos com o mesmo horário). */
  recentKeys: string[];
  /** Modo sem partição por data: última chave lida. */
  lastKey?: string;
}

export interface AwsSourceStatus {
  running: boolean;
  lastRunAt: string | null;
  lastOkAt: string | null;
  lastError: string | null;
  filesRead: number;
  eventsRead: number;
  bytesRead: number;
  lastObjectAt: string | null;
  /** Arquivos ainda pendentes na última listagem (0 = em dia). */
  pendingFiles: number;
}

export interface AwsSourceConfig {
  id: string;
  type: AwsSourceType;
  name: string;
  enabled: boolean;
  /** Onde ler: S3 (padrão) ou um log group do CloudWatch Logs. */
  kind?: AwsSourceKind;
  /** CloudWatch: nome do log group. */
  logGroup?: string;
  /** CloudWatch: prefixo do stream (separa tipos que compartilham o grupo, ex.: ALB_Access_Logs/). */
  streamPrefix?: string;
  bucket: string;
  /** Prefixo dos objetos, ex.: AWSLogs/123456789012/vpcflowlogs/sa-east-1/ */
  prefix: string;
  region: string;
  /** Objetos organizados em AAAA/MM/DD dentro do prefixo (padrão da AWS). */
  dateLayout: boolean;
  /** Na primeira leitura, quantas horas para trás buscar. */
  lookbackHours: number;
  cursor?: AwsSourceCursor;
  status?: AwsSourceStatus;
}

export interface AwsSiteConfigPublic {
  /** Região principal (define o país de origem no mapa do Behavior). */
  region: string;
  accessKeyId: string;
  hasSecret: boolean;
  /** AssumeRole opcional (conta do cliente). */
  roleArn: string;
  externalId: string;
  pollSeconds: number;
  sources: AwsSourceConfig[];
}

export interface AwsConfigSaveBody {
  region?: string;
  accessKeyId?: string;
  /** Só enviado quando o usuário digitou uma nova; vazio mantém a atual. */
  secretAccessKey?: string;
  roleArn?: string;
  externalId?: string;
  pollSeconds?: number;
  sources?: Array<Partial<AwsSourceConfig> & { id?: string }>;
}

export interface AwsTestResult {
  ok: boolean;
  message: string;
  sampleKeys: string[];
  /** Linhas/eventos reconhecidos no objeto de amostra. */
  sampleEvents: number;
  sampleKey?: string;
}

export const AWS_REGION_COUNTRY: Record<string, string> = {
  'us-east-1': 'US', 'us-east-2': 'US', 'us-west-1': 'US', 'us-west-2': 'US',
  'ca-central-1': 'CA', 'ca-west-1': 'CA',
  'sa-east-1': 'BR',
  'eu-west-1': 'IE', 'eu-west-2': 'GB', 'eu-west-3': 'FR', 'eu-central-1': 'DE', 'eu-central-2': 'CH',
  'eu-north-1': 'SE', 'eu-south-1': 'IT', 'eu-south-2': 'ES',
  'ap-southeast-1': 'SG', 'ap-southeast-2': 'AU', 'ap-southeast-3': 'ID', 'ap-southeast-4': 'AU',
  'ap-northeast-1': 'JP', 'ap-northeast-2': 'KR', 'ap-northeast-3': 'JP',
  'ap-south-1': 'IN', 'ap-south-2': 'IN', 'ap-east-1': 'HK',
  'me-south-1': 'BH', 'me-central-1': 'AE', 'af-south-1': 'ZA', 'il-central-1': 'IL',
};
