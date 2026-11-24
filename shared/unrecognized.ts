/** Linhas de log que os analisadores não entenderam (tipos compartilhados). */

export type UnrecognizedSource = 'udp' | 'paste' | 'upload' | 's3' | 'sample';

export interface UnrecognizedShape {
  /** Exemplo real (o mais recente) desta forma de linha. */
  sample: string;
  count: number;
  firstAt: string;
  lastAt: string;
  source: UnrecognizedSource;
}

export interface UnrecognizedSnapshot {
  total: number;
  /** Desde quando se conta (início do processo ou da última limpeza). */
  since: string;
  /** Formas diferentes que ficaram de fora do registro por excesso. */
  droppedShapes: number;
  shapes: UnrecognizedShape[];
}
