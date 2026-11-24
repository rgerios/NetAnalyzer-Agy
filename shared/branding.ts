/** Identidade do relatório de entrega: cliente, logo e quem preparou. Guardada por localidade/conta. */
export interface ReportBranding {
  /** Nome do cliente que aparece no cabeçalho de todos os relatórios. */
  clientName: string;
  /** Título opcional (ex.: "Relatório mensal de segurança"); vazio usa o título padrão de cada relatório. */
  reportTitle: string;
  /** Quem entrega o relatório (consultoria/equipe). */
  preparedBy: string;
  /** Logo do cliente como data URI (png, jpeg ou webp, até 300 KB). Vazio = sem logo. */
  logoDataUri: string;
}

export const EMPTY_BRANDING: ReportBranding = { clientName: '', reportTitle: '', preparedBy: '', logoDataUri: '' };

export const BRANDING_LIMITS = { name: 120, title: 160, logoBytes: 300 * 1024 } as const;
