import isoCountries from 'i18n-iso-countries';
import pt from 'i18n-iso-countries/langs/pt.json' with { type: 'json' };

isoCountries.registerLocale(pt);

export { isoCountries };

/** Nome do país em português (cai no código se desconhecido). */
export function countryName(code: string): string {
  return isoCountries.getName(code, 'pt') || code;
}

/** Lista de países (código e nome) para o seletor. */
export function allCountries(): Array<{ code: string; name: string }> {
  return Object.entries(isoCountries.getNames('pt', { select: 'official' }))
    .map(([code, name]) => ({ code, name }))
    .sort((a, b) => a.name.localeCompare(b.name, 'pt-BR'));
}

/** Bandeira em emoji a partir do código ISO de 2 letras. */
export function flagEmoji(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return '';
  return String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
