import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { hasPortFilter, parsePortFilter, portMatches, wellKnownService } from '../shared/ports.ts';
import { buildPortStats, filterEventsByPort, isPublicDestination } from '../server/portsEngine.ts';
import type { SyslogEvent } from '../server/types.ts';

function ev(partial: Partial<SyslogEvent>): SyslogEvent {
  return {
    srcIp: '10.0.0.5',
    dstIp: '8.8.8.8',
    dstPort: 443,
    protocol: 'tcp',
    action: 'allow',
    bytesSent: 100,
    bytesRcvd: 400,
    ...partial,
  } as SyslogEvent;
}

describe('filtro de porta de destino', () => {
  it('aceita número, lista, intervalo e normaliza o texto', () => {
    assert.deepEqual(parsePortFilter('443'), { ranges: [[443, 443]], text: '443' });
    assert.deepEqual(parsePortFilter(' 80, 443  8000-8100 ')?.ranges, [[80, 80], [443, 443], [8000, 8100]]);
    assert.equal(parsePortFilter('80, 443')?.text, '80,443');
    assert.deepEqual(parsePortFilter(''), { ranges: [], text: '' });
    assert.deepEqual(parsePortFilter(undefined), { ranges: [], text: '' });
    assert.equal(hasPortFilter(parsePortFilter('')), false);
  });

  it('rejeita entradas inválidas', () => {
    for (const bad of ['abc', '70000', '100-50', '80-', '-80', '80;drop table', '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21', '99999999']) {
      assert.equal(parsePortFilter(bad), null, bad);
    }
  });

  it('casa portas por lista e intervalo; evento sem porta não casa', () => {
    const spec = parsePortFilter('22,8000-8100')!;
    assert.ok(portMatches(spec, 22));
    assert.ok(portMatches(spec, 8050));
    assert.ok(!portMatches(spec, 443));
    assert.ok(!portMatches(spec, null));
    assert.ok(portMatches(parsePortFilter('')!, null)); // sem filtro: tudo passa
  });

  it('nomeia serviços conhecidos', () => {
    assert.equal(wellKnownService(443), 'HTTPS');
    assert.equal(wellKnownService(3389), 'RDP');
    assert.equal(wellKnownService(44321), '');
  });
});

describe('ranking de portas', () => {
  const events = [
    ...Array.from({ length: 5 }, () => ev({ dstPort: 443 })),
    ...Array.from({ length: 3 }, (_v, i) => ev({ dstPort: 22, srcIp: `10.0.0.${i}`, action: 'drop' })),
    ev({ dstPort: 53, protocol: 'udp', dstIp: '1.1.1.1' }),
    ev({ dstPort: null }),
    ev({ dstPort: 443, action: 'system' }),
    ev({ dstPort: 3389, dstIp: '192.168.1.10' }),
  ];

  it('ordena por conexões e soma bloqueios, bytes e únicos', () => {
    const { ports, counted } = buildPortStats(events);
    assert.equal(counted, 10); // ignora porta nula e evento de sistema
    assert.deepEqual(ports.map((p) => p.port), [443, 22, 53, 3389]);
    const https = ports[0];
    assert.equal(https.connections, 5);
    assert.equal(https.service, 'HTTPS');
    assert.equal(https.bytes, 5 * 500);
    assert.equal(https.sources, 1);
    const ssh = ports[1];
    assert.equal(ssh.blocked, 3);
    assert.equal(ssh.sources, 3);
    assert.equal(ports[2].proto, 'udp');
  });

  it('respeita o limite e o filtro de inclusão', () => {
    assert.equal(buildPortStats(events, 2).ports.length, 2);
    const onlyPublic = buildPortStats(events, 10, isPublicDestination).ports.map((p) => p.port);
    assert.ok(!onlyPublic.includes(3389));
  });

  it('filtra eventos por porta de destino', () => {
    assert.equal(filterEventsByPort(events, parsePortFilter('22')).length, 3);
    assert.equal(filterEventsByPort(events, parsePortFilter('22,53')).length, 4);
    assert.equal(filterEventsByPort(events, parsePortFilter('')).length, events.length);
    assert.equal(filterEventsByPort(events, null).length, events.length);
  });
});
