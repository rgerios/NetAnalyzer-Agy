import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createUnrecognizedTracker, shapeOf } from '../server/unrecognized.ts';
import { parseFortiGateSyslog } from '../server/fortigateParsers.ts';
import { parseSonicWallSyslog } from '../server/parsers.ts';
import { parseAlbLogs, parseFlowLogs, parseWafLogs } from '../server/awsParsers.ts';

describe('linhas não reconhecidas', () => {
  it('agrupa linhas parecidas pela forma, ignorando números, IPs e textos entre aspas', () => {
    const a = shapeOf('weird message 12345 from 10.0.0.5:5000 user "joao silva" id 99');
    const b = shapeOf('weird message 99999 from 192.168.1.20:80 user "maria" id 7');
    assert.equal(a, b);
    assert.notEqual(a, shapeOf('outra coisa totalmente diferente'));
  });

  it('conta, guarda o exemplo mais recente e ordena por quantidade', () => {
    const t = createUnrecognizedTracker();
    for (let i = 0; i < 5; i += 1) t.record(`tipo A evento ${i} ip 10.0.0.${i}`, 'udp');
    t.record('tipo B raro', 'paste');
    t.record('   ', 'udp'); // vazio não conta
    const snap = t.snapshot();
    assert.equal(snap.total, 6);
    assert.equal(snap.shapes.length, 2);
    assert.equal(snap.shapes[0].count, 5);
    assert.match(snap.shapes[0].sample, /evento 4/);
    assert.equal(snap.shapes[1].source, 'paste');
    t.clear();
    assert.equal(t.snapshot().total, 0);
    assert.equal(t.snapshot().shapes.length, 0);
  });

  it('limita o número de formas, descartando as menos frequentes, sem perder o total', () => {
    const t = createUnrecognizedTracker(3);
    for (let i = 0; i < 10; i += 1) t.record('popular', 'udp');
    t.record('a-unica', 'udp');
    t.record('b-unica', 'udp');
    t.record('c-unica', 'udp'); // estoura: sai a menos frequente
    const snap = t.snapshot();
    assert.equal(snap.shapes.length, 3);
    assert.equal(snap.droppedShapes, 1);
    assert.equal(snap.total, 13);
    assert.equal(snap.shapes[0].sample, 'popular');
  });

  it('os analisadores avisam cada linha que descartam (e não as que entendem)', () => {
    const sw: string[] = [];
    const swEvents = parseSonicWallSyslog(
      ['sem formato nenhum aqui', '<134>id=firewall sn=ABC time="2026-11-24 10:00:00" fw=1.1.1.1 pri=6 c=1024 m=537 msg="Connection Closed" src=10.0.0.5:1:X0 dst=8.8.8.8:53:X1 proto=udp/dns fw_action="allow"'].join('\n'),
      'upload',
      (l) => sw.push(l)
    );
    assert.equal(swEvents.length, 1);
    assert.deepEqual(sw, ['sem formato nenhum aqui']);

    const fg: string[] = [];
    const fgEvents = parseFortiGateSyslog(
      ['lixo qualquer sem chaves', 'date=2026-11-24 time=10:00:00 devname="FGT" devid="FG1" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.0.0.5 dstip=8.8.8.8 dstport=53 proto=17 action="accept"'].join('\n'),
      'upload',
      (l) => fg.push(l)
    );
    assert.equal(fgEvents.length, 1);
    assert.deepEqual(fg, ['lixo qualquer sem chaves']);
  });

  it('os analisadores da AWS também avisam as linhas inválidas', () => {
    const skipped: string[] = [];
    const onSkip = (l: string) => skipped.push(l);
    parseWafLogs('{quebrado\n{"timestamp":1}', { onSkip });
    parseAlbLogs('nao e alb', { onSkip });
    parseFlowLogs('2 123 eni-1 1.1.1.1', { onSkip });
    assert.equal(skipped.length, 4);
  });
});
