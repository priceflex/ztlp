#!/usr/bin/env python3
"""Real-WAN ZTLP full-stack HTTP-download multistream bench.

Path: client -> relay 44.243.42.123:23095 -> gateway 54.190.82.255:23097
      -> HTTP backend on gateway 127.0.0.1:7777 -> back.

Each stream is its own `ztlp connect` session with unique local forward, then a
single HTTP GET for SIZE bytes through that tunnel.
"""
import argparse, os, signal, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT=Path('/home/trs/ztlp'); BIN=ROOT/'proto/target/release/ztlp'; IDENT=Path('/tmp/bench-identity.json')
LOG_DIR=Path('/tmp/ztlp-fullstack'); RESULT=Path('/tmp/fullstack-bench-result.txt')
RELAY='44.243.42.123:23095'; GATEWAY='54.190.82.255:23097'; RELAY_HOST='44.243.42.123'; GATEWAY_HOST='54.190.82.255'
BASE_PORT=19000

def run(cmd, timeout=20):
    return subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout).stdout

def parse_udp(txt):
    hdr=vals=None
    for line in txt.splitlines():
        if line.startswith('Udp:'):
            p=line.split(); vals=p if len(p)>1 and p[1].isdigit() else vals; hdr=p if not (len(p)>1 and p[1].isdigit()) else hdr
    if not hdr or not vals: return (0,0,0)
    d=dict(zip(hdr[1:], map(int, vals[1:])))
    return (d.get('InDatagrams',0), d.get('InErrors',0), d.get('OutDatagrams',0))

def counters():
    return {
      'client': parse_udp(Path('/proc/net/snmp').read_text()),
      'relay': parse_udp(run(f"ssh ubuntu@{RELAY_HOST} \"cat /proc/net/snmp\"", 10)),
      'gateway': parse_udp(run(f"ssh ubuntu@{GATEWAY_HOST} \"cat /proc/net/snmp\"", 10)),
    }

def cdiff(a,b): return {k: tuple(b[k][i]-a[k][i] for i in range(3)) for k in a}

def ensure_identity():
    if not IDENT.exists(): run(f"cd {ROOT} && {BIN} keygen --output {IDENT}", 20)

def wait_port(port, timeout=15):
    # IMPORTANT: do NOT open a TCP connection here. ztlp connect's local-forward
    # path is effectively one TCP connection per tunnel session; a readiness
    # probe that connects+closes consumes the session and causes the real curl
    # transfer to see a closed tunnel. Poll LISTEN state via ss instead.
    end=time.time()+timeout
    cmd=f"ss -ltn 'sport = :{port}' | grep -q LISTEN"
    while time.time()<end:
        if subprocess.run(cmd, shell=True).returncode == 0:
            return True
        time.sleep(0.1)
    return False

def start_conn(i, port):
    log=LOG_DIR/f'connect-{i}.log'; f=open(log,'wb')
    # Force a unique SessionID per stream. Without this, repeated/concurrent CLI
    # runs can collide and the gateway logs "Replacing session ...", killing the
    # older local-forward before curl consumes it.
    sid=f'{int(time.time()*1000000)%0xffffffffffff:012x}{i:012x}'[-24:]
    cmd=[str(BIN),'connect',GATEWAY,'--key',str(IDENT),'--relay',RELAY,'--service','echo','--session-id',sid,'--local-forward',f'{port}:127.0.0.1:7777']
    p=subprocess.Popen(cmd,cwd=str(ROOT),stdout=f,stderr=subprocess.STDOUT,preexec_fn=os.setsid)
    return p,f,log,port

def stop(p):
    if p.poll() is None:
        try: os.killpg(os.getpgid(p.pid), signal.SIGTERM); p.wait(timeout=3)
        except Exception:
            try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception: pass

def http_get(i, port, size):
    log=LOG_DIR/f'stream-{i}.log'; out=LOG_DIR/f'stream-{i}.bin'
    url=f'http://127.0.0.1:{port}/bytes?size={size}'
    t0=time.time()
    cp=subprocess.run(['curl','-sS','--max-time','90','-o',str(out),'-w','%{http_code} %{size_download} %{time_total}',url],
                      text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    elapsed=time.time()-t0
    got=out.stat().st_size if out.exists() else 0
    mbps=(got/1048576.0)/elapsed if elapsed>0 else 0.0
    err=None if cp.returncode==0 and got==size else f'rc={cp.returncode} out={cp.stdout.strip()} got={got}'
    log.write_text(f'idx={i}\nport={port}\nurl={url}\nrc={cp.returncode}\nstdout={cp.stdout}\ngot={got}\nelapsed={elapsed:.3f}\nmbps={mbps:.3f}\nerr={err}\n')
    try: out.unlink()
    except Exception: pass
    return dict(idx=i, got=got, elapsed=elapsed, mbps=mbps, err=err)

def run_n(n,size):
    conns=[]
    try:
        failed=[]
        # Stagger handshakes. The bench target is steady-state N streams, not a
        # SYN-flood/handshake burst; simultaneous HELLOs through the relay cause
        # occasional no-HELLO_ACK on this gateway path.
        for i in range(n):
            conns.append(start_conn(i, BASE_PORT+i))
            p,f,log,port = conns[-1]
            if not wait_port(port):
                failed.append(f'port {port} not ready ({log})')
            time.sleep(0.25)
        if failed: return dict(n=n,ok=0,stalled=n,agg=0,wall=0,streams=[],failed='; '.join(failed))
        time.sleep(0.5)
        t0=time.time(); streams=[]
        with ThreadPoolExecutor(max_workers=n) as ex:
            futs=[ex.submit(http_get,i,BASE_PORT+i,size) for i in range(n)]
            for fut in as_completed(futs): streams.append(fut.result())
        wall=time.time()-t0
        ok=sum(1 for s in streams if not s['err'] and s['mbps']>=0.1)
        stalled=n-ok
        agg=((size*ok)/1048576.0)/wall if wall>0 else 0.0
        return dict(n=n,ok=ok,stalled=stalled,agg=agg,wall=wall,streams=sorted(streams,key=lambda x:x['idx']),failed=None)
    finally:
        for p,f,log,port in conns:
            stop(p); f.close()
        time.sleep(1)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--size',type=int,default=10*1024*1024); ap.add_argument('--ns',default='1,4,8,16,32')
    args=ap.parse_args(); LOG_DIR.mkdir(parents=True,exist_ok=True)
    for p in LOG_DIR.glob('*'): p.unlink()
    ensure_identity(); lines=[]
    def emit(s=''): print(s,flush=True); lines.append(s)
    emit('═════════════════════════════════════════════════════════════════════════')
    emit(f'  Full-stack ZTLP HTTP throughput (size={args.size//1048576} MB per stream)')
    emit(f'  Path: client → relay {RELAY} → gateway {GATEWAY} → HTTP backend')
    emit('═════════════════════════════════════════════════════════════════════════')
    for n in [int(x) for x in args.ns.split(',') if x.strip()]:
        before=counters(); r=run_n(n,args.size); after=counters(); d=cdiff(before,after)
        per=sum(s['mbps'] for s in r['streams'])/len(r['streams']) if r['streams'] else 0.0
        emit(f"  {n:2d} streams: aggregate={r['agg']:7.1f} MB/s   wall={r['wall']*1000:6.0f} ms   per-stream-avg={per:6.1f} MB/s   stalled={r['stalled']}   ok={r['ok']}")
        if r['failed']: emit(f"       startup_failed={r['failed']}")
        for host,(din,derr,dout) in d.items(): emit(f"       udp[{host}]: dIn={din} dErr={derr} dOut={dout}")
        errs=[s for s in r['streams'] if s['err']]
        if errs: emit('       errors='+'; '.join(f"s{s['idx']}:{s['err']}" for s in errs[:5]))
    emit(''); emit(f'Per-stream logs: {LOG_DIR}'); RESULT.write_text('\n'.join(lines)+'\n')
if __name__=='__main__': main()
