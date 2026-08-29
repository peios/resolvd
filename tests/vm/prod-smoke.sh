# Guest-side smoke test for resolvd on dist/prod. Run with
#   dist/prod/drive.py --no-disk --share <dir> --timeout 260 --cmdline-extra 'loglevel=7 ignore_loglevel' <dir>/prod-smoke.sh
# with probe-glibc and probe-musl (see probe.rs) copied into <dir>, and read
# <dir>/resolvd-report.txt plus the resolvd: lines on the console.
{
  echo "== service"; svctl status resolvd | head -3
  echo "== files"; ls -l /etc/resolv.conf /usr/etc/resolv.conf /etc/hosts 2>&1; cat /etc/resolv.conf 2>&1 | tail -2
  echo "== wait for the network"; net wait routed 60; echo "wait exit=$?"
  echo "== status"; resolv status
  echo "== synthetic"; resolv query localhost; resolv query localhost AAAA; resolv lookup "$(cat /proc/sys/kernel/hostname)"; resolv reverse 127.0.0.1
  echo "== upstream A"; resolv query example.com; echo "exit=$?"
  echo "== cached"; resolv query example.com; echo "exit=$?"
  echo "== AAAA + lookup"; resolv query example.com AAAA; resolv lookup www.example.com
  echo "== nxdomain"; resolv query does-not-exist.invalid; echo "exit=$?"; resolv query does-not-exist.invalid; echo "exit=$? (cached)"
  echo "== single label, no domain"; resolv query printer; echo "exit=$?"
  echo "== hosts"; reg new Machine/System/Network/Resolver; reg new Machine/System/Network/Resolver/Hosts; reg set Machine/System/Network/Resolver/Hosts printer 10.0.2.9; sleep 2; resolv query printer; resolv reverse 10.0.2.9; resolv lookup PRINTER
  echo "== search domain expansion"; reg set Machine/System/Network/Profiles/ethernet/DNS SearchDomains multi:example.com; sleep 4; resolv status | head -12; resolv query www; echo "exit=$?"
  echo "== dot-local"; resolv query thing.local; echo "exit=$?"
  echo "== flush"; resolv flush; echo "exit=$?"; resolv status | tail -1
  echo "== stub door (raw DNS)"; /share/probe-musl dns 127.0.0.53 example.com; /share/probe-musl dns 127.0.0.53 www; /share/probe-musl dns 127.0.0.53 printer; /share/probe-musl dns 127.0.0.53 nope.invalid
  echo "== musl getaddrinfo via resolv.conf"; /share/probe-musl gai example.com; /share/probe-musl gai printer; /share/probe-musl gai localhost
  echo "== glibc getaddrinfo via libnss_peios_net"; /share/probe-glibc gai example.com; /share/probe-glibc gai printer; /share/probe-glibc gai localhost; /share/probe-glibc gai nope.invalid; /share/probe-glibc gai www
  echo "== nss module present"; ls -l /usr/lib/x86_64-linux-peios/libnss_peios_net.so.2
  echo "== fallback servers"; reg set Machine/System/Network/Resolver Servers multi:10.0.2.3; sleep 2; resolv status | tail -4
  echo "== final status"; resolv status
} > /share/resolvd-report.txt 2>&1
