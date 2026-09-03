# The Dns key on a live image (PEI-598): drive.py guest script.
#
# Exercises Machine\System\Network\Dns — Hosts, ExtraSearchDomains,
# FallbackServers — and that the retired Resolver key is ignored.
# Everything goes to /share; the image has no grep/sed/awk.
#
#   ./drive.py --no-disk --build <dir> --share <host dir> \
#       --cmdline-extra 'loglevel=7 ignore_loglevel' resolvd/tests/vm/dns-key.sh

R=/share
N=Machine/System/Network
export REG_ASSUME_YES=1

step() { echo; echo "== $1"; }

{
step "wait for the network"
net wait routed 60; echo "wait exit=$?"
step "baseline"
resolv status
reg tree $N/Dns --values --depth 2
} > $R/01-baseline.txt 2>&1

{
step "the retired Resolver key is ignored"
reg new $N/Resolver
reg new $N/Resolver/Hosts
reg set $N/Resolver/Hosts oldname 10.0.2.99
sleep 3
resolv query oldname; echo "exit=$? (2 = not found, as intended)"
reg del $N/Resolver -r
} > $R/02-old-key.txt 2>&1

{
step "Hosts: a static name at every door"
reg new $N/Dns
reg new $N/Dns/Hosts
reg set $N/Dns/Hosts printer 10.0.2.9
sleep 3
resolv query printer; echo "exit=$?"
resolv reverse 10.0.2.9
resolv lookup PRINTER
} > $R/03-hosts.txt 2>&1

{
step "ExtraSearchDomains: a single label with no interface domain"
resolv query www; echo "exit=$? (before)"
reg set $N/Dns ExtraSearchDomains multi:example.com
sleep 3
resolv status
resolv query www; echo "exit=$? (after: expanded to www.example.com)"
} > $R/04-extra-search.txt 2>&1

{
step "FallbackServers: consulted only when no interface offers any"
reg set $N/Dns FallbackServers multi:10.0.2.3
sleep 3
resolv status
step "take the offered servers away from the profile"
reg set $N/Profiles/default Dns.Offered dword:0
sleep 6
resolv status
resolv flush
resolv query example.com; echo "exit=$? (via the fallback)"
step "restore"
reg set $N/Profiles/default Dns.Offered dword:1
sleep 6
resolv status
} > $R/05-fallback.txt 2>&1

{
step "resolvd's log"
evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 60'
step "the key as left"
reg tree $N/Dns --values --depth 2
} > $R/06-logs.txt 2>&1

echo done > $R/done.txt
