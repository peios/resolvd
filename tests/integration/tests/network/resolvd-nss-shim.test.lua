-- resolvd TRM ch.7 (the NSS shim: §7.1 the module, §7.2 forward
-- lookups, §7.3 reverse lookups) and PSPU §6.10 (the hosts shim).
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), a whole Peios (helpers.network), and pt-nss, an
-- instrument whose C source is in tests/tools/pt-nss.c.
--
-- Why an instrument. The image has no compiler and no python, and
-- nothing it ships reports an NSS status or h_errno: `getent` gives an
-- exit status, and `ping`/`nc`/`curl` give gai_strerror text at best. The
-- probe must be dynamically linked against a glibc compatible with the
-- guest. Supply it as guest_tools.pt-nss.unsigned in the composition;
-- it is staged into the boot as /usr/bin/pt-nss without host compilation.
--
-- What it does:
--   * dlopens the installed libnss_peios_net.so.2 and calls its six entry
--     points directly, with a buffer of a chosen size and errno, h_errno
--     and TTL out-parameters preset to -77, so "left alone" and "written
--     0" differ;
--   * calls glibc too (getaddrinfo, gethostbyname2_r, gethostbyaddr,
--     __nss_configure_lookup), for what a program sees;
--   * defines socket, connect, close, setsockopt, read/recv*, write/send*
--     and open*/fopen* itself, exported (-rdynamic), so they interpose the
--     module's PLT calls. Each call's trace is therefore exactly the
--     module's socket and file activity — glibc's own internal calls do not
--     go through the PLT and are not traced — including the request bytes
--     it wrote and the reply bytes it read, which are decoded here;
--   * optionally (PTNSS_FAKE) runs a stand-in server in a child process and
--     redirects the module's connect to /run/resolvd/resolv.sock to it, for
--     the replies the real resolvd cannot be made to give (silence for ten
--     seconds, a reply of the wrong kind, bytes that do not decode). Every
--     other test talks to the real resolvd.
--
-- Answers come from static names (`Dns\Hosts`, written at file scope;
-- synthetic, never sent upstream) and, where the claim needs TTLs, CNAMEs
-- or PTR records, from the gateway's DNS server, which DHCP names as the
-- interface's server. A question that goes upstream runs while the gateway
-- pumps (`served`).
--
-- Order matters at the end: the access-denied and unreachable test sets
-- and then clears ControlSecurity, and stops resolvd; the test after it
-- runs with resolvd stopped and starts it again.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

--- Resolve the supplied dynamic probe and return it as a boot file.
local function build_pt_nss()
    return peinit.tool("pt-nss")
end

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

local SOCK = "/run/resolvd/resolv.sock"
local MODULE = "/usr/lib/x86_64-linux-peios/libnss_peios_net.so.2"
local NSS = { SUCCESS = 1, NOTFOUND = 0, UNAVAIL = -1, TRYAGAIN = -2 }
local E = { ENOENT = 2, EAGAIN = 11, ERANGE = 34, EAFNOSUPPORT = 97 }
local H = { HOST_NOT_FOUND = 1, TRY_AGAIN = 2, NO_RECOVERY = 3, NO_DATA = 4, NETDB_INTERNAL = -1 }
local AF = { UNSPEC = 0, UNIX = 1, INET = 2, INET6 = 10 }
local ENTRY_POINTS = {
    "_nss_peios_net_gethostbyaddr2_r", "_nss_peios_net_gethostbyaddr_r",
    "_nss_peios_net_gethostbyname2_r", "_nss_peios_net_gethostbyname3_r",
    "_nss_peios_net_gethostbyname4_r", "_nss_peios_net_gethostbyname_r",
}

-- The static names (Dns\Hosts). `many` is 120 IPv4 addresses: more than
-- fit glibc's first 1024-byte buffer as a hostent (getaddrinfo's AF_INET
-- path, gethostbyname2) or as address tuples (getaddrinfo's AF_UNSPEC
-- path), so each of them must grow its buffer to answer.
local MANY_N = 120
local MANY = {}
for i = 1, MANY_N do MANY[i] = "10.89." .. (i // 100) .. "." .. (i % 100) end
local HOSTS = {
    ["both.nss.test"] = "multi:10.88.0.1,fd88::1,10.88.0.2,fd88::2",
    ["v4only.nss.test"] = "sz:10.88.0.5",
    ["ll.nss.test"] = "sz:fe80::5",
    ["change.nss.test"] = "sz:10.88.0.7",
    ["many.nss.test"] = "multi:" .. table.concat(MANY, ","),
}

-- The gateway's zone, for the claims that need TTLs, CNAMEs and PTRs.
local ZONE = {
    ["www.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.80" } },
    ["alias.example.test"] = { { type = "CNAME", ttl = 30, data = "www.example.test" } },
    ["ttl.example.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" },
                             { type = "A", ttl = 120, data = "10.77.0.82" },
                             { type = "AAAA", ttl = 200, data = "fd77::81" } },
    -- The same, under a name only one test asks, so its TTLs are not
    -- lowered by a cache hit.
    ["ttl4.example.test"] = { { type = "A", ttl = 300, data = "10.77.0.81" },
                              { type = "A", ttl = 120, data = "10.77.0.82" },
                              { type = "AAAA", ttl = 200, data = "fd77::81" } },
    ["81.0.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 400, data = "ptr-one.example.test" },
                                    { type = "PTR", ttl = 200, data = "ptr-two.example.test" } },
    ["82.0.77.10.in-addr.arpa"] = { { type = "CNAME", ttl = 30, data = "82.sub.0.77.10.in-addr.arpa" } },
    ["82.sub.0.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 300, data = "classless.example.test" } },
    ["83.0.77.10.in-addr.arpa"] = { { type = "CNAME", ttl = 30, data = "83.gone.example.test" } },
    ["83.gone.example.test"] = { { type = "TXT", ttl = 30, data = "no ptr here" } },
    ["84.0.77.10.in-addr.arpa"] = { { type = "TXT", ttl = 30, data = "no ptr here" } },
}

-- ---------------------------------------------------------------------------
-- The pair
-- ---------------------------------------------------------------------------

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" } })
dns.serve(gw, {
    zone = ZONE,
    soa = { name = "example.test", data = { minimum = 30 } },
    on = function(q)
        -- A server that never answers this name: resolvd's attempts run
        -- out and the lookup is `unavailable`.
        if q.questions[1] and dns.same_name(q.questions[1].name, "slow.example.test") then return false end
    end,
})
local files = build_pt_nss()
-- Optional signed candidates replace only the two modules in the disposable boot.
files = peinit.test_files(files, {
    NSS_NET_TEST_BINARY = { path = "usr/lib/x86_64-linux-peios/libnss_peios_net.so.2", exec = true },
    NSS_IDENTITY_TEST_BINARY = { path = "usr/lib/x86_64-linux-peios/libnss_peios.so.2", exec = true },
})
local sut = network.boot({ bridges = { lan }, gateway = gw, files = files })

-- ---------------------------------------------------------------------------
-- Talking to resolvd and running pt-nss
-- ---------------------------------------------------------------------------

local function native(req) return network.call(sut, req, { path = SOCK, timeout_ms = 5000 }) end

local function addresses_of(reply)
    local out = {}
    for _, a in ipairs((reply and reply.addresses) or {}) do out[#out + 1] = a.address end
    return out
end

local function list(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

-- The static names, at file scope: every test below reads them.
network.write(sut, "Dns", {})
network.write(sut, "Dns\\Hosts", HOSTS)
wait_until(function()
    local a = native({ query = "lookup", name = "many.nss.test", family = "inet" })
    local b = native({ query = "lookup", name = "both.nss.test", family = "any" })
    return a and #addresses_of(a) == MANY_N and b and #addresses_of(b) == 4
end, { timeout = 30, interval = 0.3, desc = "resolvd answering the static names" })

--- Run `cmd` in the guest while the gateway pumps.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 30, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

local function quote(s) return "'" .. s:gsub("'", "'\\''") .. "'" end

local function unhex(h) return (h:gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end)) end
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

--- One length-prefixed native message from its bytes, decoded.
local function message(bytes)
    if #bytes < 4 then return nil end
    local n = string.unpack("<I4", bytes)
    if #bytes < 4 + n then return nil end
    local ok, m = pcall(msgpack.decode, bytes:sub(5, 4 + n))
    return ok and m or nil
end

--- A native frame, as hex, for PTNSS_FAKE.
local function frame_hex(payload)
    if type(payload) == "table" then payload = msgpack.encode(payload) end
    return hex(string.pack("<I4", #payload) .. payload)
end

local function parse(out)
    local ops, cur = {}, nil
    for line in out:gmatch("[^\n]+") do
        local o = line:match("^op=(%S+)$")
        if o then
            cur = { op = o, addrs = {}, alias_list = {}, tuples = {}, trace = {}, sockets = {}, connects = {},
                    closes = {}, opens = {}, inet_sends = {}, timeouts = {}, exports = {}, needed = {},
                    sent = "", got = "", recv_errors = {} }
            ops[#ops + 1] = cur
        elseif cur and line:match("^t ") then
            cur.trace[#cur.trace + 1] = line
            local kind = line:match("^t (%S+)")
            local f = {}
            for k, v in line:gmatch("(%S+)=(%S*)") do f[k] = tonumber(v) or v end
            f.hex = line:match(" hex=(%x+)$")
            if kind == "send" and f.hex then cur.sent = cur.sent .. unhex(f.hex)
            elseif kind == "recv" and f.hex then cur.got = cur.got .. unhex(f.hex)
            elseif kind == "recv" then cur.recv_errors[#cur.recv_errors + 1] = f
            elseif kind == "socket" then cur.sockets[#cur.sockets + 1] = f
            elseif kind == "connect" then cur.connects[#cur.connects + 1] = f
            elseif kind == "close" then cur.closes[#cur.closes + 1] = f
            elseif kind == "open" then cur.opens[#cur.opens + 1] = line:match("path=(.*)$")
            elseif kind == "sendto" or kind == "sendmsg" then cur.inet_sends[#cur.inet_sends + 1] = f
            elseif kind == "setsockopt" and f.opt then cur.timeouts[f.opt] = f end
        elseif cur and line:match("^tuple ") then
            local f = {}
            for k, v in line:gmatch("(%S+)=(%S*)") do f[k] = tonumber(v) or v end
            cur.tuples[#cur.tuples + 1] = f
        elseif cur and line:match("^addr=") then cur.addrs[#cur.addrs + 1] = line:sub(6)
        elseif cur and line:match("^alias=") then cur.alias_list[#cur.alias_list + 1] = line:sub(7)
        elseif cur and line:match("^needed=") then cur.needed[#cur.needed + 1] = line:sub(8)
        elseif cur and line:match("^export=") then
            local name, ty = line:match("^export=(%S+) type=(%S+)")
            cur.exports[#cur.exports + 1] = { name = name, type = ty }
        elseif cur and line:match("^gai=") then
            local code, text = line:match("^gai=(%-?%d+) gaistr=(.*)$")
            cur.gai, cur.gaistr = tonumber(code), text
        elseif cur and line:find(" [%w_]+=") then
            for k, v in line:gmatch("([%w_]+)=(%S*)") do cur[k] = tonumber(v) or v end
        elseif cur then
            local k, v = line:match("^([%w_]+)=(.*)$")
            if k then cur[k] = tonumber(v) or v end
        end
    end
    for _, r in ipairs(ops) do
        r.request = message(r.sent)
        r.reply = message(r.got)
    end
    return ops
end

--- Run pt-nss with `ops` (a list of argument lists). `o.buf`, `o.fake`
--- (a PTNSS_FAKE value), `o.serve` (pump the gateway while it runs),
--- `o.timeout`. Returns the parsed results, one per op.
local function pt(t, ops, o)
    o = o or {}
    local args = {}
    for i, op in ipairs(ops) do
        if i > 1 then args[#args + 1] = "+" end
        for _, a in ipairs(op) do args[#args + 1] = quote(a) end
    end
    local env = ""
    if o.buf then env = env .. "PTNSS_BUF=" .. o.buf .. " " end
    if o.fake then env = env .. "PTNSS_FAKE=" .. o.fake .. " " end
    local cmd = env .. "pt-nss " .. table.concat(args, " ")
    local r
    if o.serve then r = served(cmd, o.timeout) else r = sut:run(cmd, { timeout = o.timeout or 60 }) end
    t:log("$ " .. cmd .. "\n" .. r.stdout .. (r.stderr ~= "" and ("stderr: " .. r.stderr) or ""))
    t:assert(not r.stdout:find("\nerror=", 1, true) and not r.stdout:find("^error="),
        "pt-nss ran every op (exit " .. tostring(r.exit_code) .. ")")
    local out = parse(r.stdout)
    t:assert_eq(#out, #ops, "pt-nss reported every op")
    return out
end

--- Assert an NSS result's status, errno and h_errno.
local function expect(t, r, status, errno, herrno, what)
    t:assert_eq(r.status, status, what .. ": NSS status")
    t:assert_eq(r.errno, errno, what .. ": errno")
    t:assert_eq(r.herrno, herrno, what .. ": h_errno")
end

--- The call made no socket at all.
local function no_socket(t, r, what)
    t:assert_eq(#r.sockets, 0, what .. ": no socket was opened")
    t:assert_eq(#r.connects, 0, what .. ": nothing was connected to")
end

--- The call opened exactly one connection, to resolvd's socket, and
--- closed it before returning.
local function one_connection(t, r, what)
    t:assert_eq(#r.sockets, 1, what .. ": one socket")
    t:assert_eq(r.sockets[1] and r.sockets[1].family, 1, what .. ": an AF_UNIX socket")
    t:assert_eq(#r.connects, 1, what .. ": one connect")
    t:assert_eq(r.connects[1] and r.connects[1].path, SOCK, what .. ": to " .. SOCK)
    t:assert_eq(#r.closes, 1, what .. ": one close")
    t:assert_eq(r.closes[1] and r.closes[1].fd, r.sockets[1] and r.sockets[1].ret, what .. ": of that socket")
    t:assert_eq(r.sockets_left, 0, what .. ": no socket left open after the call")
end

local function same_list(t, got, want, what)
    t:assert_eq(list(got), list(want), what)
end

--- Wait for the interface's scope to carry the gateway as its server.
local function scope_ready(t)
    local ok = wait_until(function()
        local s = native({ query = "status" })
        for _, sc in ipairs((s and s.scopes) or {}) do
            for _, sv in ipairs(sc.servers or {}) do
                if sv == "10.77.0.1" then return true end
            end
        end
        -- Keep the gateway answering DHCP while we wait.
        gw:pump(100)
        return false
    end, { timeout = 60, interval = 0.2, desc = "a scope with the gateway as its server" })
    t:assert(ok ~= false, "resolvd has a scope whose server is the gateway")
end

-- ---------------------------------------------------------------------------
-- §7.1 the object
-- ---------------------------------------------------------------------------

test("the module is installed by dev.peios.resolvd-nss at the TRM's path, with SONAME libnss_peios_net.so.2, in the directory glibc's own libc is loaded from, and glibc loads it from there",
    { spec = "resolvd *nss-module.installed-path PSPU *nri-shim.soname-and-location" }, function(t)
        local owns = sut:run("peipkg owns " .. MODULE)
        t:log("peipkg owns: exit " .. owns.exit_code .. "\n" .. owns.stdout .. owns.stderr)
        t:assert_eq(owns.exit_code, 0, "peipkg knows the file")
        t:assert(owns.stdout:find("dev.peios.resolvd-nss", 1, true), "the owning package is dev.peios.resolvd-nss")

        local r = pt(t, { { "elf", MODULE }, { "gai", "localhost", "0" }, { "where" } })
        t:assert_eq(r[1].soname, "libnss_peios_net.so.2", "the SONAME")
        t:assert_eq(r[2].gai, 0, "getaddrinfo(localhost) succeeds, so glibc has loaded the hosts module")
        t:assert(r[3].module ~= "(not loaded)" and r[3].module, "glibc loaded libnss_peios_net.so.2")
        local real = sut:run("readlink -f " .. quote(r[3].module) .. " " .. quote(r[3].libc))
        local mod_path, libc_path = real.stdout:match("^(%S+)\n(%S+)")
        t:log("glibc loaded the module from " .. tostring(mod_path) .. "; libc is " .. tostring(libc_path))
        t:assert_eq(mod_path, MODULE, "glibc loaded the installed file")
        t:assert_eq(mod_path and mod_path:match("^(.*)/"), libc_path and libc_path:match("^(.*)/"),
            "the module is in libc's own library directory")
    end)

test("the module exports the six entry points and no other symbol, and each asks resolvd what the TRM's table says",
    { spec = "resolvd *nss-module.entry-points PSPU *nri-shim.entry-points" }, function(t)
        local r = pt(t, {
            { "elf", MODULE },
            { "n4", "both.nss.test" },
            { "n3", "both.nss.test", "2" }, { "n3", "both.nss.test", "10" },
            { "n2", "both.nss.test", "2" }, { "n2", "both.nss.test", "10" },
            { "n1", "both.nss.test" },
            { "a2", "10.88.0.1" }, { "a1", "10.88.0.1" },
        })
        local names = {}
        for _, e in ipairs(r[1].exports) do
            names[#names + 1] = e.name
            t:assert_eq(e.type, "func", e.name .. " is a function")
        end
        table.sort(names)
        same_list(t, names, ENTRY_POINTS, "the exported symbols are exactly the six entry points")

        local function asks(i, what, want)
            local q = r[i].request
            t:assert(q, what .. ": a request was written")
            for k, v in pairs(want) do t:assert_eq(q[k], v, what .. ": request " .. k) end
            local n = 0
            for _ in pairs(q) do n = n + 1 end
            local m = 0
            for _ in pairs(want) do m = m + 1 end
            t:assert_eq(n, m, what .. ": the request has no other field")
            t:assert_eq(r[i].status, NSS.SUCCESS, what .. ": answered")
        end
        asks(2, "gethostbyname4_r", { query = "lookup", name = "both.nss.test", family = "any" })
        asks(3, "gethostbyname3_r AF_INET", { query = "lookup", name = "both.nss.test", family = "inet" })
        asks(4, "gethostbyname3_r AF_INET6", { query = "lookup", name = "both.nss.test", family = "inet6" })
        asks(5, "gethostbyname2_r AF_INET", { query = "lookup", name = "both.nss.test", family = "inet" })
        asks(6, "gethostbyname2_r AF_INET6", { query = "lookup", name = "both.nss.test", family = "inet6" })
        asks(7, "gethostbyname_r", { query = "lookup", name = "both.nss.test", family = "inet" })
        t:assert_eq(r[7].addrtype, AF.INET, "gethostbyname_r answers AF_INET")
        asks(8, "gethostbyaddr2_r", { query = "reverse", address = "10.88.0.1" })
        asks(9, "gethostbyaddr_r", { query = "reverse", address = "10.88.0.1" })
        -- gethostbyname3_r reports a TTL and canonical name; 2_r and _r
        -- have no such out-parameters; gethostbyaddr2_r reports a TTL and
        -- gethostbyaddr_r none (pt-nss's -77 is left in place).
        t:assert_eq(r[3].ttl, 0, "gethostbyname3_r writes the TTL (a static name's is 0)")
        t:assert_eq(r[3].canon_is_h_name, 1, "gethostbyname3_r points canonp at h_name")
        t:assert_eq(r[5].ttl, -77, "gethostbyname2_r has no TTL out")
        t:assert_eq(r[8].ttl, 0, "gethostbyaddr2_r writes the TTL")
        t:assert_eq(r[9].ttl, -77, "gethostbyaddr_r has no TTL out")
    end)

test("the module needs only libc.so.6 and ld-linux-x86-64.so.2; the codec and unwinder are compiled in",
    { spec = "resolvd *nss-module.link-dependencies", tags = { "pei-1374" } }, function(t)
        local r = pt(t, { { "elf", MODULE } })
        t:log("needed: " .. list(r[1].needed))
        t:assert(#r[1].needed > 0, "the module's dynamic section was read")
        local needed = {}
        for i, n in ipairs(r[1].needed) do
            needed[i] = n
            t:assert(not n:find("peios", 1, true), "it does not link libpeios (" .. n .. ")")
        end
        table.sort(needed)
        t:assert_eq(table.concat(needed, " "), "ld-linux-x86-64.so.2 libc.so.6",
            "exactly libc and the dynamic loader")
    end)

test("the shim links against libc and the wire codec and nothing else",
    { spec = "PSPU *nri-shim.links-libc-and-codec-only", tags = { "pei-1374" } }, function(t)
        local r = pt(t, { { "elf", MODULE } })
        t:log("needed: " .. list(r[1].needed))
        t:assert(#r[1].needed > 0, "the module's dynamic section was read")
        for _, n in ipairs(r[1].needed) do
            t:assert(n == "libc.so.6" or n == "ld-linux-x86-64.so.2",
                "needed " .. n .. " is libc (the codec is compiled in)")
        end
    end)

test("identity and host lookups load both NSS modules without loading libgcc_s",
    { tags = { "pei-1374" } }, function(t)
        sut:run("lps group create pt-nss-group"):assert_ok()
        sut:run("lps add pt-nss-user --no-password --disabled --no-prompt --primary-group pt-nss-group"):assert_ok()
        local r = pt(t, {
            { "elf", "/usr/lib/x86_64-linux-peios/libnss_peios.so.2" },
            { "gai", "localhost", "0" }, { "identity" },
        })
        local needed = r[1].needed
        table.sort(needed)
        t:assert_eq(table.concat(needed, " "), "ld-linux-x86-64.so.2 libc.so.6",
            "identity shim also needs only libc and its loader")
        t:assert_eq(r[2].gai, 0, "host lookup succeeds")
        for _, field in ipairs({ "by_name", "by_id", "group_by_name", "group_by_id", "identity_loaded" }) do
            t:assert_eq(r[3][field], 1, field)
        end
        t:assert_eq(r[3].gcc_loaded, 0, "neither lookup loaded libgcc_s into this fresh process")
    end)

-- ---------------------------------------------------------------------------
-- localhost and loopback, in the process
-- ---------------------------------------------------------------------------

test("localhost, a name under it and a loopback address are answered with no socket: 127.0.0.1 then ::1, canonical localhost, TTL 0; h_name localhost with no aliases for the reverse",
    { spec = "resolvd *nss-forward.localhost-answer PSPU *nri-shim.answers-localhost-itself resolvd *nss-reverse.loopback-answered-in-process" }, function(t)
        local r = pt(t, {
            { "n4", "localhost" }, { "n4", "LOCALHOST." }, { "n4", "printer.Localhost" },
            { "n3", "localhost", "2" }, { "n3", "localhost", "10" },
            { "a2", "127.0.0.1" }, { "a2", "127.9.8.7" }, { "a2", "::1" },
        })
        for i = 1, 3 do
            local x = r[i]
            no_socket(t, x, x.op .. " #" .. i)
            t:assert_eq(x.status, NSS.SUCCESS, "#" .. i .. " found")
            t:assert_eq(#x.tuples, 2, "#" .. i .. " two addresses")
            t:assert_eq(x.tuples[1] and x.tuples[1].addr, "127.0.0.1", "#" .. i .. " IPv4 first")
            t:assert_eq(x.tuples[2] and x.tuples[2].addr, "::1", "#" .. i .. " then IPv6")
            t:assert_eq(x.name, "localhost", "#" .. i .. " canonical localhost")
            t:assert_eq(x.ttl, 0, "#" .. i .. " TTL 0")
        end
        for i, want in pairs({ [4] = "127.0.0.1", [5] = "::1" }) do
            no_socket(t, r[i], "gethostbyname3_r #" .. i)
            t:assert_eq(r[i].status, NSS.SUCCESS, "#" .. i .. " found")
            same_list(t, r[i].addrs, { want }, "#" .. i .. " the one address of the family")
            t:assert_eq(r[i].h_name, "localhost", "#" .. i .. " h_name")
            t:assert_eq(r[i].ttl, 0, "#" .. i .. " TTL 0")
        end
        for i = 6, 8 do
            no_socket(t, r[i], "gethostbyaddr2_r #" .. i)
            t:assert_eq(r[i].status, NSS.SUCCESS, "#" .. i .. " found")
            t:assert_eq(r[i].h_name, "localhost", "#" .. i .. " h_name localhost")
            t:assert_eq(r[i].aliases, 0, "#" .. i .. " no aliases")
            t:assert_eq(r[i].ttl, 0, "#" .. i .. " TTL 0")
        end
    end)

-- ---------------------------------------------------------------------------
-- found: the hostent and the address tuples
-- ---------------------------------------------------------------------------

test("a found name is SUCCESS; the tuples and the hostent carry the reply's addresses in reply order, one tuple each with its own family and one shared name; the hostent's h_name is the reply's canonical name, with no aliases",
    { spec = "resolvd *nss-module.found-is-success PSPU *nri-shim.found-is-success resolvd *nss-forward.hostent-layout resolvd *nss-forward.reply-order-kept resolvd *nss-forward.gaih-addrtuple-order resolvd *nss-forward.gaih-addrtuple-name-shared resolvd *nss-forward.gaih-addrtuple-family" }, function(t)
        local r = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "2" }, { "n2", "both.nss.test", "10" } })
        local n4, n3, n2 = r[1], r[2], r[3]
        for _, x in ipairs(r) do
            t:assert_eq(x.status, NSS.SUCCESS, x.op .. ": SUCCESS")
            t:assert(x.reply and x.reply.outcome == "found", x.op .. ": resolvd said found")
        end
        local reply4 = addresses_of(n4.reply)
        local got4 = {}
        for _, tu in ipairs(n4.tuples) do
            got4[#got4 + 1] = tu.addr
            t:assert_eq(tu.family, tu.addr:find(":", 1, true) and AF.INET6 or AF.INET, tu.addr .. ": its own family")
        end
        same_list(t, got4, reply4, "one tuple per address, in the reply's order")
        t:assert_eq(#got4, 4, "all four addresses")
        t:assert_eq(n4.name_shared, 1, "every tuple points at one copy of the name")
        t:assert_eq(n4.name, n4.reply.canonical, "the name is the reply's canonical name")

        same_list(t, n3.addrs, addresses_of(n3.reply), "gethostbyname3_r: h_addr_list in the reply's order")
        same_list(t, n3.addrs, { "10.88.0.1", "10.88.0.2" }, "gethostbyname3_r AF_INET: both IPv4 addresses")
        t:assert_eq(n3.h_name, n3.reply.canonical, "h_name is the reply's canonical name")
        t:assert_eq(n3.aliases, 0, "h_aliases is empty")
        t:assert_eq(n3.addrtype, AF.INET, "h_addrtype is the af asked")
        t:assert_eq(n3.length, 4, "h_length 4")

        same_list(t, n2.addrs, addresses_of(n2.reply), "gethostbyname2_r AF_INET6: reply order")
        same_list(t, n2.addrs, { "fd88::1", "fd88::2" }, "both IPv6 addresses")
        t:assert_eq(n2.addrtype, AF.INET6, "h_addrtype AF_INET6")
        t:assert_eq(n2.length, 16, "h_length 16")
        t:assert_eq(n2.aliases, 0, "h_aliases is empty")
    end)

test("an IPv6 link-local address comes back in a tuple with scope id 0",
    { spec = "resolvd *nss-forward.gaih-addrtuple-scopeid-zero" }, function(t)
        local r = pt(t, { { "n4", "ll.nss.test" } })[1]
        t:assert_eq(r.status, NSS.SUCCESS, "found")
        t:assert_eq(#r.tuples, 1, "one address")
        t:assert_eq(r.tuples[1].addr, "fe80::5", "the link-local address")
        t:assert_eq(r.tuples[1].family, AF.INET6, "AF_INET6")
        t:assert_eq(r.tuples[1].scopeid, 0, "scope id 0")
    end)

-- ---------------------------------------------------------------------------
-- found, but not in the family asked
-- ---------------------------------------------------------------------------

test("a name resolvd finds with no address of the family asked is NOTFOUND, ENOENT, NO_DATA",
    { spec = "resolvd *nss-module.found-without-family-is-no-data" }, function(t)
        local r = pt(t, { { "n3", "v4only.nss.test", "10" }, { "n2", "v4only.nss.test", "10" } })
        for _, x in ipairs(r) do
            t:assert(x.reply and x.reply.outcome == "found", x.op .. ": resolvd said found")
            t:assert_eq(#addresses_of(x.reply), 0, x.op .. ": with no IPv6 address")
            expect(t, x, NSS.NOTFOUND, E.ENOENT, H.NO_DATA, x.op)
        end
    end)

test("a found name with no address of the family asked is NOTFOUND with NO_DATA",
    { spec = "PSPU *nri-shim.found-without-family-is-no-data" }, function(t)
        local r = pt(t, { { "n3", "v4only.nss.test", "10" } })[1]
        t:assert(r.reply and r.reply.outcome == "found" and #addresses_of(r.reply) == 0,
            "resolvd said found, with no IPv6 address")
        expect(t, r, NSS.NOTFOUND, E.ENOENT, H.NO_DATA, "found without the requested family")
    end)

-- ---------------------------------------------------------------------------
-- Families, bad input, buffers
-- ---------------------------------------------------------------------------

test("an unsupported family is UNAVAIL with EAFNOSUPPORT: NO_DATA forward (AF_UNSPEC too, except through gethostbyname4_r, which asks for both), NO_RECOVERY in reverse for any af/length but AF_INET/4 and AF_INET6/16",
    { spec = "resolvd *nss-module.unsupported-family-forward resolvd *nss-module.af-unspec-only-via-gethostbyname4 resolvd *nss-module.unsupported-family-reverse" }, function(t)
        local r = pt(t, {
            { "n3", "both.nss.test", "1" }, { "n2", "both.nss.test", "1" },
            { "n3", "both.nss.test", "0" }, { "n2", "both.nss.test", "0" },
            { "n4", "both.nss.test" },
            { "a2", "10.88.0.1", "2", "16" }, { "a2", "10.88.0.1", "10", "4" },
            { "a1", "10.88.0.1", "1", "4" }, { "a2", "10.88.0.1", "0", "4" },
        })
        for i = 1, 4 do
            expect(t, r[i], NSS.UNAVAIL, E.EAFNOSUPPORT, H.NO_DATA, r[i].op .. " af " .. (i <= 2 and "AF_UNIX" or "AF_UNSPEC"))
            no_socket(t, r[i], r[i].op .. " #" .. i)
        end
        t:assert_eq(r[5].status, NSS.SUCCESS, "gethostbyname4_r answers")
        t:assert_eq(r[5].request and r[5].request.family, "any", "gethostbyname4_r asks for family any")
        local fams = {}
        for _, tu in ipairs(r[5].tuples) do fams[tu.family] = true end
        t:assert(fams[AF.INET] and fams[AF.INET6], "and returns both families")
        for i = 6, 9 do
            expect(t, r[i], NSS.UNAVAIL, E.EAFNOSUPPORT, H.NO_RECOVERY, r[i].op .. " #" .. i)
            no_socket(t, r[i], r[i].op .. " #" .. i)
        end
    end)

test("a null name, a name that is not UTF-8 and a null address are NOTFOUND, ENOENT, HOST_NOT_FOUND",
    { spec = "resolvd *nss-module.null-or-non-utf8-input-is-notfound" }, function(t)
        local r = pt(t, {
            { "n4", "@null" }, { "n3", "@null", "2" }, { "n1", "@null" },
            { "n4", "@hex:ff2e6e73732e74657374" }, { "n3", "@hex:c3286e7373", "2" },
            { "a2", "@null" }, { "a1", "@null" },
        })
        for i, x in ipairs(r) do expect(t, x, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, x.op .. " #" .. i) end
    end)

test("a buffer too small for the result is TRYAGAIN, ERANGE, NETDB_INTERNAL; everything a successful call returns lies inside the caller's buffer",
    { spec = "resolvd *nss-module.small-buffer-is-erange resolvd *nss-module.results-placed-in-caller-buffer" }, function(t)
        local small = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "10" },
                              { "n2", "both.nss.test", "2" }, { "a2", "10.88.0.1" }, { "a1", "10.88.0.1" },
                              { "n1", "localhost" }, { "n4", "localhost" } }, { buf = 16 })
        for i, x in ipairs(small) do
            expect(t, x, NSS.TRYAGAIN, E.ERANGE, H.NETDB_INTERNAL, x.op .. " #" .. i .. " with a 16-byte buffer")
        end
        local ok = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "10" }, { "a2", "10.88.0.1" },
                           { "n4", "many.nss.test" } })
        for i, x in ipairs(ok) do
            t:assert_eq(x.status, NSS.SUCCESS, x.op .. " #" .. i .. " found")
            t:assert_eq(x.inbuf, 1, x.op .. " #" .. i .. ": every name, pointer array, address and tuple is in the buffer")
        end
        t:assert_eq(#ok[4].tuples, MANY_N, "the " .. MANY_N .. "-address name fits a 64 KiB buffer")
    end)

test("an over-full caller buffer is TRYAGAIN with ERANGE, so glibc retries with a larger one",
    { spec = "PSPU *nri-shim.over-full-buffer-is-tryagain-erange" }, function(t)
        -- PEI-1341: glibc grows its buffer only for the complete
        -- TRYAGAIN + ERANGE + NETDB_INTERNAL result. Check the installed
        -- module's triple as well as the real glibc retry paths.
        local direct = pt(t, { { "n4", "many.nss.test" } }, { buf = 64 })[1]
        expect(t, direct, NSS.TRYAGAIN, E.ERANGE, H.NETDB_INTERNAL, "the module's over-full buffer result")
        local r = pt(t, { { "gai", "many.nss.test", "0" }, { "gai", "many.nss.test", "2" },
                          { "ghbn", "many.nss.test", "2" } }, { buf = 64 })
        for i = 1, 2 do
            t:log("getaddrinfo #" .. i .. ": " .. tostring(r[i].gai) .. " " .. tostring(r[i].gaistr) .. ", "
                .. tostring(r[i].count) .. " addresses")
        end
        t:log("gethostbyname2_r with a 64-byte buffer: ret " .. tostring(r[3].ret) .. ", h_errno " .. tostring(r[3].herrno)
            .. "; gethostbyname2: found " .. tostring(r[3].growing_found) .. ", h_errno " .. tostring(r[3].growing_herrno))
        t:assert_eq(r[1].gai, 0, "getaddrinfo(AF_UNSPEC) retries with a larger buffer and succeeds")
        t:assert_eq(r[1].count, MANY_N, "with every address")
        t:assert_eq(r[2].gai, 0, "getaddrinfo(AF_INET) retries with a larger buffer and succeeds")
        t:assert_eq(r[2].count, MANY_N, "with every address")
        t:assert_eq(r[3].ret, E.ERANGE, "gethostbyname2_r passes ERANGE back, so its caller can grow the buffer")
        t:assert_eq(r[3].herrno, H.NETDB_INTERNAL, "gethostbyname2_r identifies caller-buffer exhaustion")
        t:assert_eq(r[3].growing_count, MANY_N, "gethostbyname2, which grows its own buffer, returns every address")
    end)

-- ---------------------------------------------------------------------------
-- Connections, files, timeouts, caching
-- ---------------------------------------------------------------------------

test("every call that needs resolvd opens one connection to resolv.sock with ten-second read and write timeouts, sends one request, reads one reply and closes it; nothing is held between calls and no file is opened",
    { spec = "resolvd *nss-module.one-connection-per-call resolvd *nss-module.no-state-no-files resolvd *nss-module.ten-second-socket-timeouts PSPU *nri-shim.one-connection-per-call PSPU *nri-shim.no-connection-across-calls PSPU *nri-shim.reads-no-file" }, function(t)
        local r = pt(t, {
            { "n4", "both.nss.test" }, { "n4", "both.nss.test" }, { "n3", "both.nss.test", "2" },
            { "n2", "both.nss.test", "10" }, { "n1", "both.nss.test" },
            { "a2", "10.88.0.1" }, { "a1", "10.88.0.2" },
            { "gai", "both.nss.test", "0" }, { "ghbn", "both.nss.test", "2" }, { "ghba", "10.88.0.1" },
        })
        for i, x in ipairs(r) do
            local what = x.op .. " #" .. i
            one_connection(t, x, what)
            t:assert(x.request ~= nil, what .. ": one request written")
            t:assert(x.reply ~= nil, what .. ": one reply read")
            t:assert_eq(#x.opens, 0, what .. ": no file opened (" .. list(x.opens) .. ")")
            local rcv, snd = x.timeouts.rcvtimeo, x.timeouts.sndtimeo
            t:assert(rcv and rcv.sec == 10 and rcv.usec == 0, what .. ": a ten-second read timeout")
            t:assert(snd and snd.sec == 10 and snd.usec == 0, what .. ": a ten-second write timeout")
        end
        t:assert_eq(r[8].gai, 0, "getaddrinfo found the name")
        t:assert_eq(r[9].found, 1, "gethostbyname2_r found the name")
        t:assert_eq(r[10].found, 1, "gethostbyaddr found the address")
    end)

test("the shim does not cache: a second call in the same process asks resolvd again and gets the changed answer",
    { spec = "PSPU *nri-shim.does-not-cache" }, function(t)
        sut:run("rm -f /tmp/r11-first /tmp/r11-go")
        local p = sut:run_async("sh", { args = { "-c",
            "pt-nss n4 change.nss.test + touch /tmp/r11-first + wait /tmp/r11-go + n4 change.nss.test" } })
        wait_until(function() return sut:run("test -e /tmp/r11-first").exit_code == 0 end,
            { timeout = 20, interval = 0.2, desc = "the first call done" })
        network.write(sut, "Dns\\Hosts", { ["change.nss.test"] = "sz:10.88.0.8" })
        wait_until(function()
            local a = native({ query = "lookup", name = "change.nss.test", family = "inet" })
            return list(addresses_of(a)) == "[10.88.0.8]"
        end, { timeout = 20, interval = 0.2, desc = "resolvd answering the new address" })
        sut:run("touch /tmp/r11-go")
        local done = p:wait(30)
        t:log(done.stdout)
        local r = parse(done.stdout)
        local first, second = r[1], r[4]
        t:assert(first and second, "both calls ran")
        t:assert_eq(first.tuples[1] and first.tuples[1].addr, "10.88.0.7", "the first call: the old address")
        one_connection(t, second, "the second call")
        t:assert_eq(second.tuples[1] and second.tuples[1].addr, "10.88.0.8", "the second call: the new address")
    end)

-- ---------------------------------------------------------------------------
-- Through the network: TTLs, canonical names, notfound, reverse
-- ---------------------------------------------------------------------------

test("gethostbyname3_r: h_name is the reply's canonical name (the end of the CNAME chain), canonp points at it, and the TTL is the least among the addresses, not the CNAME's",
    { spec = "resolvd *nss-forward.gethostbyname3-ttl-and-canon PSPU *nri-shim.h-name-is-canonical PSPU *nri-shim.ttl-is-least-address-ttl" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "n3", "alias.example.test", "2" }, { "n3", "ttl.example.test", "2" } }, { serve = true })
        local a = r[1]
        t:assert_eq(a.status, NSS.SUCCESS, "alias.example.test found")
        t:assert_eq(a.reply and a.reply.canonical, "www.example.test", "resolvd's canonical name is the chain's end")
        t:assert_eq(a.h_name, "www.example.test", "h_name is the canonical name")
        t:assert_eq(a.canon_is_h_name, 1, "canonp points at h_name")
        same_list(t, a.addrs, { "10.77.0.80" }, "the address")
        t:assert_eq(a.ttl, 60, "the TTL is the address's (60), not the CNAME's (30)")
        local b = r[2]
        t:assert_eq(b.status, NSS.SUCCESS, "ttl.example.test found")
        t:assert_eq(b.ttl, 120, "the least of the IPv4 addresses' TTLs (300, 120)")
        t:assert_eq(b.h_name, b.reply and b.reply.canonical, "h_name is the canonical name")
    end)

test("gethostbyname4_r's TTL is the least among all the addresses",
    { spec = "resolvd *nss-forward.gethostbyname4-ttl-least" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "n4", "ttl4.example.test" } }, { serve = true })[1]
        t:assert_eq(r.status, NSS.SUCCESS, "found")
        t:assert_eq(#r.tuples, 3, "three addresses")
        local ttls = {}
        for _, a in ipairs((r.reply and r.reply.addresses) or {}) do ttls[#ttls + 1] = tostring(a.ttl) end
        t:log("the reply's TTLs: " .. list(ttls))
        t:assert_eq(r.ttl, 120, "the least TTL (300, 120, 200)")
    end)

test("notfound is NOTFOUND, ENOENT, HOST_NOT_FOUND",
    { spec = "resolvd *nss-module.notfound-is-host-not-found PSPU *nri-shim.notfound-is-host-not-found" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "n4", "nosuch.example.test" }, { "n3", "nosuch.example.test", "2" },
                         { "a2", "10.77.0.85" }, { "a1", "10.77.0.85" } }, { serve = true })
        for _, x in ipairs(r) do
            t:assert_eq(x.reply and x.reply.outcome, "notfound", x.op .. ": resolvd said notfound")
            expect(t, x, NSS.NOTFOUND, E.ENOENT, H.HOST_NOT_FOUND, x.op)
        end
    end)

test("a reverse is rendered from the PTR records in order, trailing dots removed: the first is h_name, the rest are aliases, the address alone in h_addr_list; the TTL is the least of all the reply's records, PTR or not",
    { spec = "resolvd *nss-reverse.hostent-layout resolvd *nss-reverse.ttl-least-of-all-records" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "a2", "10.77.0.81" }, { "a2", "10.77.0.82" } }, { serve = true })
        local a = r[1]
        t:assert_eq(a.status, NSS.SUCCESS, "10.77.0.81 found")
        local texts = {}
        for _, rec in ipairs((a.reply and a.reply.records) or {}) do texts[#texts + 1] = rec.text end
        t:log("the reply's records: " .. list(texts))
        t:assert_eq(a.h_name, "ptr-one.example.test", "h_name is the first PTR, without a trailing dot")
        same_list(t, a.alias_list, { "ptr-two.example.test" }, "the second PTR is the alias")
        t:assert_eq(a.aliases, 1, "and the only one")
        t:assert_eq(a.addrtype, AF.INET, "h_addrtype")
        t:assert_eq(a.length, 4, "h_length")
        same_list(t, a.addrs, { "10.77.0.81" }, "the address asked, alone")
        t:assert_eq(a.ttl, 200, "the least TTL of the two PTRs (400, 200)")
        local b = r[2]
        t:assert_eq(b.status, NSS.SUCCESS, "10.77.0.82 found")
        local types = {}
        for _, rec in ipairs((b.reply and b.reply.records) or {}) do types[#types + 1] = tostring(rec.type) end
        t:log("the reply's record types: " .. list(types))
        t:assert_eq(b.h_name, "classless.example.test", "h_name is the PTR at the end of the CNAME")
        t:assert_eq(b.aliases, 0, "a CNAME is not an alias")
        t:assert_eq(b.ttl, 30, "the least TTL includes the CNAME's (30) as well as the PTR's (300)")
    end)

test("a reverse found with no records, or with records but no PTR among them, is NOTFOUND with NO_DATA",
    { spec = "resolvd *nss-reverse.found-without-records-is-notfound resolvd *nss-reverse.no-ptr-record-is-notfound" }, function(t)
        scope_ready(t)
        local r = pt(t, { { "a2", "10.77.0.84" }, { "a2", "10.77.0.83" } }, { serve = true })
        local empty, cname = r[1], r[2]
        t:assert_eq(empty.reply and empty.reply.outcome, "found", "10.77.0.84: resolvd said found")
        t:assert_eq(#((empty.reply and empty.reply.records) or {}), 0, "10.77.0.84: with no records")
        expect(t, empty, NSS.NOTFOUND, E.ENOENT, H.NO_DATA, "found without records")
        t:assert_eq(cname.reply and cname.reply.outcome, "found", "10.77.0.83: resolvd said found")
        local recs = (cname.reply and cname.reply.records) or {}
        t:assert(#recs > 0, "10.77.0.83: with records")
        for _, rec in ipairs(recs) do t:assert(rec.type ~= 12, "none of them a PTR (type " .. tostring(rec.type) .. ")") end
        expect(t, cname, NSS.NOTFOUND, E.ENOENT, H.NO_DATA, "records but no PTR")
    end)

-- ---------------------------------------------------------------------------
-- Replies the real resolvd cannot be made to give (the stand-in server)
-- ---------------------------------------------------------------------------

test("no reply within ten seconds is TRYAGAIN, EAGAIN, TRY_AGAIN",
    { spec = "resolvd *nss-module.timeout-is-try-again" }, function(t)
        local r = pt(t, { { "n4", "quiet.nss.test" }, { "a2", "10.66.0.1" } }, { fake = "silent", timeout = 90 })
        for _, x in ipairs(r) do
            t:assert_eq(x.connects[1] and x.connects[1].ret, 0, x.op .. ": connected (to the stand-in)")
            t:assert(x.request ~= nil, x.op .. ": the request was sent")
            t:assert(x.elapsed_ms >= 9800 and x.elapsed_ms < 13000,
                x.op .. ": gave up after ten seconds (" .. x.elapsed_ms .. " ms)")
            t:assert_eq(x.recv_errors[1] and x.recv_errors[1].errno, E.EAGAIN, x.op .. ": the read timed out")
            expect(t, x, NSS.TRYAGAIN, E.EAGAIN, H.TRY_AGAIN, x.op)
        end
    end)

test("a reply of the wrong kind, a reply that does not decode, an oversized frame and a closed connection are UNAVAIL, ENOENT, NO_RECOVERY",
    { spec = "resolvd *nss-module.other-failures-are-unavail" }, function(t)
        local status = frame_hex({ ok = true, kind = "status", hostname = "x", netd = false,
            scopes = msgpack.array({}), fallback_servers = msgpack.array({}), cache_entries = 0,
            counters = { queries = 0 } })
        local addresses = frame_hex({ ok = true, kind = "addresses", outcome = "found", canonical = "x",
            addresses = { { address = "10.66.0.1", ttl = 5 } }, source = "dns", validation = "unvalidated" })
        local cases = {
            { "a status reply to a lookup", status, { "n4", "odd.nss.test" } },
            { "an ok with no kind to a lookup", frame_hex({ ok = true }), { "n3", "odd.nss.test", "2" } },
            { "an addresses reply to a reverse", addresses, { "a2", "10.66.0.1" } },
            { "bytes that are not MessagePack", frame_hex("\xc1\xc1\xc1"), { "n4", "odd.nss.test" } },
            { "a map without ok", frame_hex({ kind = "addresses" }), { "n4", "odd.nss.test" } },
            { "a frame longer than 65,536 bytes", hex(string.pack("<I4", 65537)) .. "00", { "n4", "odd.nss.test" } },
            { "a short frame then the close", hex(string.pack("<I4", 40)) .. "81a26f6b", { "n4", "odd.nss.test" } },
        }
        for _, c in ipairs(cases) do
            local x = pt(t, { c[3] }, { fake = "hex:" .. c[2] })[1]
            t:assert_eq(x.connects[1] and x.connects[1].ret, 0, c[1] .. ": connected (to the stand-in)")
            expect(t, x, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, c[1])
        end
        local closed = pt(t, { { "n4", "odd.nss.test" } }, { fake = "close" })[1]
        expect(t, closed, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, "the connection closed with no reply")
    end)

test("a name is asked as a lookup in the entry point's family, the reply's addresses are filtered to that family, and an empty result is NOTFOUND",
    { spec = "resolvd *nss-forward.addresses-filtered-to-family" }, function(t)
        -- A reply carrying both families to a single-family question,
        -- which resolvd itself never sends.
        local mixed = frame_hex({ ok = true, kind = "addresses", outcome = "found", canonical = "mix.nss.test",
            addresses = { { address = "fd66::1", ttl = 50 }, { address = "10.66.0.1", ttl = 40 },
                          { address = "fd66::2", ttl = 45 }, { address = "10.66.0.2", ttl = 30 } },
            source = "dns", validation = "unvalidated" })
        local r = pt(t, { { "n3", "mix.nss.test", "2" }, { "n2", "mix.nss.test", "10" }, { "n1", "mix.nss.test" },
                          { "n4", "mix.nss.test" } }, { fake = "hex:" .. mixed })
        t:assert_eq(r[1].request and r[1].request.family, "inet", "gethostbyname3_r AF_INET asks inet")
        same_list(t, r[1].addrs, { "10.66.0.1", "10.66.0.2" }, "AF_INET: the IPv4 addresses only, in order")
        t:assert_eq(r[1].ttl, 30, "the TTL is the least among the kept addresses")
        t:assert_eq(r[2].request and r[2].request.family, "inet6", "gethostbyname2_r AF_INET6 asks inet6")
        same_list(t, r[2].addrs, { "fd66::1", "fd66::2" }, "AF_INET6: the IPv6 addresses only, in order")
        same_list(t, r[3].addrs, { "10.66.0.1", "10.66.0.2" }, "gethostbyname_r: IPv4 only")
        t:assert_eq(#r[4].tuples, 4, "gethostbyname4_r keeps every family")

        local v6only = frame_hex({ ok = true, kind = "addresses", outcome = "found", canonical = "six.nss.test",
            addresses = { { address = "fd66::6", ttl = 50 } }, source = "dns", validation = "unvalidated" })
        local e = pt(t, { { "n3", "six.nss.test", "2" } }, { fake = "hex:" .. v6only })[1]
        t:assert_eq(e.reply and e.reply.outcome, "found", "the stand-in said found")
        same_list(t, addresses_of(e.reply), { "fd66::6" }, "only the unrequested family arrived")
        expect(t, e, NSS.NOTFOUND, E.ENOENT, H.NO_DATA, "nothing left after the filter")
    end)

-- ---------------------------------------------------------------------------
-- glibc's hosts database
-- ---------------------------------------------------------------------------

test("glibc's hosts database is peios_net whatever nsswitch.conf or __nss_configure_lookup says, and /etc/hosts is not read",
    { spec = "PSPU *nri-shim.hosts-database-fixed-to-peios-net" }, function(t)
        scope_ready(t)
        local cfg = pt(t, { { "cfg", "hosts", "files" } })[1]
        t:assert_eq(cfg.ret, -1, "__nss_configure_lookup(\"hosts\", \"files\") is refused")
        sut:run("mkdir -p /etc")
        sut:run("printf 'hosts: files\\n' > /etc/nsswitch.conf")
        sut:run("printf '10.66.0.9 filesonly.nss.test\\n' > /etc/hosts")
        local written = sut:run("cat /etc/nsswitch.conf /etc/hosts")
        t:log(written.stdout .. written.stderr)
        t:assert(written.stdout:find("hosts: files", 1, true) and written.stdout:find("filesonly", 1, true),
            "the test wrote /etc/nsswitch.conf and /etc/hosts")
        local r = pt(t, { { "gai", "filesonly.nss.test", "0" }, { "gai", "both.nss.test", "2" } }, { serve = true })
        t:assert(r[1].gai ~= 0, "the /etc/hosts name does not resolve (" .. tostring(r[1].gaistr) .. ")")
        one_connection(t, r[1], "getaddrinfo(filesonly.nss.test) went to resolvd")
        t:assert_eq(r[2].gai, 0, "a static name resolves")
        one_connection(t, r[2], "getaddrinfo(both.nss.test) went to resolvd")
        local ge = served("getent hosts filesonly.nss.test")
        t:assert_eq(ge.exit_code, 2, "getent hosts: not found")
        sut:run("rm -f /etc/nsswitch.conf /etc/hosts")
    end)

-- ---------------------------------------------------------------------------
-- unavailable (late in the file: the silent server may get demoted)
-- ---------------------------------------------------------------------------

test("unavailable from resolvd is TRYAGAIN, EAGAIN, TRY_AGAIN, not NOTFOUND",
    { spec = "resolvd *nss-module.unavailable-is-try-again PSPU *nri-shim.unavailable-is-tryagain" }, function(t)
        scope_ready(t)
        dns.forget(gw)
        local x = pt(t, { { "n4", "slow.example.test" } }, { serve = true, timeout = 60 })[1]
        local asked = dns.queries(gw, function(e) return e.msg and e.msg.questions[1]
            and dns.same_name(e.msg.questions[1].name, "slow.example.test") end)
        t:log(#asked .. " questions for slow.example.test reached the (silent) gateway")
        t:assert(#asked > 0, "resolvd asked the gateway, which did not answer")
        t:assert_eq(x.reply and x.reply.outcome, "unavailable", "resolvd said unavailable (its attempts ran out)")
        t:assert(x.elapsed_ms < 10000, "resolvd answered inside the shim's ten seconds (" .. x.elapsed_ms .. " ms)")
        expect(t, x, NSS.TRYAGAIN, E.EAGAIN, H.TRY_AGAIN, "gethostbyname4_r")
    end)

-- ---------------------------------------------------------------------------
-- An error reply, then resolvd unreachable (left stopped for the next test)
-- ---------------------------------------------------------------------------

test("an error reply (access denied) and an unreachable resolvd are UNAVAIL, ENOENT, NO_RECOVERY",
    { spec = "resolvd *nss-module.error-reply-is-unavail resolvd *nss-module.unreachable-is-unavail PSPU *nri-shim.unreachable-or-error-is-no-recovery PSPU *nri-shim.unreachable-resolver-is-unavail" }, function(t)
        local dnskey = network.KEY .. "\\Dns"
        -- SYSTEM may only flush: lookup and reverse are denied to everyone.
        network.reg(sut, { "set", dnskey, "ControlSecurity", "hex:" .. peinit.system_descriptor_hex(0x2) }):assert_ok()
        wait_until(function()
            local a = native({ query = "lookup", name = "both.nss.test", family = "any" })
            return a and a.ok == false and a.error == "access denied"
        end, { timeout = 20, interval = 0.2, desc = "resolvd denying lookups" })
        local denied = pt(t, { { "n4", "both.nss.test" }, { "a2", "10.88.0.1" } })
        network.reg(sut, { "del", dnskey, "ControlSecurity" })
        wait_until(function()
            local a = native({ query = "lookup", name = "both.nss.test", family = "any" })
            return a and a.ok == true
        end, { timeout = 20, interval = 0.2, desc = "resolvd answering again" })
        for _, x in ipairs(denied) do
            t:assert(x.reply and x.reply.ok == false, x.op .. ": resolvd replied with an error")
            t:assert_eq(x.reply and x.reply.error, "access denied", x.op .. ": access denied")
            expect(t, x, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, x.op .. " (error reply)")
        end

        sut:run("svctl stop resolvd", { timeout = 60 })
        wait_until(function() return native({ query = "status" }) == nil end,
            { timeout = 30, interval = 0.3, desc = "resolv.sock refusing connections" })
        local gone = pt(t, { { "n4", "both.nss.test" }, { "n3", "both.nss.test", "2" }, { "a2", "10.88.0.1" } })
        for _, x in ipairs(gone) do
            t:assert(x.connects[1] and x.connects[1].ret == -1, x.op .. ": the connect failed (errno "
                .. tostring(x.connects[1] and x.connects[1].errno) .. ")")
            expect(t, x, NSS.UNAVAIL, E.ENOENT, H.NO_RECOVERY, x.op .. " (resolvd stopped)")
        end
    end)

test("with resolvd stopped, localhost is still answered in the process, and the shim never falls back to DNS: no inet socket, no question on the wire",
    { spec = "resolvd *nss-forward.localhost-answered-in-process PSPU *nri-shim.speaks-no-dns" }, function(t)
        t:assert(native({ query = "status" }) == nil, "resolvd is still stopped")
        dns.forget(gw)
        local r = pt(t, { { "n4", "localhost" }, { "n3", "sub.LOCALHOST.", "10" }, { "n4", "www.example.test" },
                          { "gai", "www.example.test", "0" }, { "ghbn", "www.example.test", "2" } },
            { serve = true })
        for i = 1, 2 do
            no_socket(t, r[i], r[i].op .. " #" .. i)
            t:assert_eq(r[i].status, NSS.SUCCESS, r[i].op .. " #" .. i .. ": answered without resolvd")
        end
        same_list(t, r[2].addrs, { "::1" }, "sub.LOCALHOST. AF_INET6 is ::1")
        for i = 3, 5 do
            for _, s in ipairs(r[i].sockets) do
                t:assert_eq(s.family, 1, r[i].op .. ": only AF_UNIX sockets (saw family " .. s.family .. ")")
            end
            t:assert_eq(#r[i].inet_sends, 0, r[i].op .. ": no datagram sent")
        end
        t:assert_eq(r[3].status, NSS.UNAVAIL, "the shim gives UNAVAIL rather than asking DNS itself")
        t:assert(r[4].gai ~= 0, "getaddrinfo fails")
        -- Pump a little longer: anything sent would have reached the gateway.
        gw:serve({ timeout = 2, until_ = function() return false end })
        local asked = dns.queries(gw, function(e) return e.msg and e.msg.questions[1]
            and dns.same_name(e.msg.questions[1].name, "www.example.test") end)
        t:assert_eq(#asked, 0, "the gateway saw no question for www.example.test")

        -- PEI-1373: a resolvd started over the old /run/resolvd crash-loops
        -- on `native socket: Permission denied`; clear it first.
        sut:run("rm -rf /run/resolvd; svctl start resolvd", { timeout = 60 })
        wait_until(function()
            local s = native({ query = "status" })
            return s ~= nil and s.ok == true
        end, { timeout = 30, interval = 0.3, desc = "resolvd answering again" })
    end)
