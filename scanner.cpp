/*
 * ============================================================
 *  WinRecon.cpp  —  Host Discovery + Full Port Scanner
 *  For Pentest / Red Team Lab (Windows Pivot Machine)
 *
 *  Features:
 *    - ICMP ping sweep (IcmpSendEcho)
 *    - TCP Connect scan  (full connect, most accurate)
 *    - TCP SYN scan hint (raw socket, needs admin)
 *    - UDP scan on known ports
 *    - Banner grabbing (HTTP, FTP, SSH, SMTP, etc.)
 *    - Service/version fingerprinting
 *    - OS guess (TTL heuristic)
 *    - ARP + Reverse DNS
 *    - Multi-threaded (configurable)
 *    - Output: console table + TXT + CSV
 *
 *  Compile (MSVC Developer Prompt):
 *    cl /EHsc /O2 /std:c++17 WinRecon.cpp /link ws2_32.lib iphlpapi.lib
 *
 *  Compile (MinGW / cross from Kali):
 *    x86_64-w64-mingw32-g++ -O2 -std=c++17 -o WinRecon.exe WinRecon.cpp \
 *        -lws2_32 -liphlpapi -static
 *
 *  Usage:
 *    WinRecon.exe -h                          # help
 *    WinRecon.exe -scan 192.168.57.0/24       # host discovery only
 *    WinRecon.exe -port 192.168.57.10         # full port scan single host
 *    WinRecon.exe -port 192.168.57.10 -p 1-1024
 *    WinRecon.exe -port 192.168.57.10 -p top  # top 1000 ports
 *    WinRecon.exe -scan 192.168.57.0/24 -port -o result  # sweep + scan all
 * ============================================================
 */

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <map>
#include <set>
#include <functional>
#include <sstream>
#include <fstream>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

 // ════════════════════════════════════════════════════════════
 //  Constants & Config
 // ════════════════════════════════════════════════════════════
#define TOOL_VERSION        "2.0"
#define MAX_THREADS         128
#define DEFAULT_THREADS     64
#define ICMP_TIMEOUT_MS     1500
#define TCP_CONNECT_TIMEOUT 800     // ms per port
#define UDP_TIMEOUT_MS      1500
#define BANNER_TIMEOUT_MS   2000
#define BANNER_MAX_BYTES    512

// ════════════════════════════════════════════════════════════
//  Top 1000 ports (Nmap-style, sorted by frequency)
// ════════════════════════════════════════════════════════════
static const uint16_t TOP1000_PORTS[] = {
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
    2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
    544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
    // extended common ports
    8888, 4443, 8843, 8060, 4848, 7001, 7002, 9200, 9300, 5601,
    6379, 27017, 27018, 28017, 11211, 5984, 9042, 7474, 8291, 3690,
    1521, 1830, 5500, 9090, 9091, 8161, 61616, 8069, 8086, 8083,
    2375, 2376, 4243, 5000, 8080, 8500, 8600, 8787, 9389, 47001,
    // RDP, VNC variants
    3389, 3390, 3391, 5900, 5901, 5902, 5903,
    // SMB / NetBIOS
    135, 136, 137, 138, 139, 445,
    // Mail
    25, 26, 465, 587, 110, 143, 993, 995,
    // DNS
    53,
    // HTTP variants
    80, 81, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 8889,
    // DB
    1433, 1434, 3306, 5432, 1521, 27017, 6379, 9042,
    // Other
    22, 23, 21, 69, 161, 162, 500, 4500, 1194
};

// ════════════════════════════════════════════════════════════
//  Service name map (port → service name)
// ════════════════════════════════════════════════════════════
static std::map<uint16_t, std::string> SERVICE_MAP = {
    {7,    "echo"},      {9,    "discard"},   {13,   "daytime"},
    {21,   "ftp"},       {22,   "ssh"},       {23,   "telnet"},
    {25,   "smtp"},      {26,   "rsftp"},     {37,   "time"},
    {53,   "dns"},       {69,   "tftp"},      {79,   "finger"},
    {80,   "http"},      {81,   "http-alt"},  {88,   "kerberos"},
    {106,  "pop3pw"},    {110,  "pop3"},      {111,  "rpcbind"},
    {113,  "ident"},     {119,  "nntp"},      {135,  "msrpc"},
    {137,  "netbios-ns"},{138,  "netbios-dgm"},{139, "netbios-ssn"},
    {143,  "imap"},      {144,  "news"},      {161,  "snmp"},
    {162,  "snmptrap"},  {179,  "bgp"},       {199,  "smux"},
    {389,  "ldap"},      {427,  "svrloc"},    {443,  "https"},
    {444,  "snpp"},      {445,  "microsoft-ds"},{465, "smtps"},
    {500,  "isakmp"},    {513,  "login"},     {514,  "shell"},
    {515,  "printer"},   {543,  "klogin"},    {544,  "kshell"},
    {548,  "afp"},       {554,  "rtsp"},      {587,  "submission"},
    {631,  "ipp"},       {646,  "ldp"},       {873,  "rsync"},
    {990,  "ftps"},      {993,  "imaps"},     {995,  "pop3s"},
    {1025, "msrpc-ep"},  {1026, "msrpc-ep2"},{1027, "msrpc-ep3"},
    {1028, "msrpc-ep4"},{1029, "msrpc-ep5"},{1110, "nfsd-status"},
    {1194, "openvpn"},   {1433, "mssql"},     {1434, "mssql-mon"},
    {1521, "oracle"},    {1720, "h323"},      {1723, "pptp"},
    {1755, "wms"},       {1900, "upnp"},      {2000, "cisco-sccp"},
    {2001, "dc"},        {2049, "nfs"},       {2121, "ccproxy-ftp"},
    {2375, "docker"},    {2376, "docker-ssl"},{2717, "pn-requester"},
    {3000, "http-dev"},  {3128, "squid"},     {3306, "mysql"},
    {3389, "rdp"},       {3690, "svn"},       {3986, "mapper-ws-ethd"},
    {4443, "https-alt"}, {4500, "ipsec-nat"},{4848, "glassfish"},
    {4899, "radmin"},    {5000, "upnp-alt"},  {5009, "airport-admin"},
    {5051, "ida-agent"}, {5060, "sip"},       {5190, "aol"},
    {5357, "wsdapi"},    {5432, "postgresql"},{5500, "vnc-d"},
    {5601, "kibana"},    {5631, "pcanywhere"},{5666, "nrpe"},
    {5800, "vnc-http"},  {5900, "vnc"},       {5984, "couchdb"},
    {6000, "x11"},       {6001, "x11-1"},     {6379, "redis"},
    {6646, "unknown"},   {7001, "weblogic"},  {7002, "weblogic-ssl"},
    {7070, "realserver"},{7474, "neo4j"},     {8000, "http-alt"},
    {8001, "http-alt2"}, {8008, "http-alt3"}, {8009, "ajp"},
    {8060, "http-alt4"}, {8069, "odoo"},      {8080, "http-proxy"},
    {8081, "http-alt5"}, {8083, "influxdb"},  {8086, "influxdb-http"},
    {8088, "radan-http"},{8161, "activemq"},  {8291, "winbox"},
    {8443, "https-alt"}, {8500, "consul"},    {8600, "consul-dns"},
    {8787, "rdesktop"},  {8843, "https-alt"}, {8888, "http-alt6"},
    {8889, "http-alt7"}, {9009, "pichat"},    {9042, "cassandra"},
    {9090, "zeus-admin"},{9091, "xmltec"},    {9100, "jetdirect"},
    {9200, "elasticsearch"},{9300, "elasticsearch-cluster"},
    {9389, "adws"},      {10000,"webmin"},    {11211,"memcached"},
    {27017,"mongodb"},   {27018,"mongodb2"},  {28017,"mongodb-http"},
    {32768,"filenet"},   {47001,"winrm"},     {49152,"msrpc-dyn"},
    {49153,"msrpc-dyn2"},{49154,"msrpc-dyn3"},{49155,"msrpc-dyn4"},
    {49156,"msrpc-dyn5"},{49157,"msrpc-dyn6"},{61616,"activemq-msg"},
};

// ════════════════════════════════════════════════════════════
//  Banner probe payloads  (port → payload to send)
// ════════════════════════════════════════════════════════════
static std::map<uint16_t, std::string> BANNER_PROBES = {
    {21,   ""},                                         // FTP sends banner first
    {22,   ""},                                         // SSH sends banner first
    {23,   ""},                                         // Telnet sends banner first
    {25,   "EHLO winrecon\r\n"},                        // SMTP
    {80,   "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"},
    {81,   "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"},
    {110,  ""},                                         // POP3 banner first
    {143,  ""},                                         // IMAP banner first
    {389,  ""},
    {443,  ""},
    {445,  ""},
    {587,  "EHLO winrecon\r\n"},
    {993,  ""},
    {995,  ""},
    {1433, ""},
    {3306, ""},                                         // MySQL sends banner
    {3389, ""},
    {5432, ""},
    {6379, "INFO\r\n"},                                 // Redis
    {8000, "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"},
    {8080, "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"},
    {8443, "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"},
    {8888, "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"},
    {9200, "GET / HTTP/1.0\r\nHost: target\r\n\r\n"},   // Elasticsearch
    {10000,"GET / HTTP/1.0\r\nHost: target\r\n\r\n"},   // Webmin
    {27017,""},                                         // MongoDB
};

// ════════════════════════════════════════════════════════════
//  Data Structures
// ════════════════════════════════════════════════════════════
enum PortState { PS_OPEN, PS_CLOSED, PS_FILTERED };

struct PortResult {
    uint16_t    port;
    std::string protocol;   // "tcp" / "udp"
    PortState   state;
    std::string service;
    std::string banner;
    std::string version;
};

struct HostResult {
    std::string            ip;
    std::string            hostname;
    std::string            mac;
    std::string            osGuess;
    int                    ttl;
    bool                   alive;
    std::vector<PortResult> openPorts;
};

// ════════════════════════════════════════════════════════════
//  Globals
// ════════════════════════════════════════════════════════════
static std::mutex          g_printMutex;
static std::atomic<int>    g_scanned(0);
static std::atomic<int>    g_portsScanned(0);

// ════════════════════════════════════════════════════════════
//  Console Color Helpers (Windows ANSI)
// ════════════════════════════════════════════════════════════
static void EnableANSI() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

#define CLR_RESET  "\033[0m"
#define CLR_RED    "\033[91m"
#define CLR_GREEN  "\033[92m"
#define CLR_YELLOW "\033[93m"
#define CLR_CYAN   "\033[96m"
#define CLR_BOLD   "\033[1m"
#define CLR_DIM    "\033[2m"

// ════════════════════════════════════════════════════════════
//  Utility Functions
// ════════════════════════════════════════════════════════════
static std::string DwordToIp(DWORD ip_hbo) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
        (ip_hbo >> 24) & 0xFF, (ip_hbo >> 16) & 0xFF,
        (ip_hbo >> 8) & 0xFF, ip_hbo & 0xFF);
    return buf;
}

static DWORD IpToDword(const char* ip) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) == 1)
        return ntohl(a.s_addr);
    return 0;
}

static std::string GetServiceName(uint16_t port, const std::string& proto) {
    auto it = SERVICE_MAP.find(port);
    if (it != SERVICE_MAP.end()) return it->second;
    // getservbyport as fallback
    struct servent* se = getservbyport(htons(port), proto.c_str());
    if (se) return se->s_name;
    return "unknown";
}

static std::string TrimBanner(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '\r' || c == '\n') { r += ' '; }
        else if ((unsigned char)c >= 0x20 && (unsigned char)c < 0x7F) r += c;
        else r += '.';
    }
    // trim trailing spaces
    size_t e = r.find_last_not_of(' ');
    return (e == std::string::npos) ? "" : r.substr(0, e + 1);
}

static std::string GuessBannerVersion(uint16_t port, const std::string& banner) {
    // Very lightweight fingerprinting
    std::string b = banner;
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);

    if (b.find("ssh") != std::string::npos) {
        // Extract SSH version: SSH-2.0-OpenSSH_8.4
        size_t p = banner.find("SSH-");
        if (p != std::string::npos) {
            size_t e = banner.find_first_of("\r\n ", p);
            return banner.substr(p, e == std::string::npos ? std::string::npos : e - p);
        }
    }
    if (b.find("apache") != std::string::npos) {
        size_t p = b.find("apache");
        size_t e = b.find_first_of(" \r\n(", p + 6);
        return banner.substr(p, e == std::string::npos ? 20 : e - p);
    }
    if (b.find("nginx") != std::string::npos) {
        size_t p = b.find("nginx");
        size_t e = b.find_first_of(" \r\n", p + 5);
        return banner.substr(p, e == std::string::npos ? 20 : e - p);
    }
    if (b.find("iis") != std::string::npos) {
        size_t p = b.find("iis");
        size_t e = b.find_first_of(" \r\n", p + 3);
        return banner.substr(p, e == std::string::npos ? 20 : e - p);
    }
    if (b.find("mysql") != std::string::npos || port == 3306) {
        // MySQL banner starts with version after 5 bytes header
        if (banner.size() > 10) {
            std::string v;
            for (size_t i = 5; i < banner.size() && i < 25; i++) {
                char c = banner[i];
                if (c == '\0') break;
                if ((unsigned char)c >= 0x20 && (unsigned char)c < 0x7F) v += c;
            }
            if (!v.empty()) return "MySQL/" + v;
        }
    }
    if (b.find("redis") != std::string::npos) {
        size_t p = b.find("redis_version:");
        if (p != std::string::npos) {
            size_t e = b.find("\r\n", p);
            return "Redis/" + banner.substr(p + 14, e == std::string::npos ? 10 : e - p - 14);
        }
    }
    if (b.find("microsoft") != std::string::npos && b.find("exchange") != std::string::npos)
        return "Microsoft Exchange";
    if (b.find("220") == 0 && b.find("ftp") != std::string::npos)
        return banner.substr(4, std::min<size_t>(banner.size() - 4, 40));
    if (b.find("smb") != std::string::npos || port == 445) return "SMB";
    return "";
}

static std::string GuessOS(int ttl) {
    if (ttl <= 0)   return "Unknown";
    if (ttl <= 64)  return "Linux/Unix/macOS";
    if (ttl <= 128) return "Windows";
    if (ttl <= 255) return "Cisco/Network Device";
    return "Unknown";
}

// ════════════════════════════════════════════════════════════
//  Network Functions
// ════════════════════════════════════════════════════════════

// ── ICMP Ping ──
static bool IcmpPing(DWORD ip_hbo, int* ttlOut = nullptr) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return false;

    char   sendBuf[32] = "WinRecon Ping";
    DWORD  replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendBuf) + 8;
    BYTE* replyBuf = new BYTE[replySize];

    DWORD ret = IcmpSendEcho(hIcmp, htonl(ip_hbo),
        sendBuf, sizeof(sendBuf),
        NULL, replyBuf, replySize,
        ICMP_TIMEOUT_MS);
    bool alive = false;
    if (ret > 0) {
        ICMP_ECHO_REPLY* r = (ICMP_ECHO_REPLY*)replyBuf;
        alive = (r->Status == 0);
        if (alive && ttlOut) *ttlOut = r->Options.Ttl;
    }
    delete[] replyBuf;
    IcmpCloseHandle(hIcmp);
    return alive;
}

// ── ARP ──
static std::string GetMac(DWORD ip_hbo) {
    ULONG mac[2] = { 0 }, macLen = 6;
    if (SendARP(htonl(ip_hbo), 0, mac, &macLen) == NO_ERROR) {
        BYTE* b = (BYTE*)mac;
        char buf[32];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
            b[0], b[1], b[2], b[3], b[4], b[5]);
        return buf;
    }
    return "";
}

// ── Reverse DNS ──
static std::string ReverseDns(DWORD ip_hbo) {
    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip_hbo);
    char host[NI_MAXHOST] = {};
    if (getnameinfo((sockaddr*)&sa, sizeof(sa), host, NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0)
        return host;
    return "";
}

// ── Set socket timeout ──
static void SetSockTimeout(SOCKET s, int ms) {
    DWORD t = ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&t, sizeof(t));
}

// ── TCP Connect Scan ──
// Returns: true=open, false=closed/filtered
// Sets filtered=true if connection timed out (no RST)
static bool TcpConnect(DWORD ip_hbo, uint16_t port, bool* filtered = nullptr, int timeoutMs = TCP_CONNECT_TIMEOUT) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    // Non-blocking mode for timeout control
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip_hbo);

    connect(s, (sockaddr*)&sa, sizeof(sa));

    fd_set wfds, efds;
    FD_ZERO(&wfds); FD_SET(s, &wfds);
    FD_ZERO(&efds); FD_SET(s, &efds);
    timeval tv = { 0, timeoutMs * 1000 };

    int sel = select(0, NULL, &wfds, &efds, &tv);

    bool open = false;
    if (sel > 0 && FD_ISSET(s, &wfds)) {
        // Verify actual connection (not just ECONNREFUSED completing)
        int err = 0; int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        open = (err == 0);
        if (filtered) *filtered = false;
    }
    else if (sel == 0) {
        // Timeout → filtered
        if (filtered) *filtered = true;
        open = false;
    }
    else {
        // Error (RST) → closed
        if (filtered) *filtered = false;
        open = false;
    }

    closesocket(s);
    return open;
}

// ── Banner Grabbing ──
static std::string GrabBanner(DWORD ip_hbo, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";

    SetSockTimeout(s, BANNER_TIMEOUT_MS);

    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip_hbo);

    if (connect(s, (sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        return "";
    }

    // Send probe if we have one
    auto it = BANNER_PROBES.find(port);
    if (it != BANNER_PROBES.end() && !it->second.empty()) {
        send(s, it->second.c_str(), (int)it->second.size(), 0);
    }

    char buf[BANNER_MAX_BYTES + 1] = {};
    int  received = recv(s, buf, BANNER_MAX_BYTES, 0);
    closesocket(s);

    if (received > 0)
        return std::string(buf, received);
    return "";
}

// ── UDP Scan (for well-known UDP ports) ──
static bool UdpProbe(DWORD ip_hbo, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

    SetSockTimeout(s, UDP_TIMEOUT_MS);

    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip_hbo);

    // Port-specific UDP probes
    const char* probe = "\x00";
    int         pLen = 1;

    char snmpGet[] = "\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04"
        "\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b"
        "\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00";
    char dnsProbe[] = "\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    char ntpProbe[] = "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    if (port == 161 || port == 162) { probe = snmpGet; pLen = sizeof(snmpGet) - 1; }
    else if (port == 53) { probe = dnsProbe; pLen = sizeof(dnsProbe) - 1; }
    else if (port == 123) { probe = ntpProbe; pLen = sizeof(ntpProbe) - 1; }

    sendto(s, probe, pLen, 0, (sockaddr*)&sa, sizeof(sa));

    char recv_buf[256] = {};
    int  r = recvfrom(s, recv_buf, sizeof(recv_buf) - 1, 0, NULL, NULL);
    closesocket(s);
    return (r > 0);
}

// ════════════════════════════════════════════════════════════
//  Port Range Parser
// ════════════════════════════════════════════════════════════
static std::vector<uint16_t> ParsePortRange(const char* spec) {
    std::vector<uint16_t> ports;

    if (!spec || strcmp(spec, "all") == 0) {
        for (int p = 1; p <= 65535; p++) ports.push_back((uint16_t)p);
        return ports;
    }
    if (strcmp(spec, "top") == 0 || strcmp(spec, "top1000") == 0) {
        std::set<uint16_t> seen;
        for (auto p : TOP1000_PORTS) if (seen.insert(p).second) ports.push_back(p);
        return ports;
    }

    // Parse comma-separated: "80,443,1-1024,8080"
    std::string s = spec;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, ',')) {
        size_t dash = token.find('-');
        if (dash != std::string::npos) {
            int lo = atoi(token.substr(0, dash).c_str());
            int hi = atoi(token.substr(dash + 1).c_str());
            for (int p = lo; p <= hi && p <= 65535; p++) ports.push_back((uint16_t)p);
        }
        else {
            int p = atoi(token.c_str());
            if (p > 0 && p <= 65535) ports.push_back((uint16_t)p);
        }
    }
    return ports;
}

// ════════════════════════════════════════════════════════════
//  Subnet Parser
// ════════════════════════════════════════════════════════════
static std::vector<DWORD> ParseSubnet(const char* subnet) {
    std::vector<DWORD> ips;
    char buf[64];
    strncpy_s(buf, subnet, sizeof(buf) - 1);

    // Range: 192.168.1.1-50
    char* dash = strchr(buf, '-');
    if (dash && !strchr(dash + 1, '.')) {
        *dash = '\0';
        struct in_addr a;
        if (inet_pton(AF_INET, buf, &a) != 1) return ips;
        DWORD base = ntohl(a.s_addr);
        int start = base & 0xFF;
        int end = atoi(dash + 1);
        base &= 0xFFFFFF00;
        for (int h = start; h <= end && h <= 254; h++) ips.push_back(base | h);
        return ips;
    }

    // CIDR
    char* slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        int prefix = atoi(slash + 1);
        struct in_addr a;
        if (inet_pton(AF_INET, buf, &a) != 1) return ips;
        DWORD network = ntohl(a.s_addr);
        DWORD mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
        DWORD host = ~mask;
        for (DWORD h = 1; h < host; h++) ips.push_back((network & mask) + h);
        return ips;
    }

    // Single IP
    struct in_addr a;
    if (inet_pton(AF_INET, subnet, &a) == 1) ips.push_back(ntohl(a.s_addr));
    return ips;
}

// ════════════════════════════════════════════════════════════
//  Port Scan Worker
// ════════════════════════════════════════════════════════════
struct PortScanArg {
    DWORD                   ip;
    std::vector<uint16_t>   ports;
    bool                    grabBanners;
    bool                    scanUdp;
    std::vector<PortResult>* results;  // output
    std::mutex* resMutex;
};

static DWORD WINAPI PortScanWorker(LPVOID param) {
    PortScanArg* arg = (PortScanArg*)param;

    for (uint16_t port : arg->ports) {
        bool filtered = false;
        bool open = TcpConnect(arg->ip, port, &filtered);
        g_portsScanned++;

        if (open) {
            PortResult pr;
            pr.port = port;
            pr.protocol = "tcp";
            pr.state = PS_OPEN;
            pr.service = GetServiceName(port, "tcp");

            // Banner
            if (arg->grabBanners) {
                std::string raw = GrabBanner(arg->ip, port);
                if (!raw.empty()) {
                    pr.banner = TrimBanner(raw);
                    pr.version = GuessBannerVersion(port, raw);
                }
            }

            std::lock_guard<std::mutex> lk(*arg->resMutex);
            arg->results->push_back(pr);
        }
    }

    // UDP scan
    if (arg->scanUdp) {
        uint16_t udpPorts[] = { 53, 67, 69, 123, 135, 137, 138, 161, 162,
                                500, 514, 520, 1194, 1900, 4500, 5060 };
        for (auto p : udpPorts) {
            if (UdpProbe(arg->ip, p)) {
                PortResult pr;
                pr.port = p;
                pr.protocol = "udp";
                pr.state = PS_OPEN;
                pr.service = GetServiceName(p, "udp");
                std::lock_guard<std::mutex> lk(*arg->resMutex);
                arg->results->push_back(pr);
            }
        }
    }

    delete arg;
    return 0;
}

// ════════════════════════════════════════════════════════════
//  Full Port Scan  (entry point per host)
// ════════════════════════════════════════════════════════════
static std::vector<PortResult> ScanPorts(
    DWORD ip_hbo,
    const std::vector<uint16_t>& ports,
    int numThreads,
    bool grabBanners,
    bool scanUdp)
{
    std::vector<PortResult> results;
    std::mutex              resMutex;

    // Split ports among threads
    int chunk = (int)ports.size() / numThreads;
    if (chunk < 1) chunk = 1;

    std::vector<HANDLE> handles;
    int idx = 0;
    for (int t = 0; t < numThreads && idx < (int)ports.size(); t++) {
        auto* arg = new PortScanArg();
        arg->ip = ip_hbo;
        arg->grabBanners = grabBanners;
        arg->scanUdp = (t == 0) ? scanUdp : false;  // UDP only on first thread
        arg->results = &results;
        arg->resMutex = &resMutex;

        int end = (t == numThreads - 1) ? (int)ports.size() : (std::min)(idx + chunk, (int)ports.size());
        for (int i = idx; i < end; i++) arg->ports.push_back(ports[i]);
        idx = end;

        HANDLE h = CreateThread(NULL, 0, PortScanWorker, arg, 0, NULL);
        if (h) handles.push_back(h);
        else   delete arg;
    }

    WaitForMultipleObjects((DWORD)handles.size(), handles.data(), TRUE, INFINITE);
    for (auto h : handles) CloseHandle(h);

    // Sort by port number
    std::sort(results.begin(), results.end(), [](const PortResult& a, const PortResult& b) {
        return a.port < b.port;
        });
    return results;
}

// ════════════════════════════════════════════════════════════
//  Host Discovery Worker
// ════════════════════════════════════════════════════════════
struct DiscoveryArg {
    std::vector<DWORD>       ips;
    std::vector<HostResult>* results;
    std::mutex* resMutex;
    bool                     verbose;
};

static DWORD WINAPI DiscoveryWorker(LPVOID param) {
    DiscoveryArg* arg = (DiscoveryArg*)param;

    for (DWORD ip : arg->ips) {
        int  ttl = 0;
        bool alive = IcmpPing(ip, &ttl);
        g_scanned++;

        if (alive) {
            HostResult hr;
            hr.ip = DwordToIp(ip);
            hr.alive = true;
            hr.ttl = ttl;
            hr.osGuess = GuessOS(ttl);
            hr.mac = GetMac(ip);
            hr.hostname = ReverseDns(ip);

            std::lock_guard<std::mutex> lk(*arg->resMutex);
            arg->results->push_back(hr);

            if (arg->verbose) {
                std::lock_guard<std::mutex> plk(g_printMutex);
                printf("  " CLR_GREEN "[+]" CLR_RESET " %-16s  TTL:%-4d  OS:%-20s  MAC:%-20s  %s\n",
                    hr.ip.c_str(), hr.ttl, hr.osGuess.c_str(),
                    hr.mac.empty() ? "(N/A)" : hr.mac.c_str(),
                    hr.hostname.empty() ? "" : hr.hostname.c_str());
            }
        }
    }
    delete arg;
    return 0;
}

// ════════════════════════════════════════════════════════════
//  Host Discovery (ICMP sweep)
// ════════════════════════════════════════════════════════════
static std::vector<HostResult> DiscoverHosts(
    const std::vector<DWORD>& ips,
    int numThreads,
    bool verbose)
{
    std::vector<HostResult> results;
    std::mutex              resMutex;
    g_scanned = 0;

    int total = (int)ips.size();
    int chunk = total / numThreads;
    if (chunk < 1) chunk = 1;

    std::vector<HANDLE> handles;
    int idx = 0;
    for (int t = 0; t < numThreads && idx < total; t++) {
        auto* arg = new DiscoveryArg();
        arg->results = &results;
        arg->resMutex = &resMutex;
        arg->verbose = verbose;

        int end = (t == numThreads - 1) ? total : (std::min)(idx + chunk, total);
        for (int i = idx; i < end; i++) arg->ips.push_back(ips[i]);
        idx = end;

        HANDLE h = CreateThread(NULL, 0, DiscoveryWorker, arg, 0, NULL);
        if (h) handles.push_back(h);
        else   delete arg;
    }

    WaitForMultipleObjects((DWORD)handles.size(), handles.data(), TRUE, INFINITE);
    for (auto h : handles) CloseHandle(h);

    std::sort(results.begin(), results.end(), [](const HostResult& a, const HostResult& b) {
        return a.ip < b.ip;
        });
    return results;
}

// ════════════════════════════════════════════════════════════
//  Output / Report
// ════════════════════════════════════════════════════════════
static void PrintPortTable(const HostResult& hr) {
    printf("\n  " CLR_BOLD CLR_CYAN "Host: %s" CLR_RESET, hr.ip.c_str());
    if (!hr.hostname.empty()) printf("  (%s)", hr.hostname.c_str());
    if (!hr.osGuess.empty())  printf("  [OS: %s TTL=%d]", hr.osGuess.c_str(), hr.ttl);
    if (!hr.mac.empty())      printf("  MAC: %s", hr.mac.c_str());
    printf("\n");

    if (hr.openPorts.empty()) {
        printf("  " CLR_DIM "(no open ports found)\n" CLR_RESET);
        return;
    }

    printf("  %-8s %-8s %-22s %-20s %s\n",
        "PORT", "PROTO", "SERVICE", "VERSION", "BANNER");
    printf("  %-8s %-8s %-22s %-20s %s\n",
        "────────", "────────", "──────────────────────", "────────────────────", "───────────────────────────────");

    for (auto& p : hr.openPorts) {
        std::string portStr = std::to_string(p.port) +
            (p.state == PS_OPEN ? "/open" : "/filt");
        std::string ver = p.version.empty() ? "-" : p.version.substr(0, 19);
        std::string ban = p.banner.empty() ? "-" : p.banner.substr(0, 50);

        printf("  " CLR_GREEN "%-8s" CLR_RESET " %-8s %-22s %-20s %s\n",
            portStr.c_str(),
            p.protocol.c_str(),
            p.service.substr(0, 21).c_str(),
            ver.c_str(),
            ban.c_str());
    }
    printf("\n");
}

static void SaveTxt(const std::vector<HostResult>& hosts, const std::string& filename) {
    std::ofstream f(filename + ".txt");
    if (!f) return;
    f << "# WinRecon Results\n";
    for (auto& hr : hosts) {
        f << "\nHost: " << hr.ip;
        if (!hr.hostname.empty()) f << " (" << hr.hostname << ")";
        if (!hr.osGuess.empty())  f << " [OS: " << hr.osGuess << " TTL=" << hr.ttl << "]";
        if (!hr.mac.empty())      f << " MAC: " << hr.mac;
        f << "\n";
        f << std::string(60, '-') << "\n";
        for (auto& p : hr.openPorts) {
            f << "  " << p.port << "/" << p.protocol
                << "\t" << p.service
                << "\t" << (p.version.empty() ? "-" : p.version)
                << "\t" << (p.banner.empty() ? "-" : p.banner)
                << "\n";
        }
    }
    printf("  " CLR_CYAN "[*] TXT saved: %s.txt\n" CLR_RESET, filename.c_str());
}

static void SaveCsv(const std::vector<HostResult>& hosts, const std::string& filename) {
    std::ofstream f(filename + ".csv");
    if (!f) return;
    f << "IP,Hostname,OS,TTL,MAC,Port,Protocol,State,Service,Version,Banner\n";
    for (auto& hr : hosts) {
        if (hr.openPorts.empty()) {
            f << hr.ip << "," << hr.hostname << "," << hr.osGuess
                << "," << hr.ttl << "," << hr.mac
                << ",,,,,\n";
        }
        for (auto& p : hr.openPorts) {
            // Escape CSV
            auto esc = [](std::string s) {
                for (auto& c : s) if (c == ',') c = ';';
                return s;
                };
            f << hr.ip << "," << hr.hostname << "," << hr.osGuess
                << "," << hr.ttl << "," << hr.mac
                << "," << p.port << "," << p.protocol
                << "," << (p.state == PS_OPEN ? "open" : "filtered")
                << "," << p.service
                << "," << esc(p.version)
                << "," << esc(p.banner)
                << "\n";
        }
    }
    printf("  " CLR_CYAN "[*] CSV saved: %s.csv\n" CLR_RESET, filename.c_str());
}

// ════════════════════════════════════════════════════════════
//  Usage
// ════════════════════════════════════════════════════════════
static void PrintBanner() {
    printf("\n");
    printf("  " CLR_BOLD CLR_CYAN "╔══════════════════════════════════════════════════════╗\n");
    printf("  ║   WinRecon v%-5s  —  Host Discovery + Port Scanner  ║\n", TOOL_VERSION);
    printf("  ║   ICMP · TCP Connect · UDP · Banner Grab · OS Guess  ║\n");
    printf("  ║   For Pentest / Red Team Lab  (Run as Administrator)  ║\n");
    printf("  ╚══════════════════════════════════════════════════════╝\n" CLR_RESET);
    printf("\n");
}

static void PrintUsage(const char* prog) {
    printf("  Usage:\n");
    printf("    %s -scan  <subnet>    [options]   Host discovery\n", prog);
    printf("    %s -port  <ip/subnet> [options]   Port scan\n", prog);
    printf("\n");
    printf("  Subnet formats:\n");
    printf("    192.168.57.0/24     CIDR\n");
    printf("    192.168.57.1-50     Range\n");
    printf("    192.168.57.10       Single host\n");
    printf("\n");
    printf("  Options:\n");
    printf("    -p <range>     Port range (default: top1000)\n");
    printf("                   Examples: -p 1-65535   -p top   -p all\n");
    printf("                             -p 80,443,8080-8090\n");
    printf("    -t <n>         Threads (default: 64, max: %d)\n", MAX_THREADS);
    printf("    -b             Banner grabbing (default: on)\n");
    printf("    -nb            No banner grabbing (faster)\n");
    printf("    -udp           Include UDP scan on common ports\n");
    printf("    -o <name>      Output file prefix (creates .txt + .csv)\n");
    printf("    -v             Verbose mode\n");
    printf("\n");
    printf("  Examples:\n");
    printf("    %s -scan 192.168.57.0/24\n", prog);
    printf("    %s -port 192.168.57.10\n", prog);
    printf("    %s -port 192.168.57.10 -p 1-65535 -t 100 -udp -o result\n", prog);
    printf("    %s -scan 192.168.57.0/24 -port -p top -nb -o sweep\n", prog);
    printf("\n");
}

// ════════════════════════════════════════════════════════════
//  Main
// ════════════════════════════════════════════════════════════
int main(int argc, char* argv[]) {
    EnableANSI();
    PrintBanner();

    if (argc < 2) { PrintUsage(argv[0]); return 1; }

    // ── Parse arguments ──
    bool        doScan = false;
    bool        doPort = false;
    const char* target = nullptr;
    const char* portSpec = "top";
    int         numThreads = DEFAULT_THREADS;
    bool        grabBanners = true;
    bool        scanUdp = false;
    bool        verbose = false;
    std::string outFile;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            PrintUsage(argv[0]); return 0;
        }
        else if (!strcmp(argv[i], "-scan")) {
            doScan = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') target = argv[++i];
        }
        else if (!strcmp(argv[i], "-port")) {
            doPort = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') target = argv[++i];
        }
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) { portSpec = argv[++i]; }
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
            numThreads = atoi(argv[++i]);
            numThreads = (std::max)(1, (std::min)(numThreads, MAX_THREADS));
        }
        else if (!strcmp(argv[i], "-b")) { grabBanners = true; }
        else if (!strcmp(argv[i], "-nb")) { grabBanners = false; }
        else if (!strcmp(argv[i], "-udp")) { scanUdp = true; }
        else if (!strcmp(argv[i], "-v")) { verbose = true; }
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) { outFile = argv[++i]; }
        else if (!target && argv[i][0] != '-') { target = argv[i]; }
    }

    if (!doScan && !doPort) { doScan = true; doPort = false; }
    if (!target) {
        printf(CLR_RED "  [-] No target specified.\n" CLR_RESET);
        PrintUsage(argv[0]); return 1;
    }

    // ── Init Winsock ──
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf(CLR_RED "  [-] WSAStartup failed.\n" CLR_RESET);
        return 1;
    }

    // ── Parse targets ──
    auto ips = ParseSubnet(target);
    if (ips.empty()) {
        printf(CLR_RED "  [-] No valid IPs from target: %s\n" CLR_RESET, target);
        return 1;
    }

    auto ports = ParsePortRange(portSpec);

    printf("  " CLR_BOLD "[*] Target   : %s  (%d hosts)\n" CLR_RESET, target, (int)ips.size());
    if (doPort) {
        printf("  " CLR_BOLD "[*] Ports    : %d  (%s)\n" CLR_RESET, (int)ports.size(), portSpec);
        printf("  " CLR_BOLD "[*] Banners  : %s\n" CLR_RESET, grabBanners ? "YES" : "NO");
        printf("  " CLR_BOLD "[*] UDP scan : %s\n" CLR_RESET, scanUdp ? "YES" : "NO");
    }
    printf("  " CLR_BOLD "[*] Threads  : %d\n\n" CLR_RESET, numThreads);

    auto t0 = std::chrono::steady_clock::now();
    std::vector<HostResult> allHosts;

    // ════════════════════════════
    //  Phase 1: Host Discovery
    // ════════════════════════════
    if (doScan) {
        printf("  " CLR_BOLD "──── Phase 1: Host Discovery ────\n\n" CLR_RESET);

        // Progress thread
        HANDLE hProgress = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
            int* total = (int*)p;
            while (true) {
                Sleep(1000);
                int sc = g_scanned.load();
                if (sc >= *total) break;
                printf("  " CLR_DIM "[~] Ping sweep: %d/%d\r" CLR_RESET, sc, *total);
            }
            return 0;
            }, (LPVOID)new int((int)ips.size()), 0, NULL);

        allHosts = DiscoverHosts(ips, numThreads, true);
        CloseHandle(hProgress);
        printf("\n\n  " CLR_GREEN "[+] Alive hosts: %d / %d\n\n" CLR_RESET,
            (int)allHosts.size(), (int)ips.size());
    }
    else {
        // No discovery — use all IPs directly
        for (DWORD ip : ips) {
            HostResult hr;
            hr.ip = DwordToIp(ip);
            hr.alive = true;
            int ttl = 0;
            if (IcmpPing(ip, &ttl)) {
                hr.ttl = ttl;
                hr.osGuess = GuessOS(ttl);
                hr.mac = GetMac(ip);
                hr.hostname = ReverseDns(ip);
            }
            allHosts.push_back(hr);
        }
    }

    // ════════════════════════════
    //  Phase 2: Port Scan
    // ════════════════════════════
    if (doPort && !allHosts.empty()) {
        printf("  " CLR_BOLD "──── Phase 2: Port Scan ────\n\n" CLR_RESET);

        for (auto& hr : allHosts) {
            DWORD ip = IpToDword(hr.ip.c_str());
            printf("  " CLR_CYAN "[~] Scanning %s (%d ports)...\n" CLR_RESET,
                hr.ip.c_str(), (int)ports.size());

            auto t1s = std::chrono::steady_clock::now();
            hr.openPorts = ScanPorts(ip, ports, numThreads, grabBanners, scanUdp);
            auto t1e = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(t1e - t1s).count();

            PrintPortTable(hr);
            printf("  " CLR_DIM "[~] %d open ports found in %.1fs\n\n" CLR_RESET,
                (int)hr.openPorts.size(), elapsed);
        }
    }
    else if (doPort) {
        printf("  " CLR_YELLOW "[!] No alive hosts to port-scan.\n" CLR_RESET);
    }

    // ════════════════════════════
    //  Summary
    // ════════════════════════════
    auto t1 = std::chrono::steady_clock::now();
    double totalSec = std::chrono::duration<double>(t1 - t0).count();

    int totalOpen = 0;
    for (auto& h : allHosts) totalOpen += (int)h.openPorts.size();

    printf("  " CLR_BOLD "────────────────────────────────────────────────────\n");
    printf("  SUMMARY\n");
    printf("  ────────────────────────────────────────────────────\n" CLR_RESET);
    printf("  Hosts alive   : %d\n", (int)allHosts.size());
    if (doPort) {
        printf("  Ports scanned : %d\n", (int)g_portsScanned);
        printf("  Open ports    : %d\n", totalOpen);
    }
    printf("  Elapsed       : %.2f seconds\n", totalSec);
    printf("\n");

    // ── Save output ──
    if (!outFile.empty()) {
        SaveTxt(allHosts, outFile);
        SaveCsv(allHosts, outFile);
    }

    WSACleanup();
    return 0;
}