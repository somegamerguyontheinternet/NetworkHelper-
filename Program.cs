using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;

class NetworkHelperPlusPlus
{
    // -----------------------------
    // STATE
    // -----------------------------
    private readonly Dictionary<string, string> knownDevices = new();
    private string controlUrl = "";
    private string serviceType = "";
    private bool running = true;

    private string currentProtocol = "both";
    private int? lastOpenedPort = null;
    private string lastProtocol = "both";

    // Ports opened in this session (console + HTTP)
    private readonly HashSet<int> openedPorts = new();

    // Whitelist
    private bool whitelistEnabled = false;
    private readonly HashSet<string> whitelist = new();

    // Lockdown
    private bool lockdownEnabled = false;

    // Connection monitors per port
    private class PortMonitor
    {
        public TcpListener? Tcp { get; set; }
        public UdpClient? Udp { get; set; }
    }

    private readonly Dictionary<int, PortMonitor> portMonitors = new();

    // -----------------------------
    // ENTRY POINT
    // -----------------------------
    static async Task Main()
    {
        Console.WriteLine("Starting Network Helper++...");
        Console.WriteLine("Discovering networking info...");
        var helper = new NetworkHelperPlusPlus();
        await helper.InitializeAsync();

        Console.WriteLine("Networking ready\n");

        _ = Task.Run(helper.StartHttpServer);
        _ = Task.Run(helper.StartNetworkWatcher);

        await helper.ConsoleLoop();
    }

    // -----------------------------
    // INITIALIZATION
    // -----------------------------
    public async Task InitializeAsync()
    {
        await DiscoverUpnpAsync();
    }

    // -----------------------------
    // CONSOLE LOOP
    // -----------------------------
    private async Task ConsoleLoop()
    {
        Console.WriteLine("Network Helper++ Commands:");
        Console.WriteLine("  [port]            - open port using current protocol");
        Console.WriteLine("  TCP               - switch to TCP mode");
        Console.WriteLine("  UDP               - switch to UDP mode");
        Console.WriteLine("  BOTH              - switch to TCP+UDP mode");
        Console.WriteLine("  CLOSE [ports...]  - close one or more ports");
        Console.WriteLine("  CLOSE ALL         - close all ports opened this session");
        Console.WriteLine("  SCAN              - scan port table and auto-close ports");
        Console.WriteLine("  WHITELIST ON/OFF  - enable or disable whitelist mode");
        Console.WriteLine("  ADDWL [IP]        - add IP to whitelist");
        Console.WriteLine("  REMWL [IP]        - remove IP from whitelist");
        Console.WriteLine("  SHOWWL            - show whitelist entries");
        Console.WriteLine("  LOCKDOWN          - close all ports and block new ones");
        Console.WriteLine("  UNLOCKDOWN        - allow ports to be opened again");
        Console.WriteLine("  EMERGENCY         - attempt to close ALL ports");
        Console.WriteLine("  STATUS            - show current Network Helper++ status");
        Console.WriteLine("  HELP              - show your Local + Public IP");
        Console.WriteLine("  HIDE              - hide IP info from console");
        Console.WriteLine("  STOP              - close last port and exit\n");

        int helpLinesPrinted = 0;

        while (running)
        {
            Console.Write("> ");
            string? input = Console.ReadLine();

            if (input == null)
                continue;

            string trimmed = input.Trim();
            string upper = trimmed.ToUpperInvariant();

            // STOP: close last opened port (console) then exit
            if (upper == "STOP")
            {
                if (lastOpenedPort.HasValue)
                {
                    Console.WriteLine($"Closing port {lastOpenedPort.Value} ({lastProtocol.ToUpper()}) before exit...");
                    try
                    {
                        ClosePort(lastOpenedPort.Value, lastProtocol).GetAwaiter().GetResult();
                        openedPorts.Remove(lastOpenedPort.Value);
                        Console.WriteLine($"Port {lastOpenedPort.Value} closed.\n");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error closing port {lastOpenedPort.Value}: {ex.Message}\n");
                    }
                }

                running = false;
                Console.WriteLine("Stopping Network Helper++...");
                break;
            }

            // Protocol switching
            if (upper == "TCP" || upper == "UDP" || upper == "BOTH")
            {
                currentProtocol = upper.ToLowerInvariant();
                Console.WriteLine($"Protocol set to {upper}");
                continue;
            }

            // WHITELIST ON
            if (upper == "WHITELIST ON")
            {
                whitelistEnabled = true;
                Console.WriteLine("Whitelist mode enabled.\n");
                continue;
            }

            // WHITELIST OFF
            if (upper == "WHITELIST OFF")
            {
                whitelistEnabled = false;
                Console.WriteLine("Whitelist mode disabled.\n");
                continue;
            }

            // ADDWL [IP]
            if (upper.StartsWith("ADDWL "))
            {
                string ip = trimmed.Substring(6).Trim();
                if (!string.IsNullOrWhiteSpace(ip))
                {
                    whitelist.Add(ip);
                    Console.WriteLine($"Added {ip} to whitelist.\n");
                }
                else
                {
                    Console.WriteLine("Usage: ADDWL [IP]\n");
                }
                continue;
            }

            // REMWL [IP]
            if (upper.StartsWith("REMWL "))
            {
                string ip = trimmed.Substring(6).Trim();
                if (!string.IsNullOrWhiteSpace(ip))
                {
                    whitelist.Remove(ip);
                    Console.WriteLine($"Removed {ip} from whitelist.\n");
                }
                else
                {
                    Console.WriteLine("Usage: REMWL [IP]\n");
                }
                continue;
            }

            // SHOWWL
            if (upper == "SHOWWL")
            {
                Console.WriteLine("Whitelist:");
                if (whitelist.Count == 0)
                    Console.WriteLine("  (empty)");
                else
                {
                    foreach (var ip in whitelist)
                        Console.WriteLine("  " + ip);
                }
                Console.WriteLine();
                continue;
            }

            // LOCKDOWN
            if (upper == "LOCKDOWN")
            {
                Console.WriteLine("!!! LOCKDOWN MODE ACTIVATED !!!");
                lockdownEnabled = true;

                Console.WriteLine("Closing all session ports...");
                foreach (int p in new List<int>(openedPorts))
                {
                    try
                    {
                        ClosePort(p, "both").GetAwaiter().GetResult();
                        openedPorts.Remove(p);
                        Console.WriteLine($"Closed session port {p}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to close session port {p}: {ex.Message}");
                    }
                }

                Console.WriteLine("Closing all ports in port table...");
                try
                {
                    var mappings = GetAllPortMappingsAsync().GetAwaiter().GetResult();
                    foreach (var m in mappings)
                    {
                        if (m.HasValidPortOrProtocol)
                        {
                            try
                            {
                                ClosePort(m.ExternalPort, m.Protocol.ToLowerInvariant()).GetAwaiter().GetResult();
                                Console.WriteLine($"Closed {m.ExternalPort} {m.Protocol}");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Failed to close {m.ExternalPort} {m.Protocol}: {ex.Message}");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Attempting UNKNOWN close: {m.RawPort} {m.RawProtocol}");
                            if (int.TryParse(m.RawPort, out int unknownPort))
                            {
                                try
                                {
                                    ClosePort(unknownPort, "both").GetAwaiter().GetResult();
                                    Console.WriteLine($"Closed UNKNOWN port {unknownPort}");
                                }
                                catch
                                {
                                    // ignore
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Lockdown port-table cleanup error: {ex.Message}");
                }

                Console.WriteLine("LOCKDOWN complete. Port opening is now disabled.\n");
                continue;
            }

            // UNLOCKDOWN
            if (upper == "UNLOCKDOWN")
            {
                lockdownEnabled = false;
                Console.WriteLine("Lockdown disabled. Port opening is now allowed.\n");
                continue;
            }

            // CLOSE ALL
            if (upper == "CLOSE ALL")
            {
                if (openedPorts.Count == 0)
                {
                    Console.WriteLine("No ports recorded as open this session.\n");
                    continue;
                }

                Console.WriteLine("Closing all ports opened this session...");
                foreach (int p in new List<int>(openedPorts))
                {
                    try
                    {
                        ClosePort(p, currentProtocol).GetAwaiter().GetResult();
                        Console.WriteLine($"Closed port {p} ({currentProtocol.ToUpper()})");
                        openedPorts.Remove(p);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error closing port {p}: {ex.Message}");
                    }
                }
                Console.WriteLine();
                continue;
            }

            // CLOSE [ports...]
            if (upper.StartsWith("CLOSE "))
            {
                string[] parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2)
                {
                    Console.WriteLine("Usage: CLOSE [port] [port] ...\n");
                    continue;
                }

                for (int i = 1; i < parts.Length; i++)
                {
                    if (int.TryParse(parts[i], out int p))
                    {
                        Console.WriteLine($"Closing port {p} ({currentProtocol.ToUpper()})...");
                        try
                        {
                            await ClosePort(p, currentProtocol);
                            openedPorts.Remove(p);
                            Console.WriteLine($"Port {p} closed.");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error closing port {p}: {ex.Message}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Invalid port: {parts[i]}");
                    }
                }
                Console.WriteLine();
                continue;
            }

            // SCAN: port table + auto-close everything (including UNKNOWN attempts)
            if (upper == "SCAN")
            {
                Console.WriteLine("Scanning port table...");
                try
                {
                    var mappings = await GetAllPortMappingsAsync();
                    if (mappings.Count == 0)
                    {
                        Console.WriteLine("No ports found in the port table.\n");
                    }
                    else
                    {
                        Console.WriteLine("Port Table:");

                        foreach (var m in mappings)
                        {
                            if (!m.HasValidPortOrProtocol)
                            {
                                Console.WriteLine($"  {m.RawPort} {m.RawProtocol} [UNKNOWN!] [{m.Description}]");
                                continue;
                            }

                            Console.WriteLine(
                                $"  {m.ExternalPort} {m.Protocol} -> {m.InternalClient}:{m.InternalPort}  [{m.Description}]");
                        }

                        Console.WriteLine();
                        Console.WriteLine("Auto-closing all ports (including UNKNOWN entries)...");

                        foreach (var m in mappings)
                        {
                            if (m.HasValidPortOrProtocol)
                            {
                                try
                                {
                                    await ClosePort(m.ExternalPort, m.Protocol.ToLowerInvariant());
                                    openedPorts.Remove(m.ExternalPort);
                                    Console.WriteLine($"Closed {m.ExternalPort} {m.Protocol}");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Failed to close {m.ExternalPort} {m.Protocol}: {ex.Message}");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Attempting to close UNKNOWN entry: {m.RawPort} {m.RawProtocol}");

                                if (int.TryParse(m.RawPort, out int unknownPort) &&
                                    !string.IsNullOrWhiteSpace(m.RawProtocol))
                                {
                                    try
                                    {
                                        await ClosePort(unknownPort, m.RawProtocol.ToLowerInvariant());
                                        openedPorts.Remove(unknownPort);
                                        Console.WriteLine($"Closed {unknownPort} {m.RawProtocol}");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"Failed to close UNKNOWN {m.RawPort} {m.RawProtocol}: {ex.Message}");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"Failed: UNKNOWN entry has invalid port/protocol ({m.RawPort} {m.RawProtocol})");
                                }
                            }
                        }

                        Console.WriteLine("\nAuto-closed all ports.\n");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Scan error: {ex.Message}\n");
                }
                continue;
            }

            // EMERGENCY: attempt to close ALL ports (session + port table)
            if (upper == "EMERGENCY")
            {
                Console.WriteLine("!!! EMERGENCY MODE ACTIVATED !!!");
                Console.WriteLine("Attempting to close ALL ports...");

                // Close session ports
                foreach (int p in new List<int>(openedPorts))
                {
                    try
                    {
                        ClosePort(p, "both").GetAwaiter().GetResult();
                        openedPorts.Remove(p);
                        Console.WriteLine($"Closed session port {p}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to close session port {p}: {ex.Message}");
                    }
                }

                // Close everything in port table
                try
                {
                    var mappings = GetAllPortMappingsAsync().GetAwaiter().GetResult();
                    foreach (var m in mappings)
                    {
                        if (m.HasValidPortOrProtocol)
                        {
                            try
                            {
                                ClosePort(m.ExternalPort, m.Protocol.ToLowerInvariant()).GetAwaiter().GetResult();
                                Console.WriteLine($"Closed port table entry {m.ExternalPort} {m.Protocol}");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Failed to close {m.ExternalPort} {m.Protocol}: {ex.Message}");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Attempting UNKNOWN close from port table: {m.RawPort} {m.RawProtocol}");

                            if (int.TryParse(m.RawPort, out int unknownPort))
                            {
                                try
                                {
                                    ClosePort(unknownPort, "both").GetAwaiter().GetResult();
                                    Console.WriteLine($"Closed UNKNOWN port {unknownPort}");
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Failed to close UNKNOWN port {unknownPort}: {ex.Message}");
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"EMERGENCY port table cleanup error: {ex.Message}");
                }

                Console.WriteLine("EMERGENCY cleanup complete.\n");
                continue;
            }

            // STATUS
            if (upper == "STATUS")
            {
                Console.WriteLine("\n=== NETWORK HELPER++ STATUS ===");

                Console.WriteLine($"Protocol Mode: {currentProtocol.ToUpper()}");
                Console.WriteLine($"Last Opened Port: {(lastOpenedPort.HasValue ? lastOpenedPort.Value.ToString() : "None")}");
                Console.WriteLine($"Last Protocol Used: {lastProtocol.ToUpper()}");
                Console.WriteLine($"Ports Opened This Session: {(openedPorts.Count == 0 ? "None" : string.Join(", ", openedPorts))}");
                Console.WriteLine($"Whitelist Mode: {(whitelistEnabled ? "ENABLED" : "DISABLED")}");
                Console.WriteLine($"Lockdown Mode: {(lockdownEnabled ? "ENABLED" : "DISABLED")}");

                if (whitelistEnabled)
                {
                    Console.WriteLine("Whitelisted IPs:");
                    if (whitelist.Count == 0)
                        Console.WriteLine("  (none)");
                    else
                        foreach (var ip in whitelist)
                            Console.WriteLine("  " + ip);
                }

                Console.WriteLine($"Known Devices (this run): {knownDevices.Count}");

                Console.WriteLine("==============================\n");
                continue;
            }

            // HELP: show IPs
            if (upper == "HELP")
            {
                string local = GetLocalIPAddress();
                string pub = GetPublicIP();

                Console.WriteLine();
                Console.WriteLine("--- IP Information ---");
                Console.WriteLine($"Local IP:  {local}");
                Console.WriteLine($"Public IP: {pub}");
                Console.WriteLine("----------------------");
                Console.WriteLine();

                helpLinesPrinted = 6; // blank + 4 lines + blank
                continue;
            }

            // HIDE: erase last HELP block if present
            if (upper == "HIDE")
            {
                if (helpLinesPrinted > 0)
                {
                    for (int i = 0; i < helpLinesPrinted; i++)
                    {
                        if (Console.CursorTop == 0)
                            break;

                        Console.SetCursorPosition(0, Console.CursorTop - 1);
                        Console.Write(new string(' ', Console.BufferWidth));
                        Console.SetCursorPosition(0, Console.CursorTop);
                    }

                    helpLinesPrinted = 0;
                }

                Console.WriteLine("IP information hidden.\n");
                continue;
            }

            // Port input → open with current protocol
            if (int.TryParse(upper, out int port))
            {
                if (lockdownEnabled)
                {
                    Console.WriteLine("Cannot open ports while LOCKDOWN is active.\n");
                    continue;
                }

                Console.WriteLine($"Opening port {port} ({currentProtocol.ToUpper()})...");
                await OpenPort(port, currentProtocol);
                StartConnectionMonitor(port, currentProtocol);
                Console.WriteLine($"Port {port} opened.\n");

                lastOpenedPort = port;
                lastProtocol = currentProtocol;
                openedPorts.Add(port);
                continue;
            }

            Console.WriteLine("Invalid input. Type HELP for commands.\n");
        }
    }

    // -----------------------------
    // HTTP SERVER (HTML UI)
    // -----------------------------
    private async Task StartHttpServer()
    {
        HttpListener listener = new();
        listener.Prefixes.Add("http://localhost:54875/");
        listener.Start();

        while (running)
        {
            var ctx = await listener.GetContextAsync();
            _ = HandleHttpRequest(ctx);
        }
    }

    private async Task HandleHttpRequest(HttpListenerContext ctx)
    {
        try
        {
            string path = ctx.Request.Url.AbsolutePath;

            using var reader = new StreamReader(ctx.Request.InputStream);
            string body = await reader.ReadToEndAsync();

            var json = JsonDocument.Parse(body);
            int port = json.RootElement.GetProperty("port").GetInt32();
            string protocol = json.RootElement.GetProperty("protocol").GetString() ?? "both";
            protocol = protocol.ToLowerInvariant();

            if (path == "/open")
            {
                if (lockdownEnabled)
                {
                    await Respond(ctx, new { error = "LOCKDOWN active — cannot open ports." });
                    return;
                }

                await OpenPort(port, protocol);
                openedPorts.Add(port);
                StartConnectionMonitor(port, protocol);
                await Respond(ctx, new { ok = true, port, protocol });
            }
            else if (path == "/close")
            {
                await ClosePort(port, protocol);
                openedPorts.Remove(port);
                await Respond(ctx, new { ok = true, port, protocol });
            }
            else
            {
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        }
        catch (Exception ex)
        {
            await Respond(ctx, new { error = ex.Message });
        }
    }

    private async Task Respond(HttpListenerContext ctx, object obj)
    {
        string json = JsonSerializer.Serialize(obj);
        byte[] data = Encoding.UTF8.GetBytes(json);

        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = data.Length;
        await ctx.Response.OutputStream.WriteAsync(data);
        ctx.Response.Close();
    }

    // -----------------------------
    // CONNECTION MONITORS (TCP / UDP / BOTH)
    // -----------------------------
    private void StartConnectionMonitor(int port, string protocol)
    {
        protocol = protocol.ToLowerInvariant();

        if (portMonitors.ContainsKey(port))
            return; // already monitoring this port

        var monitor = new PortMonitor();
        portMonitors[port] = monitor;

        // TCP monitor
        if (protocol == "tcp" || protocol == "both")
        {
            Task.Run(async () =>
            {
                try
                {
                    monitor.Tcp = new TcpListener(IPAddress.Any, port);
                    monitor.Tcp.Start();

                    while (running)
                    {
                        if (monitor.Tcp.Pending())
                        {
                            var client = await monitor.Tcp.AcceptTcpClientAsync();
                            string remoteIp = ((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString();

                            Console.WriteLine($"A new user has connected to your port {port} with TCP");

                            bool unauthorized = whitelistEnabled && !whitelist.Contains(remoteIp);
                            if (unauthorized)
                            {
                                HandleUnauthorizedConnection(remoteIp, port, "tcp");
                            }

                            client.Close();
                        }

                        await Task.Delay(25);
                    }
                }
                catch
                {
                    // Listener failure: silently ignore for now
                }
            });
        }

        // UDP monitor
        if (protocol == "udp" || protocol == "both")
        {
            Task.Run(async () =>
            {
                try
                {
                    monitor.Udp = new UdpClient(port);

                    while (running)
                    {
                        var result = await monitor.Udp.ReceiveAsync();
                        string remoteIp = result.RemoteEndPoint.Address.ToString();

                        Console.WriteLine($"A new user has connected to your port {port} with UDP");

                        bool unauthorized = whitelistEnabled && !whitelist.Contains(remoteIp);
                        if (unauthorized)
                        {
                            HandleUnauthorizedConnection(remoteIp, port, "udp");
                        }
                    }
                }
                catch
                {
                    // UDP monitor failure: silently ignore for now
                }
            });
        }
    }

    private void StopConnectionMonitor(int port)
    {
        if (portMonitors.TryGetValue(port, out var monitor))
        {
            try { monitor.Tcp?.Stop(); } catch { }
            try { monitor.Udp?.Close(); } catch { }
            portMonitors.Remove(port);
        }
    }

    private void HandleUnauthorizedConnection(string ip, int port, string protocol)
    {
        // Only kick when they actually connected to a monitored port.
        // If they didn't connect, they are never kicked — this method is only called from connection handlers.

        // Ignore LAN devices entirely
        if (IsLocalSubnet(ip))
            return;

        Console.WriteLine("Unauthorized connection detected!");
        Console.WriteLine($"IP:  {ip}");
        Console.WriteLine($"Port: {port}");
        Console.WriteLine($"Protocol: {protocol.ToUpper()}");
        Console.WriteLine("This IP is NOT in the whitelist — initiating kick-off...\n");

        // Close all session ports
        foreach (int p in new List<int>(openedPorts))
        {
            try
            {
                ClosePort(p, "both").GetAwaiter().GetResult();
                openedPorts.Remove(p);
                Console.WriteLine($"Closed session port {p}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error closing session port {p}: {ex.Message}");
            }
        }

        // Close all UPnP ports
        try
        {
            var mappings = GetAllPortMappingsAsync().GetAwaiter().GetResult();
            foreach (var m in mappings)
            {
                if (m.HasValidPortOrProtocol)
                {
                    try
                    {
                        ClosePort(m.ExternalPort, m.Protocol.ToLowerInvariant()).GetAwaiter().GetResult();
                        Console.WriteLine($"Closed port table entry {m.ExternalPort} {m.Protocol}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to close {m.ExternalPort} {m.Protocol}: {ex.Message}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Whitelist kick-off cleanup error: {ex.Message}");
        }

        Console.WriteLine("Kick-off attempt complete.\n");
    }

    private bool IsLocalSubnet(string ip)
    {
        string local = GetLocalIPAddress();
        if (!local.Contains("."))
            return false;

        string subnet = local.Substring(0, local.LastIndexOf('.') + 1);
        return ip.StartsWith(subnet);
    }

    // -----------------------------
    // NETWORK WATCHER (ARP-based, silent)
    // -----------------------------
    private async Task StartNetworkWatcher()
    {
        while (running)
        {
            try
            {
                ScanNetwork();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Watcher error: {ex.Message}");
            }

            await Task.Delay(5000);
        }
    }

    private void ScanNetwork()
    {
        string localIp = GetLocalIPAddress();
        if (!localIp.Contains("."))
            return;

        string subnet = localIp.Substring(0, localIp.LastIndexOf('.') + 1);

        for (int i = 1; i < 255; i++)
        {
            string ip = subnet + i;
            PingHost(ip);
        }

        var arp = GetArpTable();

        foreach (var entry in arp)
        {
            string ip = entry.Key;
            string mac = entry.Value;

            if (!knownDevices.ContainsKey(ip))
            {
                knownDevices[ip] = mac;
                // Silent: no whitelist or kick here.
            }
        }
    }

    private void PingHost(string ip)
    {
        try
        {
            using var ping = new Ping();
            ping.Send(ip, 5);
        }
        catch { }
    }

    private Dictionary<string, string> GetArpTable()
    {
        var result = new Dictionary<string, string>();

        ProcessStartInfo psi = new()
        {
            FileName = "arp",
            Arguments = "-a",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        Process p = Process.Start(psi);
        string output = p!.StandardOutput.ReadToEnd();

        Regex regex = new(@"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9\-]{17})");

        foreach (Match m in regex.Matches(output))
        {
            string ip = m.Groups[1].Value;
            string mac = m.Groups[2].Value;

            if (!result.ContainsKey(ip))
                result[ip] = mac;
        }

        return result;
    }

    // -----------------------------
    // IP HELPERS
    // -----------------------------
    private string GetLocalIPAddress()
    {
        foreach (var ni in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
        {
            if (ni.AddressFamily == AddressFamily.InterNetwork)
                return ni.ToString();
        }
        return "127.0.0.1";
    }

    private string GetPublicIP()
    {
        try
        {
            using WebClient wc = new();
            return wc.DownloadString("https://api.ipify.org");
        }
        catch
        {
            return "Unavailable";
        }
    }

    // -----------------------------
    // UPNP DISCOVERY
    // -----------------------------
    private async Task DiscoverUpnpAsync()
    {
        using UdpClient udp = new();
        udp.Client.ReceiveTimeout = 3000;

        string ssdp =
            "M-SEARCH * HTTP/1.1\r\n" +
            "HOST: 239.255.255.250:1900\r\n" +
            "MAN: \"ssdp:discover\"\r\n" +
            "MX: 2\r\n" +
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";

        byte[] data = Encoding.UTF8.GetBytes(ssdp);
        IPEndPoint multicast = new(IPAddress.Parse("239.255.255.250"), 1900);

        await udp.SendAsync(data, data.Length, multicast);

        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        byte[] resp = udp.Receive(ref endpoint);

        string response = Encoding.UTF8.GetString(resp);
        string location = ExtractHeader(response, "LOCATION");

        await ParseIgdAsync(location);
    }

    private async Task ParseIgdAsync(string url)
    {
        using HttpClient http = new();
        string xml = await http.GetStringAsync(url);

        XmlDocument doc = new();
        doc.LoadXml(xml);

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("tns", "urn:schemas-upnp-org:device-1-0");

        XmlNode? service = doc.SelectSingleNode(
            "//tns:service[tns:serviceType[contains(text(),'WANIPConnection')]]",
            ns
        );

        if (service == null)
            throw new Exception("WANIPConnection service not found");

        serviceType = service["serviceType"]!.InnerText;
        string control = service["controlURL"]!.InnerText;

        Uri baseUri = new(url);
        controlUrl = new Uri(baseUri, control).ToString();
    }

    private string ExtractHeader(string response, string header)
    {
        foreach (string line in response.Split("\r\n"))
        {
            if (line.StartsWith(header, StringComparison.OrdinalIgnoreCase))
                return line[(header.Length + 1)..].Trim();
        }
        throw new Exception($"{header} not found");
    }

    // -----------------------------
    // UPNP PORT MAPPING
    // -----------------------------
    public async Task OpenPort(int port, string protocol)
    {
        protocol = protocol.ToLowerInvariant();

        if (protocol == "tcp" || protocol == "both")
            await AddMapping(port, "TCP");

        if (protocol == "udp" || protocol == "both")
            await AddMapping(port, "UDP");
    }

    public async Task ClosePort(int port, string protocol)
    {
        protocol = protocol.ToLowerInvariant();

        if (protocol == "tcp" || protocol == "both")
            await DeleteMapping(port, "TCP");

        if (protocol == "udp" || protocol == "both")
            await DeleteMapping(port, "UDP");

        StopConnectionMonitor(port);
    }

    private async Task AddMapping(int port, string proto)
    {
        string body =
            $"<u:AddPortMapping xmlns:u=\"{serviceType}\">" +
            $"<NewRemoteHost></NewRemoteHost>" +
            $"<NewExternalPort>{port}</NewExternalPort>" +
            $"<NewProtocol>{proto}</NewProtocol>" +
            $"<NewInternalPort>{port}</NewInternalPort>" +
            $"<NewInternalClient>{GetLocalIPAddress()}</NewInternalClient>" +
            $"<NewEnabled>1</NewEnabled>" +
            $"<NewPortMappingDescription>Network Helper++</NewPortMappingDescription>" +
            $"<NewLeaseDuration>0</NewLeaseDuration>" +
            $"</u:AddPortMapping>";

        await SendSoap("AddPortMapping", body);
    }

    private async Task DeleteMapping(int port, string proto)
    {
        string body =
            $"<u:DeletePortMapping xmlns:u=\"{serviceType}\">" +
            $"<NewRemoteHost></NewRemoteHost>" +
            $"<NewExternalPort>{port}</NewExternalPort>" +
            $"<NewProtocol>{proto}</NewProtocol>" +
            $"</u:DeletePortMapping>";

        await SendSoap("DeletePortMapping", body);
    }

    private async Task SendSoap(string action, string body)
    {
        string envelope =
            "<?xml version=\"1.0\"?>" +
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
            "<s:Body>" + body + "</s:Body></s:Envelope>";

        using HttpClient http = new();
        var req = new HttpRequestMessage(HttpMethod.Post, controlUrl);
        req.Headers.Add("SOAPAction", $"\"{serviceType}#{action}\"");
        req.Content = new StringContent(envelope, Encoding.UTF8, "text/xml");

        var resp = await http.SendAsync(req);
        if (!resp.IsSuccessStatusCode)
        {
            string err = await resp.Content.ReadAsStringAsync();
            throw new Exception($"SOAP error: {resp.StatusCode}\n{err}");
        }
    }

    // -----------------------------
    // UPNP PORT TABLE SCAN
    // -----------------------------
    private class PortMapping
    {
        public bool HasValidPortOrProtocol { get; set; }
        public int ExternalPort { get; set; }
        public int InternalPort { get; set; }
        public string Protocol { get; set; } = "";
        public string InternalClient { get; set; } = "";
        public string Description { get; set; } = "";
        public string RawPort { get; set; } = "";
        public string RawProtocol { get; set; } = "";
    }

    private async Task<List<PortMapping>> GetAllPortMappingsAsync()
    {
        var list = new List<PortMapping>();
        int index = 0;

        while (true)
        {
            string body =
                $"<u:GetGenericPortMappingEntry xmlns:u=\"{serviceType}\">" +
                $"<NewPortMappingIndex>{index}</NewPortMappingIndex>" +
                $"</u:GetGenericPortMappingEntry>";

            string envelope =
                "<?xml version=\"1.0\"?>" +
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
                "<s:Body>" + body + "</s:Body></s:Envelope>";

            using HttpClient http = new();
            var req = new HttpRequestMessage(HttpMethod.Post, controlUrl);
            req.Headers.Add("SOAPAction", $"\"{serviceType}#GetGenericPortMappingEntry\"");
            req.Content = new StringContent(envelope, Encoding.UTF8, "text/xml");

            HttpResponseMessage resp;
            try
            {
                resp = await http.SendAsync(req);
            }
            catch
            {
                break;
            }

            if (!resp.IsSuccessStatusCode)
            {
                // Typically means no more entries
                break;
            }

            string xml = await resp.Content.ReadAsStringAsync();

            try
            {
                XmlDocument doc = new();
                doc.LoadXml(xml);

                string rawPort = doc.GetElementsByTagName("NewExternalPort")?.Item(0)?.InnerText ?? "";
                string rawProto = doc.GetElementsByTagName("NewProtocol")?.Item(0)?.InnerText ?? "";
                string rawInternalPort = doc.GetElementsByTagName("NewInternalPort")?.Item(0)?.InnerText ?? "";
                string internalClient = doc.GetElementsByTagName("NewInternalClient")?.Item(0)?.InnerText ?? "";
                string desc = doc.GetElementsByTagName("NewPortMappingDescription")?.Item(0)?.InnerText ?? "";

                var mapping = new PortMapping
                {
                    RawPort = rawPort,
                    RawProtocol = rawProto,
                    InternalClient = internalClient,
                    Description = string.IsNullOrWhiteSpace(desc) ? "No description" : desc
                };

                if (int.TryParse(rawPort, out int extPort) &&
                    int.TryParse(rawInternalPort, out int intPort) &&
                    !string.IsNullOrWhiteSpace(rawProto))
                {
                    mapping.HasValidPortOrProtocol = true;
                    mapping.ExternalPort = extPort;
                    mapping.InternalPort = intPort;
                    mapping.Protocol = rawProto;
                }
                else
                {
                    mapping.HasValidPortOrProtocol = false;
                }

                list.Add(mapping);
            }
            catch
            {
                list.Add(new PortMapping
                {
                    HasValidPortOrProtocol = false,
                    RawPort = "N/A",
                    RawProtocol = "N/A",
                    Description = "Parse error"
                });
            }

            index++;
        }

        return list;
    }
}