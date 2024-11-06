# shadow.rb

require 'net/ping'  # For network ping tests
require 'socket'    # For port scanning
require 'digest'    # For password cracking and hashing
require 'open-uri'  # For HTTP request to simulate vulnerability scanning

# Main SHADOW toolkit module
module Shadow

  # ----------------------------------------------
  # Vulnerability Scanner
  # ----------------------------------------------
  class VulnerabilityScanner
    def initialize
      @vulnerabilities = []
    end

    # Simulate vulnerability scanning by checking common HTTP vulnerabilities
    def scan_http_vulnerabilities(url)
      puts "Scanning HTTP endpoint for vulnerabilities..."

      # Placeholder: Check for common HTTP vulnerabilities (like directory traversal, etc.)
      begin
        open(url)
        puts "Connected to #{url} successfully."
        # You would add more complex vulnerability checks here (e.g., SQL Injection, XSS)
        puts "Potential vulnerability detected: Open redirect at #{url}/redirect"
      rescue => e
        puts "Error accessing URL #{url}: #{e.message}"
      end
    end

    # Simulate a basic vulnerability scan for OS/Network based vulnerabilities
    def scan_network_vulnerabilities(target_ip)
      puts "Scanning network for vulnerabilities on IP: #{target_ip}..."
      # Example: Look for open ports
      open_ports = scan_ports(target_ip)
      if open_ports.any?
        puts "Vulnerabilities detected: Open ports #{open_ports.join(', ')}"
      else
        puts "No open ports found."
      end
    end

    # Placeholder: Simulate a simple port scan
    def scan_ports(target_ip)
      open_ports = []
      (20..1024).each do |port|
        begin
          socket = Socket.new(:INET, :STREAM)
          socket.connect(Socket.sockaddr_in(port, target_ip))
          open_ports << port
          socket.close
        rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT
          next
        end
      end
      open_ports
    end

    # Print out a basic vulnerability report
    def report
      puts "\nVulnerability Report:"
      @vulnerabilities.each do |vuln|
        puts "ID: #{vuln[:id]}, Name: #{vuln[:name]}, Severity: #{vuln[:severity]}"
      end
    end
  end

  # ----------------------------------------------
  # Network Analyzer
  # ----------------------------------------------
  class NetworkAnalyzer
    def initialize(target)
      @target = target
    end

    # Perform a basic ping test
    def ping_test
      puts "Running ping test on #{@target}..."
      check = Net::Ping::External.new(@target)
      if check.ping
        puts "Ping successful to #{@target}"
      else
        puts "Ping failed to #{@target}"
      end
    end

    # Perform a basic port scan
    def port_scan
      puts "Scanning ports for #{@target}..."
      open_ports = scan_ports(@target)
      if open_ports.any?
        puts "Open ports: #{open_ports.join(', ')}"
      else
        puts "No open ports detected."
      end
    end

    private

    def scan_ports(target_ip)
      open_ports = []
      (20..1024).each do |port|
        begin
          socket = Socket.new(:INET, :STREAM)
          socket.connect(Socket.sockaddr_in(port, target_ip))
          open_ports << port
          socket.close
        rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT
          next
        end
      end
      open_ports
    end
  end

  # ----------------------------------------------
  # Password Cracker
  # ----------------------------------------------
  class PasswordCracker
    def initialize
      @common_passwords = %w[password 123456 qwerty letmein admin 12345]
    end

    # Attempt to crack a hashed password using a basic dictionary attack
    def crack_password(hash)
      puts "Attempting to crack password for hash: #{hash}"
      @common_passwords.each do |password|
        if Digest::SHA256.hexdigest(password) == hash
          puts "Password cracked: #{password}"
          return password
        end
      end
      puts "Password not found in dictionary."
      nil
    end
  end

  # ----------------------------------------------
  # Defensive Operations (Firewall, Monitoring)
  # ----------------------------------------------
  class DefensiveOperations
    def initialize
      @firewall_rules = []
    end

    # Add a rule to the firewall
    def add_firewall_rule(rule)
      puts "Adding firewall rule: #{rule}"
      @firewall_rules << rule
    end

    # Monitor network activity and detect suspicious events
    def monitor_network
      puts "Monitoring network traffic for suspicious activity..."
      # Placeholder: Simulate some suspicious activity
      suspicious_activity = ["Unusual login attempt", "High data upload from IP 192.168.1.10"]
      suspicious_activity.each do |activity|
        puts "Alert: #{activity}"
      end
    end

    # List the active firewall rules
    def list_firewall_rules
      puts "\nCurrent Firewall Rules:"
      @firewall_rules.each { |rule| puts "Rule: #{rule}" }
    end
  end
end

# Example usage
puts "Welcome to SHADOW Toolkit\n\n"

# Initialize tools
vuln_scanner = Shadow::VulnerabilityScanner.new
network_analyzer = Shadow::NetworkAnalyzer.new("192.168.1.1")
password_cracker = Shadow::PasswordCracker.new
defensive_ops = Shadow::DefensiveOperations.new

# Run vulnerability scans
vuln_scanner.scan_http_vulnerabilities("http://example.com")
vuln_scanner.scan_network_vulnerabilities("192.168.1.1")

# Perform network analysis
network_analyzer.ping_test
network_analyzer.port_scan

# Attempt to crack a password hash (example hash for 'password')
hashed_password = Digest::SHA256.hexdigest("password")
password_cracker.crack_password(hashed_password)

# Set up defensive operations
defensive_ops.add_firewall_rule("Allow only HTTPS traffic")
defensive_ops.monitor_network
defensive_ops.list_firewall_rules
