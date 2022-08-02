#**
#** Name   : netskope_steering_irule
#** Author : bretts@netskope.com
#** Description: Used to steer connections to Netskope EPoT replacing PAC files
#**

when RULE_INIT {
  ## Debug logging control
   # 0 = Logging Disabled.
   # 1 = DEBUG Logging Enabled. Do not enable in Production when using log local0.
  set static::netskope_dbg 1

  ## Default Decision Flag
   # 0 = Netskope
   # 1 = BIG-IP Explicit Proxy
  set static::default_decision "0"
  
  ## DNS resolver
   # Used to check split DNS IP Addresses
  set static::dns_resolver "/Common/proxy_dns_resolver"

  ## Netskope EPoT Virtual Server - Default Path
   # This virtual server is listening on a VLAN with no interfaces attached, private to the BIG-IP.
  set static::ns_epot_vs "/Common/ns_epot_tcp_80_vs"

  ## Data group containing non-routable local networks (RFC1918, Link-Local, CGNAT etc).
   # If the local network is the destination should not be routed to Netskope.
   # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  set static::local_networks_dg "local_networks_dg"
  
  ## Data group containing Domains (example.com will match exact and .example.com) or FQDNs (www.example.com) that have split DNS.
   # These FQDNs require DNS lookup to determine if they should be steered to Netskope.
  set static::split_dns_dg "split_dns_dg"

  ## Data group containing Source IP Addresses (10.1.1.1) or Networks (10.0.0.0/8)
   # Any IP or CIDR is this data-group with a value of "0" will be steered to Netskope.
   # Any IP or CIDR is this data-group with a value of "1" will be processed by the BIG-IP Explicit Proxy.
  set static::source_ip_steering_dg "source_ip_steering_dg"

  ## Data group containing Domains (example.com will match exact and .example.com) or FQDNs (www.example.com)
   # Any Domain or FQDN is this data-group with a value of "0" will be steered to Netskope.
   # Any Domain or FQDN is this data-group with a value of "1" will be processed by the BIG-IP Explicit Proxy.
  set static::fqdn_steering_dg "fqdn_steering_dg"
}


## This procedure will log DEBUG level information to /var/log/ltm be default
 # Should only be enabled in a Test environment
 # To enable in Production, use HSL:open and HSL::send (https://clouddocs.f5.com/api/irules/HSL__send.html)
proc netskope_dbg_log { log_message } {
  if { $static::netskope_dbg } {
    log local0. "timestamp=[clock clicks -milliseconds],vs=[virtual],$log_message"
  }
}

when CLIENT_ACCEPTED {
  set log_prefix "s_ip=[IP::client_addr],s_port=[TCP::client_port],d_ip=[IP::local_addr],d_port=[TCP::local_port]"
}

## Only trigger on Explicit Proxy requests
when HTTP_PROXY_REQUEST {
  # Default Action
  set decision $static::default_decision

  # Strip off the port number from the HTTP Host
  set host [string tolower [lindex [split [HTTP::host] ":"] 0]]
  append log_prefix ",host=$host"
  
  # Check if the HTTP Host is an IP Address
  if {[scan $host %d.%d.%d.%d a b c d] == 4 } {
    # If the IP Address matches the non-routable local networks, don't send to Netskope. 
    if { ([class match $host equals $static::local_networks_dg] ) } {
      call netskope_dbg_log "$log_prefix,decision=1"
      event disable
      return
    }
  }
  
  # Check if the HTTP host is Split DNS record
  if { [class match $host ends_with $static::split_dns_dg] } {
    # DNS resolve the HTTP host
    set result [RESOLVER::name_lookup $static::dns_resolver $host a]
    set answer [DNSMSG::section $result answer]

    # If DNS returns an Answer, check the A record for a match
    if { $answer ne "" } {
      set ip ""
      
      # Loop through the answer looking for the A record in the Resource Records (RR)
      foreach rr $answer {
        # If the DNS type equals "A", use the first IP found. Scenario of multiple "A" records
        if { [DNSMSG::record $rr type] equals "A" } {
          set ip [DNSMSG::record $rr rdata]
          # If the IP Address matches the non-routable local networks, don't send to Netskope. 
          if { ([class match $ip equals $static::local_networks_dg] ) } {
            call netskope_dbg_log "$log_prefix,decision=1"
            event disable
            return
          }
        }
      }
    }
  }

  ## Steering decision based on Source IP Addresses (10.1.1.1) or Networks (10.0.0.0/8)
   # "0" will be steered to Netskope.
   # "1" will be processed by the BIG-IP Explicit Proxy.
  if { ([class match [IP::client_addr] equals $static::source_ip_steering_dg] ) } {
    set decision [class match -value [IP::client_addr] equals $static::source_ip_steering_dg]
  }

  ## Steering decision based on Domains (example.com will match exact and .example.com) or FQDNs (www.example.com)
   # "0" will be steered to Netskope.
   # "1" will be processed by the BIG-IP Explicit Proxy.
  if { [class match $host ends_with $static::fqdn_steering_dg] } {
    set decision [class match -value $host ends_with $static::fqdn_steering_dg]
  }

  ## Switch the connection flow to Netskope (if required) by changing to the "Netskope EPoT Virtual Server"
  switch $decision {
    "1" {
      # BIG-IP Explicit Proxy (Local Proxy)
      call netskope_dbg_log "$log_prefix,decision=$decision"
    }

    default {
      # Netskope EPoT Virtual Server
      HTTP::proxy disable
      virtual $static::ns_epot_vs
      call netskope_dbg_log "$log_prefix,decision=$decision"
    }
  }
}
