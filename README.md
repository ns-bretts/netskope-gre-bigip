# Netskope GRE configuration for BIG-IP

## Names and IP Addressing used in this Example
BIG-IP:
  - 2x VLANs:
    - External:
      - Name: public
      - Self IP: 10.254.1.245 /24
    - Internal:
      - Name: private
      - Self IP: 10.254.2.245 /24
  - Default GW: 10.254.1.254

## 1. GRE Tunnels
Create a GRE tunnel configuration per Data Plane (DP). The two examples below are for SYD1 and MEL1.

### 1.1. GRE Tunnel per DP
- The local-address should be set to the Self IP of the egress interface on the BIG-IP. When the BIG-IP is deployed in a Cluster, this IP should be the Floating Self IP attached to the traffic group.
- The remote-address should be set to the Data Plane (DP) GRE Gateway IP.
```
create net tunnels tunnel ns_syd1_gre { local-address 10.254.1.245 remote-address 163.116.192.36 profile gre description "Netskope NewEdge - SYD1" }
create net tunnels tunnel ns_mel1_gre { local-address 10.254.1.245 remote-address 163.116.198.36 profile gre description "Netskope NewEdge - MEL1" }
```

### 1.2. GRE Tunnel Self IPs
- A Self IP needs to be assigned to the local (inner) GRE Tunnel. This IP address is arbitrary. I like to use the 3rd Octet of the Data Plane (DP) GRE Gateway IP in the Self IP to help identify which tunnel it’s associated with.
```
create net self ns_syd1_self { address 10.1.192.1/30 vlan ns_syd1_gre }
create net self ns_mel1_self { address 10.1.198.1/30 vlan ns_mel1_gre }
```

## 2. Probe IPs
### 2.1. ICMP Monitor
- An ICMP monitor is required per GRE Tunnel with the destination set to the Probe IP specific to the DP. The Probe IPs are documented within the Tenant GRE configuration setup.
```
create ltm monitor icmp ns_syd1_icmp { defaults-from icmp destination 10.192.6.209 }
create ltm monitor icmp ns_mel1_icmp { defaults-from icmp destination 10.198.6.209 }
```
### 2.2. Probe IP Routing
- For the ICMP to be successful a host route needs to be created for each GRE Tunnel.
```
create net route ns_syd1_route_probe { interface ns_syd1_gre network 10.192.6.209/32 }
create net route ns_mel1_route_probe { interface ns_mel1_gre network 10.198.6.209/32 }
```
## 3. Load Balancing the GRE Tunnels
### 3.1. Netskope Gateway Node + Monitoring
- Create a node using the address of the remote (Netskope end of the tunnel) and apply the ICMP monitor. This node will be used as a gateway pool member within the load balancing configuration.
```
create ltm node ns_syd1_gw { address 10.1.192.2 monitor ns_syd1_icmp }
create ltm node ns_mel1_gw { address 10.1.198.2 monitor ns_mel1_icmp }
```
### 3.2. HTTP Monitor
- Create a HTTP monitor that will send a HTTP Request to a well know site. This HTTP monitor will send the HTTP request over the GRE Tunnel to NS Proxy, simulating a real Client request. This is just one example of a HTTP monitor.
- I would recommend using more than one HTTP or HTTPS monitor with an “Availability Requirement” of at lease one monitor. This will prevent the GRE Tunnel from flapping in the event of a single HTTP/S monitor failure.
```
create ltm monitor http ns_http_monitor { defaults-from http destination *.http recv "Microsoft NCSI" send "GET /ncsi.txt HTTP/1.1\r\nHost: www.msftncsi.com\r\nUser-Agent: BIG-IP\r\nConnection: Close\r\n" }
```
### 3.3. Gateway Pool
- Create a Gateway Pool using the nodes from step 3.1 and apply the HTTP monitor.
- The Gateway pool can be configured for many different scenarios.
- Below I have included a Failover option OR a Load Balance option using Round-Robin. More advanced Load Balancing options are available depending on the BIG-IP license.

(a) Failover Option
```
create ltm pool ns_gw_pool { members replace-all-with { ns_syd1_gw:0 { priority-group 10 } ns_mel1_gw:0 { priority-group 1 } } min-active-members 1 monitor ns_http_monitor }
```
(b) Load Balance Option
```
create ltm pool ns_gw_pool { members replace-all-with { ns_syd1_gw:0 ns_mel1_gw:0 } load-balancing-mode round-robin monitor ns_http_monitor }
```
## 4. Virtual Servers
### 4.1. Transparent Steering/Forwarding
- To forward the traffic to Netskope NewEdge, create a Virtual Server for TCP:80 and TCP:443.
- I recommend using a custom Fast L4 TCP profile so you can tune the TCP settings. In the example below I have disabled “SYN Cookies” as this is mutually exclusive for transparent proxy configurations.
- Persistence (affinity/sticky sessions) is enabled using Source IP with a default timeout of 180 seconds. The persistence will we honoured across the each Virtual Server using the match-across-virtuals option.
- Source Address and Port Address Translation is disabled.
- Apply the Virtual Server to the correct VLAN specific to your configuration.
```
create ltm profile fastl4 ns_l4_profile { defaults-from fastL4 syn-cookie-enable disabled }
create ltm persistence source-addr ns_source_addr { defaults-from source_addr match-across-virtuals enabled timeout 7200 }
create ltm virtual ns_http_80_vs { destination 0.0.0.0:80 ip-protocol tcp profiles replace-all-with { ns_l4_profile } vlans-enabled vlans replace-all-with { private } translate-port disabled translate-address disabled pool ns_gw_pool persist replace-all-with { ns_source_addr } description "Forward HTTP to Netskope" }
create ltm virtual ns_https_443_vs { destination 0.0.0.0:443 ip-protocol tcp profiles replace-all-with { ns_l4_profile } vlans-enabled vlans replace-all-with { private } translate-port disabled translate-address disabled pool ns_gw_pool persist replace-all-with { ns_source_addr } description "Forward HTTPS to Netskope" }
```
### 4.2. Explicit Proxy over Tunnel (EPoT)
- The BIG-IP can also be configured to forward Explicit Proxy over Tunnel (EPoT).
- The Virtual Server configuration is very similar to transparent steering (4.1.), using the same Fast L4 TCP profile and Persistence configuration.
```
create ltm virtual ns_epot_80_vs { destination 10.254.2.200:80 ip-protocol tcp profiles replace-all-with { ns_l4_profile } vlans-enabled vlans replace-all-with { private } translate-port disabled translate-address disabled pool ns_gw_pool persist replace-all-with { ns_source_addr } description "Netskope Explicit Proxy" }
```
### 4.3 Cloud Firewall
- If Cloud Firewall is enabled, you have to add additional Virtual Servers for TCP, UDP and ICMP.
```
create ltm virtual ns_all_traffic_vs { destination 0.0.0.0:any ip-protocol any profiles replace-all-with { ns_l4_profile } vlans-enabled vlans replace-all-with { private } translate-port disabled translate-address disabled pool ns_gw_pool persist replace-all-with { ns_source_addr } description "Forward All Traffic Netskope" }
```
