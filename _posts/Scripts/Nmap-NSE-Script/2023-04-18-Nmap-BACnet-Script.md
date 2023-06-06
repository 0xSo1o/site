---
title: "Nmap BACnet Script"
classes: wide
header:
  teaser: /assets/images/scripts/Nmap/logo.png
  overlay_image: /assets/images/scripts/Nmap/logo.png
  overlay_filter: 0.5
ribbon: DarkSlateGray
excerpt: ""
description: "BACnet & Vulners script"
categories:
  - Scripts
tags:
  - Nmap
  - Script
  - BACnet
  - Vulners
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "code"
---

<!-- Toc Color -->
<style>
.toc .nav__title {
  color: #fff;
  font-size: .75em;
  background: #15bf66;
  border-top-left-radius: 4px;
  border-top-right-radius: 4px;
</style>

# Intro

As part of my professional endeavors, I actively engage in comprehensive assessments of large-scale networks with the objective of identifying potential vulnerabilities. Throughout my assessments, I have noticed instances where certain protocols are absent from the results. In response to this observation, I have developed a script that effectively combines the search for the BACnet protocol with vulnerability scanning techniques. 

<b></b>
The script allows for a more thorough evaluation of network security by examining the obtained results for potential vulnerabilities. This script leverages the bacnet-info.nse script as the source for the BACnet scanning functionality and Vulners library to perform the vulnerability scanning.

# The Script Summary

When the script encounters a BACnet service, it carries out a sequence of two distinct operations.

1. The BACnet scan uses the bacnet-info.nse script to gather information about the BACnet service running on the target host and port. This script provides detailed information such as device identification, supported objects, properties, and more. The scan results are returned as part of the script output.

2. Vulners Scan: After the BACnet scan, the script leverages the Vulners library to perform vulnerability scanning. It uses the vulners.scan function to check for any known vulnerabilities associated with the BACnet service. The vulnerability scan results are also returned as part of the script output.

Subsequently, it merges the outcomes from both scans and delivers them to the user. This approach empowers the user to identify BACnet services and assess their prospective vulnerabilities across the specified ports.

<b></b>

**Note:** Make sure you have Nmap and the necessary dependencies installed on your system. Save the script in your Nmap NSE scripts directory with .nse as extension(e.g., bacnet.<b>nse</b>). 
{: .notice}

<b></b>

# Example Usage

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap -sU --script bacnet -p 47808,47809,47810,47111 <host>
```

# The Script

```lua
local nmap = require("nmap")
local shortport = require("shortport")
local stdnse = require("stdnse")
local vulns = require("vulns")

description = [[
  Checks for BACnet services on UDP and TCP ports 47808, 47809, 47810, and 47111.
  Additionally, it leverages the Vulners script for vulnerability scanning.
]]

---
-- Performs the BACnet scan on the specified host and port.
---
local function bacnet_scan(host, port)
  local status, result = stdnse.new_try("bacnet-info", host, port)
  if status == false then
    return stdnse.format_output(false, result)
  end
  return stdnse.format_output(true, result)
end

---
-- Performs the Vulners scan on the specified host and port.
---
local function vulners_scan(host, port)
  local vulners_script = vulns.script
  if vulners_script then
    local status, result = stdnse.new_try(vulners_script, host, port)
    if status == false then
      return stdnse.format_output(false, result)
    end
    return stdnse.format_output(true, result)
  else
    return stdnse.format_output(false, "Vulners script not available.")
  end
end

---
-- Executes the BACnet Nmap script on the specified host and port.
---
local function bacnet_nmap_script(host, port)
  local protocols = { "udp", "tcp" }
  local status, result

  for _, protocol in ipairs(protocols) do
    if port.protocol == protocol then
      status, result = bacnet_scan(host, port)
      if status then
        return status, result
      end
    end
  end

  return stdnse.format_output(false, "BACnet service not found on the specified ports.")
end

---
-- Executes the Vulners Nmap script on the specified host and port.
---
local function vulners_nmap_script(host, port)
  local status, result = vulners_scan(host, port)
  return status, result
end

---
-- Executes the main action of the script.
---
action = function(host, port)
  local status, result = bacnet_nmap_script(host, port)

  if not status then
    status, result = vulners_nmap_script(host, port)
  end

  return status, result
end

---
-- Retrieves the port rule for the specified host.
---
local function get_port_rule(host)
  return shortport.port_or_service(host, { 47808, 47809, 47810, 47111 }, "bacnet")
end

---
-- Checks if the specified host is valid.
---
local function is_valid_host(host)
  if host.ipv4 or host.ipv6 then
    return true
  end
  return false
end

---
-- Determines the validity of the specified host.
---
hostrule = function(host)
  return is_valid_host(host)
end

portrule = function(host)
  return get_port_rule(host)
end

return {
  hostrule = hostrule,
  portrule = portrule,
  action = action,
  categories = categories
}
```