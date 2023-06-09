---
title: "Python X2C Script"
classes: wide
header:
  teaser: /assets/images/scripts/Nmap/logo.png
  overlay_image: /assets/images/scripts/Nmap/logo.png
  overlay_filter: 0.5
ribbon: DarkSlateGray
excerpt: ""
description: "Python XML to CSV converter script"
categories:
  - Scripts
tags:
  - Python
  - Script
  - XML
  - CSV
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

As part of my professional endeavors, I actively engage in comprehensive assessments of large-scale networks with the objective of identifying potential vulnerabilities. Often upon reviewing the results, I would like to selectively extract specific components faster, such as the IP & MAC addresses as well as the vendor name, while omiting rest of th information. In response to this observation, I developed a set of Python scripts that effectively takes Nmap XML results and converts them to CSV file.

<b></b>
The scripts are designed to parse a specific type of data, namely IP, MAC, or vendor information, with the aim of expediting the information retrieval process. However, I encountered a challenge in developing a unified script that would enable the seamless population of each row, containing the corresponding data for IP, MAC, and vendor information.

# The Script Summary

These scripts import the csv and xml.etree.ElementTree modules and defines two functions: parse_data and write_csv. The parse_data function takes an XML output file as input, extracts IP, MAC, and vendor information from the file, and returns a list of dictionaries containing this information. The write_csv function takes this list of dictionaries and writes the IP, MAC addresses and Vendor names to a CSV file.

The scripts prompts the user to enter the path to the Nmap XML output file and the desired output file path. It then calls the parse_data and write_csv functions with these inputs to generate a CSV file containing desired output.

<b></b>

**Note:** It is recommended to verify that the input file has the .xml extension before opening it, and to ensure that the output file has the .csv extension when saving it. This can help to prevent any potential errors or issues that may arise from incorrect file extensions. 
{: .notice}

<b></b>

# The Scripts

This script is designed to parse IP addresses
```python
import csv
import xml.etree.ElementTree as ET

def parse_data(xml_output):
    data = []
    tree = ET.parse(xml_output)
    root = tree.getroot()
    for host in root.findall('host'):
        ip_address = host.find('address').get('addr')
        mac_address = ''
        vendor = ''
        for address in host.findall('address'):
            if address.get('addrtype') == 'mac':
                mac_address = address.get('addr')
                vendor = address.get('vendor')
        if mac_address:
            data.append({'IP': ip_address, 'MAC': mac_address, 'Vendor': vendor})
    return data


def write_csv(data, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address'])
        for row in data:
            writer.writerow([row['IP']])

# Prompts the user to enter the path to the Nmap XML output file
xml_output_file = input("Enter path to Nmap XML output file: ")

# Parses the XML data and write the IP addresses that have a MAC address and vendor name to a CSV file
data = parse_data(xml_output_file)
output_file = input("Enter path to output file: ")
write_csv(data, output_file)
```
<b></b>

This script is designed to parse MAC addresses

```python
import csv
import xml.etree.ElementTree as ET

def parse_data(xml_output):
    data = []
    tree = ET.parse(xml_output)
    root = tree.getroot()
    for host in root.findall('host'):
        ip_address = host.find('address').get('addr')
        mac_address = ''
        vendor = ''
        for address in host.findall('address'):
            if address.get('addrtype') == 'mac':
                mac_address = address.get('addr')
            if address.get('vendor'):
                vendor = address.get('vendor')
        if vendor:
            data.append({'IP': ip_address, 'MAC': mac_address, 'Vendor': vendor})
    return data


def write_csv(data, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['MAC'])
        for row in data:
            writer.writerow([row['MAC']])

# Prompts the user to enter the path to the Nmap XML output file
xml_output_file = input("Enter path to Nmap XML output file: ")

# Parses the XML data and write the MAC addresses of the IP addresses that have a vendor name to a CSV file
data = parse_data(xml_output_file)
output_file = input("Enter path to output file: ")
write_csv(data, output_file)
```
<b></b>

This script is designed to parse Vendor names

```python
import csv
import xml.etree.ElementTree as ET

def parse_data(xml_output):
    data = []
    tree = ET.parse(xml_output)
    root = tree.getroot()
    for host in root.findall('host'):
        ip_address = host.find('address').get('addr')
        mac_address = ''
        vendor = ''
        for address in host.findall('address'):
            if address.get('addrtype') == 'mac':
                mac_address = address.get('addr')
            if address.get('vendor'):
                vendor = address.get('vendor')
        if vendor:
            data.append({'IP': ip_address, 'MAC': mac_address, 'Vendor': vendor})
    return data


def write_csv(data, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Vendor'])
        for row in data:
            writer.writerow([row['Vendor']])

# Prompts the user to enter the path to the Nmap XML output file
xml_output_file = input("Enter path to Nmap XML output file: ")

# Parses the XML data and write the vendor names of the IP addresses that have a vendor name to a CSV file
data = parse_data(xml_output_file)
output_file = input("Enter path to output file: ")
write_csv(data, output_file)
```