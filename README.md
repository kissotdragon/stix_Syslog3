# stix_Syslog3
A quick and dirty STIX/TAXII client that grabs STIX data from a TAXII discovery service, parses out the indicators and observables, and sends the data via CEF Syslog

# Requirements
This script has been updated to work with Python3 -- updated to use BeautifulSoup to parse the STIX document.  You could modify this script to use CABBY or the STIX libraries.

This script requires some python dependencies.  You can install these using pip3.

Needed modifications:
SET SYSLOG SERVER IP/PORT,
SET PROXY,
SET TIME DELTA,
SET COLLECTION NAME,
SET URL/USERNAME/PASSWORD

# Description

This is a script that connects to a TAXII servers discovery service, grabs the STIX document and parses out the indicators and observables. Specifically, this will parse IP's, Websites, Email Addresses, and Hash's. It takes the data creates a CEF message and sends is via CEF syslog to a syslog endpoint. 

# Example Usage
## Import from TAXII Server

    python3 stix_Syslog3.py

Copyright 2025 Centeral Entperises LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
