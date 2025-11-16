#py file for library management
import telebot
import g4f
import os
import requests
import re
import pandas as pd
import ipaddress

from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN=os.getenv("BOT_TOKEN")

SHODAN_URL=os.getenv("SHODAN_URL")
SHODAN_API_KEY=os.getenv("SHODAN_API_KEY")

IPAPI_URL=os.getenv("IPAPI_URL")

ABUSEIPDB_URL=os.getenv("ABUSEIPDB_URL")
ABUSEIPDB_API_KEY=os.getenv("ABUSEIPDB_API_KEY")

MAC_VENDOR_LOOKUP_URL=os.getenv("MAC_VENDOR_LOOKUP_URL")

PORTS_FILE_NAME=os.getenv("PORTS_FILE_NAME", "port-numbers-service-names.xlsx")

MACLOOKUP_API_KEY=os.getenv("MACLOOKUP_API_KEY")
MACLOOKUP_URL=os.getenv("MACLOOKUP_URL")