import requests
import os
import time
import asyncio
import fitz  # PyMuPDF
from concurrent.futures import ThreadPoolExecutor
from aiohttp import ClientSession
from colorama import Fore, Style, init
from datetime import datetime 
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

# Replace with your VirusTotal API key
API_KEY = "YOUR API"

# Function to extract embedded URLs from a PDF
def extract_embedded_urls(pdf_file_path):
    try:
        urls = []
        pdf_document = fitz.open(pdf_file_path)
        for page_num in range(pdf_document.page_count):
            page = pdf_document[page_num]
            for link in page.get_links():
                if link['uri']:
                    urls.append(link['uri'])
        pdf_document.close()
        return urls
    except Exception as e:
        print(f"Failed to extract embedded URLs from the PDF: {str(e)}")
        return []

# Function to check the safety of a URL using the VirusTotal URL scan API
async def check_url_safety(session, url):
    url_scan_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": API_KEY,
    }
    params = {
        "url": url,
    }
    async with session.get(url_scan_url, headers=headers, params=params) as response:
        if response.status == 200:
            response_json = await response.json()
            if "data" in response_json:
                return response_json["data"]["attributes"]["last_analysis_stats"]["malicious"] == 0
    return False

# Function to upload a file to VirusTotal
def upload_file_to_virustotal(pdf_file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": API_KEY,
    }
    with open(pdf_file_path, "rb") as file:
        files = {"file": (pdf_file_path, file)}
        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            response_json = response.json()
            resource_id = response_json["data"]["id"]
            return resource_id
        else:
            print("Failed to submit the file for scanning.")
            return None

# Function to fetch general information about the file
async def fetch_general_info(session, resource_id, pdf_file_path):
    url = f"https://www.virustotal.com/api/v3/analyses/{resource_id}"
    headers = {
        "x-apikey": API_KEY,
    }
    for retry_count in range(60):
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                response_json = await response.json()
                status = response_json["data"]["attributes"]["status"]
                if status == "completed":
                    # Extract general information
                    file_name = os.path.basename(pdf_file_path)
                    file_size = os.path.getsize(pdf_file_path)
                    scan_date = datetime.fromtimestamp(os.path.getmtime(pdf_file_path)).strftime('%Y-%m-%d %H:%M:%S')
                    file_type = response_json["data"]["attributes"].get("file_info", {}).get("file_type", "N/A")
                    threat_categories = response_json["data"]["attributes"].get("tags", [])
                    popular_threat_labels = response_json["data"]["attributes"].get("popular_threat_labels", [])
                    detected_engines = [
                        (engine, result["category"], result.get("result", "N/A"))
                        for engine, result in response_json["data"]["attributes"]["results"].items()
                        if result["category"] == "malicious"
                    ]
                    embedded_urls = extract_embedded_urls(pdf_file_path)
                    url_safety_info = await check_embedded_urls_safety(session, embedded_urls)
                    scan_result = Fore.RED + "Malicious" + Style.RESET_ALL if detected_engines or any(safety == "Malicious" for _, safety in url_safety_info) else Fore.GREEN + "Clean" + Style.RESET_ALL

                    return file_name, file_size, scan_date, file_type, ', '.join(threat_categories) or "N/A", ', '.join(popular_threat_labels) or "N/A", scan_result, detected_engines, embedded_urls, url_safety_info
                elif status == "queued":
                    print(f"{Fore.YELLOW}Analysis in progress. Status: queued. Retrying in 10 seconds... (Retry {retry_count+1} of 60){Style.RESET_ALL}")
                    await asyncio.sleep(10)
                else:
                    print(f"Analysis failed with status: {status}")
                    return None, None, None, None, None, None, None, [], [], []
            else:
                print("Failed to fetch the scan result.")
                return None, None, None, None, None, None, None, [], [], []

# Function to check the safety of embedded URLs
async def check_embedded_urls_safety(session, urls):
    url_safety_info = []
    for url in urls:
        url_safe = await check_url_safety(session, url)
        url_safety_info.append((url, "Malicious" if url_safe else "Clean"))
    return url_safety_info

# Function to display detailed engine results
def fetch_engine_results(engine_results):
    if engine_results:
        headers = [Fore.CYAN + "Engine Name" + Style.RESET_ALL, Fore.CYAN + "Detection Result" + Style.RESET_ALL]
        print(f"\n{Fore.YELLOW}Detailed Engine Results:{Style.RESET_ALL}")
        print(tabulate(engine_results, headers=headers, tablefmt="grid"))
    else:
        print("\nNo malicious detections by antivirus engines.")

# Function to display embedded URLs
def fetch_embedded_urls(urls):
    if urls:
        headers = [Fore.CYAN + "Embedded URL" + Style.RESET_ALL, Fore.CYAN + "Safety" + Style.RESET_ALL]
        url_info = [[url, Fore.RED + "Malicious" + Style.RESET_ALL if safety == "Malicious" else Fore.GREEN + "Clean" + Style.RESET_ALL] for url, safety in urls]
        print(f"\n{Fore.YELLOW}Embedded URLs:{Style.RESET_ALL}")
        print(tabulate(url_info, headers=headers, tablefmt="grid"))
    else:
        print("\nNo embedded URLs found.")

async def main():
    pdf_file_path = r"the pdf file path goes here"  # Specify the path to the PDF file
    print(f"Uploading {pdf_file_path} to VirusTotal...")
    resource_id = upload_file_to_virustotal(pdf_file_path)
    if resource_id:
        print(f"{Fore.GREEN}File uploaded to VirusTotal. Waiting for analysis to complete...{Style.RESET_ALL}")
        async with ClientSession() as session:
            file_name, file_size, scan_date, file_type, threat_categories, popular_threat_labels, scan_result, engine_results, embedded_urls, url_safety_info = await fetch_general_info(session, resource_id, pdf_file_path)
            if file_name is not None:
                # Display the General Information table
                general_info_table = [
                    [Fore.CYAN + "File Name" + Style.RESET_ALL, file_name],
                    [Fore.CYAN + "File Size (bytes)" + Style.RESET_ALL, file_size],
                    [Fore.CYAN + "Scan Date (Local Time)" + Style.RESET_ALL, scan_date],
                    
                    [Fore.CYAN + "Scan Result" + Style.RESET_ALL, scan_result],
                ]
                print(f"{Fore.YELLOW}General Information:{Style.RESET_ALL}")
                print(tabulate(general_info_table, tablefmt="grid"))

                # Display the Embedded URLs table
                fetch_embedded_urls(url_safety_info)

                # Display the Detailed Engine Results table
                fetch_engine_results(engine_results)
    else:
        print("Failed to upload the file to VirusTotal.")

if __name__ == "__main__":
    asyncio.run(main())