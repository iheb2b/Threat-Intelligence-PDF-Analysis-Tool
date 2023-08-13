# Threat-Intelligence-PDF-Analysis-Tool
PDF Analysis Tool with VirusTotal Integration
This Python script allows you to analyze a PDF file, extract embedded URLs, and check the safety of these URLs using the VirusTotal API. It displays detailed information about the PDF file, including its general properties, the safety of embedded URLs, and the results from various antivirus engines.

Installation
Python: Ensure you have Python installed on your system. You can download Python from the official website: Python Downloads.

Required Modules: This script requires several Python modules. You can install them using pip, which is a package installer for Python.

Open your terminal or command prompt and execute the following command to install the required modules:

shell
Copy code
pip install requests aiohttp PyMuPDF colorama tabulate
These modules are used for making HTTP requests, handling asynchronous operations, PDF analysis, terminal output styling, and tabulating data.

VirusTotal API Key: You need to replace the API_KEY variable in the script with your own VirusTotal API key. You can obtain an API key by signing up for a free account on the VirusTotal website: VirusTotal API.

Usage
Specify PDF File: In the script, replace the value of the pdf_file_path variable with the path to the PDF file you want to analyze.

python
Copy code
pdf_file_path = r"C:\path\to\your\pdf\file.pdf"
Run the Script: Open your terminal or command prompt, navigate to the directory containing the script, and execute the script:

shell
Copy code
python script_name.py
The script will upload the specified PDF file to VirusTotal for analysis, fetch and display general information, safety of embedded URLs, and detailed engine results.

View Results: The script will display detailed information about the PDF file and provide insights into the safety of embedded URLs. The script outputs a summary of the analysis, general information about the PDF, the safety of embedded URLs, and the results from antivirus engines.

Note
File Size Limitation: The script uses the VirusTotal API to analyze the file. Keep in mind that there might be limitations on the file size that can be analyzed using the free VirusTotal API. If you encounter issues with large files, consider the limitations of your VirusTotal API subscription.

Rate Limits: The script is designed to handle rate limits set by VirusTotal, and it includes retry logic if necessary.

Security: Make sure to keep your VirusTotal API key secure and do not share it publicly.

That's it! You can now use this script to analyze PDF files and check the safety of embedded URLs using the VirusTotal API. If you encounter any issues or have questions, feel free to reach out.
