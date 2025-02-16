# DLL Gazer
DLL Gazer is a Python-based security tool designed to detect and analyze DLL files on a Windows system.
![BGG](https://github.com/user-attachments/assets/260d3ce8-b245-4d80-8364-c3ee7e08bfea)
## Features
-Scans all DLL files in key system directories.<br>
-Identifies DLLs currently loaded by active processes.<br>
-Generates MD5 and SHA-256 hashes for DLL files and allows saving results in log or CSV format.<br>
## Getting Started
These instructions will guide you on how to use DLL Gazer.
## Using DLL Gazer
The instructions are straightforward. In a text editor (such as Microsoft VS Code), run dll_gazer.py and choose the scan type you prefer.<br>
![image](https://github.com/user-attachments/assets/1717ec29-0fb9-4502-8cc1-4a8bc3915908)
## VirusTotal Integration
![X](https://github.com/user-attachments/assets/aa231a7a-d06e-4f4b-bad5-3e8bc9f3491d)
### Steps
First, make sure to input your own API key<br>
![image](https://github.com/user-attachments/assets/9b3f62f7-2518-4229-8353-99270f6e7912)
Then run "Check DLLs on VirusTotal"<br>
![image](https://github.com/user-attachments/assets/6b14fc39-f335-49ad-adbf-4ca1c49e3d10)
You will then see the DLL files being scanned, and they will be marked as either Clean or Malicious.
![image](https://github.com/user-attachments/assets/da159f4f-49ce-4258-9230-4dd351042ae4)
## Real-life Scenario
After detecting a malicious DLL, save the list in either CSV or log format. Then, find the hash of the DLL file and search for it on VirusTotal to get more details.
![Malicious](https://github.com/user-attachments/assets/078564f3-c582-42ae-a0f4-5c6cf797df5f)
![CVS](https://github.com/user-attachments/assets/0de8432f-8d30-480f-8344-5d304bdc70a5)
![VirusTotal](https://github.com/user-attachments/assets/555c7405-794a-476b-8800-ea155724c4de)
