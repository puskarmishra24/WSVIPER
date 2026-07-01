import pickle
from termcolor import colored
import code_files.report_generator as report_generator
import json
from pprint import pprint

# with open('report1.dat','rb') as f:
#     s = pickle.load(f)



# def flatten_vulns(vuln_list):
#     flat = []
#     for item in vuln_list:
#         if isinstance(item, list):
#             flat.extend(flatten_vulns(item))  # recurse
#         else:
#             flat.append(item)
#     return flat

# print(colored("\n[*] Generating PDF report...", "yellow"))
# try:
#     report_file = report_generator.generate_pdf_report(s)
#     print(colored(f"[+] Report saved: {report_file}", "green"))
# except Exception as e:
#     print(colored(f"[-] Error generating report: {e}", "red"))



with open('report1.dat','rb') as f:
    s = pickle.load(f)
    with open('report1.txt', 'w') as txt_file:
        json.dump(s, txt_file, indent=4)


