import os
import requests
import time
import traceback
import datetime
import json
from openai import AzureOpenAI
import urllib3
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration variables
AZURE_OPENAI_KEY = os.getenv('AZURE_OPENAI_KEY')
DEFECTDOJO_API_KEY = os.getenv('DEFECTDOJO_API_KEY')
DEFECTDOJO_URL = os.getenv('DEFECTDOJO_URL')
POLLING_INTERVAL = int(os.getenv('POLLING_INTERVAL', 60))

# Initialize the Azure OpenAI client with your API key
client = AzureOpenAI(
    azure_endpoint = "https://openai-suseg-2.openai.azure.com/", 
    api_key=AZURE_OPENAI_KEY,  
    api_version="2024-02-15-preview"
)

# Suppress warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_latest_findings(url, headers):
    """Fetch all findings from the provided URL with given headers, handling pagination."""
    all_findings = []
    while url:
        try:
            response = requests.get(url, headers=headers, timeout=1, verify=False)
            response.raise_for_status()  # Raises HTTPError for bad status codes
            data = response.json()
            all_findings.extend(data['results'])
            url = data.get('next', None)  # Update the URL for the next page
            

            # Optionally, save each page's findings to a JSON file
           # with open("latest_findings.json", "w") as file:
             
             #json.dump(all_findings, file, indent=4)

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            break  # Exit the loop in case of a request failure
    return all_findings

def get_mitigation(description, severity=None, cvss_score=None, cwe_id=None, impact=None, steps_to_reproduce=None, references=None, line=None, file_path=None):
    """Generate mitigation advice using Azure OpenAI based on the description."""
    try:
        # Extremamente explicado:
        # custom_message_text = [
        #     {"role": "system", "content": "Você é um sistema avançado de análise e mitigação de vulnerabilidades, especializado em identificar e sugerir correções para vulnerabilidades em códigos de software. Seu objetivo é oferecer soluções seguras, eficientes e baseadas nas melhores práticas de segurança da informação."},
        #     {"role": "user", "content": f"Analisar a seguinte vulnerabilidade: {description}. Forneça uma descrição detalhada da vulnerabilidade, incluindo seu impacto e contexto. Em seguida, descreva uma estratégia de mitigação usando tecnologias e práticas recomendadas para a correção efetiva da vulnerabilidade."},
        #     {"role": "system", "content": "Com base na análise, sugerir uma solução técnica detalhada, que pode incluir código ou pseudocódigo, configurações recomendadas ou diretrizes de implementação."}
        # ]

        custom_message_text = [
            {"role": "system", "content": "Você é um sistema avançado de análise e mitigação de vulnerabilidades, especializado em identificar e sugerir correções para vulnerabilidades em códigos de software. Seu objetivo é oferecer soluções seguras, eficientes e baseadas nas melhores práticas de segurança da informação."},
            {"role": "user", "content": f"Analisar a seguinte vulnerabilidade: {description}. Forneça uma descrição detalhada da vulnerabilidade, incluindo seu impacto e contexto. Em seguida, descreva uma estratégia de mitigação usando tecnologias e práticas recomendadas para a correção efetiva da vulnerabilidade."},
            {"role": "system", "content": "Com base na análise, sugerir uma solução técnica detalhada, que pode incluir código ou pseudocódigo, configurações recomendadas ou diretrizes de implementação."}
        ]

        user_message = {"role": "user", "content": f"Severity: {severity}\nCVSS Score: {cvss_score}\nCWE ID: {cwe_id}\nImpact: {impact}\nSteps to Reproduce: {steps_to_reproduce}\nReferences: {references}\nLine: {line}\nFile Path: {file_path}"}
        custom_message_text.insert(1, user_message)

        chat_completion = client.chat.completions.create(
            model="Suseg_OpenAI",
            messages=custom_message_text,
            temperature=0.7,
            max_tokens=800,
            top_p=0.95,
            frequency_penalty=0,
            presence_penalty=0,
            stop=None
        )

        # Extracting tokens and mitigation advice
        sent_token_count = chat_completion.usage.prompt_tokens
        received_token_count = chat_completion.usage.completion_tokens

        if hasattr(chat_completion.choices[0], 'message'):
            mitigation = chat_completion.choices[0].message.content
        else:
            mitigation = "Nenhuma resposta de mitigação foi encontrada."
        return mitigation, sent_token_count, received_token_count
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        return None, 0, 0

def post_mitigation_to_defectdojo(finding_id, mitigation, url, headers):
    """Post mitigation details to DefectDojo for a specific finding, with retries and timeout."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.patch(f"{url}{finding_id}/", headers=headers, json={"mitigated": False, "mitigation": mitigation}, verify=False, timeout=5)
            response.raise_for_status()
            return response.status_code
        except requests.exceptions.RequestException as e:
            print(f"Patch request failed (Attempt {attempt + 1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(0.5)  # Wait for 2 seconds before retrying

def read_log():
    """Read and return the log data from 'log.json'."""
    processed_findings = []
    total_sent_tokens = 0
    total_received_tokens = 0
    try:
        if os.path.exists("log.json") and os.path.getsize("log.json") > 0:
            with open("log.json", "r") as file:
                data = json.load(file)
                processed_findings = [entry['finding_id'] for entry in data.get("entries", [])]
                total_sent_tokens = data.get("total_sent_tokens", 0)
                total_received_tokens = data.get("total_received_tokens", 0)
    except Exception as e:
        print(f"Error reading log file: {e}")
    return processed_findings, total_sent_tokens, total_received_tokens

def write_to_log(finding, mitigation, status, sent_token_count, received_token_count):
    """Write log data to 'log.json'."""
    sent_token_cost_per_million = 0.50
    received_token_cost_per_million = 1.50

    new_log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "finding_id": finding['id'],
        "description": finding['description'],
        "mitigation": mitigation,
        "status": status,
        "sent_token_count": sent_token_count,
        "received_token_count": received_token_count
    }

    try:
        data = {"entries": []}
        if os.path.exists("log.json") and os.path.getsize("log.json") > 0:
            with open("log.json", "r") as file:
                data = json.load(file)

        entries = data.get("entries", [])
        entries.append(new_log_entry)

        total_sent_tokens = sum(entry['sent_token_count'] for entry in entries)
        total_received_tokens = sum(entry['received_token_count'] for entry in entries)

        total_cost_sent = (total_sent_tokens / 1_000_000) * sent_token_cost_per_million
        total_cost_received = (total_received_tokens / 1_000_000) * received_token_cost_per_million

        data.update({
            "total_findings": len(entries),
            "total_sent_tokens": total_sent_tokens,
            "total_received_tokens": total_received_tokens,
            "pricing": {
                "total_cost_sent": total_cost_sent,
                "total_cost_received": total_cost_received,
                "total_cost": total_cost_sent + total_cost_received
            },
            "entries": entries
        })

        with open("log.json", "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"An error occurred while writing to log: {e}")

def main():
    headers = {
        'content-type': 'application/json',
        'Authorization': f'Token {DEFECTDOJO_API_KEY}'
    }

    while True:
        processed_ids, total_sent_tokens, total_received_tokens = read_log()
        print(f"Total Sent Tokens: {total_sent_tokens}, Total Received Tokens: {total_received_tokens}")

        # get_latest_findings now returns a list directly
        findings = get_latest_findings(DEFECTDOJO_URL, headers)

        # No need to access 'results' key since findings is already a list
        sorted_findings = sorted(findings, key=lambda f: f['id'])

        for finding in sorted_findings:
            if finding['id'] not in processed_ids:
                print(f"New finding found: {finding['id']}")

                mitigation, sent_tokens, received_tokens = get_mitigation(
                    finding['description'],
                    severity=finding['severity'],
                    cvss_score=finding['cvssv3_score'],
                    cwe_id=finding['cwe'],
                    impact=finding['impact'],
                    steps_to_reproduce=finding['steps_to_reproduce'],
                    references=finding['references'],
                    line=finding['line'],
                    file_path=finding['file_path']
                )
                if mitigation:
                    status_code = post_mitigation_to_defectdojo(finding['id'], mitigation, DEFECTDOJO_URL, headers)
                    print(f"Mitigation status for finding {finding['id']}: {status_code}")
                    write_to_log(finding, mitigation, "Success" if status_code == 200 else "Failed", sent_tokens, received_tokens)

        time.sleep(POLLING_INTERVAL)

if __name__ == '__main__':
    main()