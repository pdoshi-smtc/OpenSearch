import os
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

load_dotenv()

email = os.getenv("JIRA_USER_EMAIL_TICKET")
api_token = os.getenv("JIRA_API_TOKEN_TICKET")
base_url = os.getenv("JIRA_BASE_URL_TICKET")

def create_jsm_ticket(summary, description):
    url = f"{base_url}/rest/api/3/issue"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "fields": {
            "project": {"key": "GNOC"},
            "summary": summary,
            "issuetype": {"name": "Incident"},
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": description}
                        ]
                    }
                ]
            }
        }
    }

    response = requests.post(
        url,
        headers=headers,
        auth=HTTPBasicAuth(email, api_token),
        json=payload
    )

    return response.status_code, response.text