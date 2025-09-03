import requests
from bs4 import BeautifulSoup
from typing import Iterable, Optional, Tuple
import time

API_DEV_KEY = "TU_API_KEY_AQUI"  # Reemplaza con tu Developer Key
KEYWORDS = ["paraguay", "py", "cedula", "ruc"]

def contains_keywords(text: str, keywords):
    t = text.lower()
    return any(k.lower() in t for k in keywords)

class PastebinAPI:
    name = "pastebin_api"
    BASE_URL = "https://pastebin.com/api/api_post.php"
    
    def __init__(self, api_dev_key: str):
        self.api_dev_key = api_dev_key

    def fetch_recent_public_pastes(self) -> Iterable[Tuple[Optional[str], str]]:
        """
        Devuelve tuplas (url, contenido) de los últimos pastes públicos.
        """
        # El endpoint para pastes públicos recientes
        url = "https://pastebin.com/api/api_post.php"
        data = {
            "api_dev_key": self.api_dev_key,
            "api_option": "list",
            "api_results_limit": 10  # últimos 10 pastes
        }
        try:
            resp = requests.post(url, data=data, timeout=10)
            if resp.status_code != 200:
                print("[!] Error al obtener lista de pastes:", resp.status_code)
                return

            # Pastebin devuelve XML
            soup = BeautifulSoup(resp.text, "lxml")
            for paste in soup.find_all("paste"):
                paste_url = paste.paste_url.text
                paste_content_resp = requests.get(paste_url, timeout=10)
                if paste_content_resp.status_code != 200:
                    continue
                content = paste_content_resp.text
                if contains_keywords(content, KEYWORDS):
                    snippet = " ".join(content.split())[:500]
                    yield (paste_url, snippet)
                time.sleep(1)  # rate limit
        except Exception as e:
            print("[!] Error en API Pastebin:", e)

# ======================
# Prueba rápida
# ======================

if __name__ == "__main__":
    scraper = PastebinAPI(API_DEV_KEY)
    for url, snippet in scraper.fetch_recent_public_pastes():
        print("[+]", url)
        print(snippet)
        print("-"*40)
