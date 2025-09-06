# ----------------- checkers.py -----------------
import aiohttp
import validators

STATUS_CLEAN = "clean"
STATUS_SUSPICIOUS = "suspicious"
STATUS_PHISH = "phish"
STATUS_UNKNOWN = "unknown"

async def check_urlhaus(session: aiohttp.ClientSession, url: str):
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        async with session.post(api_url, data={"url": url}) as resp:
            if resp.status != 200:
                return STATUS_UNKNOWN, "URLhaus", {}
            r = await resp.json()

            if r.get("query_status") == "ok":
                if r.get("url_status") == "online":
                    return STATUS_PHISH, "URLhaus", r
                elif r.get("url_status") == "offline":
                    return STATUS_SUSPICIOUS, "URLhaus", r
            elif r.get("query_status") == "no_results":
                return STATUS_CLEAN, "URLhaus", r

            return STATUS_UNKNOWN, "URLhaus", r
    except Exception as e:
        return STATUS_UNKNOWN, "URLhaus", {"error": str(e)}

async def aggregate_checks(url: str):
    """
    Wrapper que valida la URL y la consulta solo con URLhaus.
    """
    if not validators.url(url):
        return (STATUS_UNKNOWN, "invalid", {"reason": "invalid_url"})

    async with aiohttp.ClientSession() as session:
        return await check_urlhaus(session, url)
