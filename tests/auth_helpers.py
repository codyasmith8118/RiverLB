"""Authenticate existing socket fixtures; no production authentication bypass."""
import http.cookiejar
import json
import subprocess
import urllib.error
import urllib.request

PASSWORD = "fixture-password-only-123"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def authenticated_urlopen(request, *args, **kwargs):
    try:
        return opener.open(request, *args, **kwargs)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        error.close()
        url = request.full_url if isinstance(request, urllib.request.Request) else request
        origin = url.split("/", 3)[:3]
        login = urllib.request.Request("/".join(origin) + "/api/v1/auth/login",
            data=json.dumps({"username": "admin", "password": PASSWORD}).encode(),
            headers={"Content-Type": "application/json", "X-RiverLB-Request": "configure"})
        with opener.open(login, timeout=5):
            pass
        return opener.open(request, *args, **kwargs)


def bootstrap(binary, config):
    subprocess.run([binary, "admin", "--database", config.with_suffix(".db")],
        input=(PASSWORD + "\n").encode(), check=True, capture_output=True)


def session_token():
    return next(cookie.value for cookie in jar if cookie.name == "riverlb_session")


urllib.request.urlopen = authenticated_urlopen
