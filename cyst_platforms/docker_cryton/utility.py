import requests


def get_request(api_url: str, *, json: dict = None) -> requests.Response:
    try:
        return requests.get(api_url, json=json)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Unable to connect to {api_url}")
    except requests.exceptions.HTTPError:
        raise RuntimeError
    except requests.exceptions.Timeout:
        raise RuntimeError(f"{api_url} request timed out")


def post_request(api_url: str, *, data: dict = None, files: dict = None, json: dict = None) -> requests.Response:
    try:
        return requests.post(api_url, json=json, data=data, files=files)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Unable to connect to {api_url}")
    except requests.exceptions.HTTPError:
        raise RuntimeError
    except requests.exceptions.Timeout:
        raise RuntimeError(f"{api_url} request timed out")
