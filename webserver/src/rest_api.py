from fastapi import FastAPI
from typing import Any, MutableMapping, Dict
from util import load_config
import datetime
tags_metadata = [
    {
        "name": "Example Web Server",
        "description": "An Example Web Server.",
    },
]


app = FastAPI(
    title="Example Web Server",
    description="An Example Web Server",
    openapi_tags=tags_metadata,
)

config: MutableMapping[str, Any] = {}
web_address: str = ""


@app.on_event("startup")
def startup():
    """When the application starts read the config
    configure bsv_client
    """
    global config, web_address

    config = load_config("web.toml")
    web_address = config["web_interface"]["address"]


@app.get("/", tags=["Web"])
def root() -> Dict[str, str]:
    """Web server Root"""
    return {
        "name": "Example Web Server",
        "description": "An Example Web Server",
    }

@app.get("/now", tags=["Web"])
def get_current_time() -> Dict[str, str]:
    """ Return the current time """
    return {
        "time": str(datetime.datetime.now()),
    }


