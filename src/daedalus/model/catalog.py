# ruff: noqa: RUF001
"""The console's packaged, public provider presets; never includes credentials."""

import json
from importlib.resources import files


def catalog():
    return json.loads(files("daedalus.service").joinpath("static/model-providers.json").read_text())


def preset(identity):
    for item in catalog()["providers"]:
        if item["id"] == identity:
            return item
    raise ValueError("未知的模型服务商，请选择自定义接口")
