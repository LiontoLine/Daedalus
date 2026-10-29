# ruff: noqa: RUF001
"""Verified HTTPS trust for model transports, including Python.org macOS installs."""

from __future__ import annotations

import os
import ssl
from pathlib import Path

from daedalus.errors import DaedalusError, ModelError


class ModelTLSConfigurationError(ModelError):
    code = "model_tls_configuration_error"


class ModelTLSVerificationError(ModelError):
    code = "model_tls_verification_failed"


def _certificate_file(name: str) -> str | None:
    value = os.environ.get(name)
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_file():
        raise ModelTLSConfigurationError(f"{name} 指定的 CA 文件不存在或不可读取，请核对证书配置")
    return str(path)


def create_tls_context() -> ssl.SSLContext:
    """Keep hostname and chain verification; never retry with verification disabled.

    Explicit OpenSSL trust configuration is authoritative. If there are no system
    roots and no explicit OpenSSL override, use certifi's Mozilla CA data bundle.
    DAEDALUS_CA_BUNDLE adds an operator-selected CA, e.g. an enterprise HTTPS proxy.
    """
    cafile = _certificate_file("SSL_CERT_FILE")
    capath = os.environ.get("SSL_CERT_DIR") or None
    if capath:
        capath = str(Path(capath).expanduser())
        if not Path(capath).is_dir():
            raise ModelTLSConfigurationError("SSL_CERT_DIR 指定的 CA 目录不存在，请核对证书配置")
    additional = _certificate_file("DAEDALUS_CA_BUNDLE")
    try:
        context = ssl.create_default_context(cafile=cafile, capath=capath)
        if not cafile and not capath and context.cert_store_stats()["x509_ca"] == 0:
            try:
                import certifi
            except ImportError:
                raise ModelTLSConfigurationError(
                    "当前 Python 没有可信 CA，且缺少 certifi 证书包；请补齐项目依赖或配置可信 CA"
                ) from None
            context.load_verify_locations(cafile=certifi.where())
        if additional:
            context.load_verify_locations(cafile=additional)
    except (OSError, ValueError):
        raise ModelTLSConfigurationError(
            "无法加载 CA 证书，请提供有效的 PEM 证书文件或正确配置 SSL_CERT_FILE / SSL_CERT_DIR"
        ) from None
    if context.cert_store_stats()["x509_ca"] == 0 and not capath:
        raise ModelTLSConfigurationError("当前证书配置没有可用的可信 CA，请检查证书包")
    return context


def verification_failure() -> ModelTLSVerificationError:
    return ModelTLSVerificationError(
        "HTTPS 证书链校验失败，当前服务不信任这条证书链。请检查 CA 配置、系统时间及 HTTPS 代理；"
        "企业代理根证书可通过 DAEDALUS_CA_BUNDLE 指定"
    )


def connection_hint(error: DaedalusError, *, discovery=False) -> str:
    if isinstance(error, ModelTLSConfigurationError):
        return "请修复服务使用的 CA 证书配置后重启，再测试连接。"
    if isinstance(error, ModelTLSVerificationError):
        return (
            "证书验证发生在 HTTP 请求之前；手填模型 ID 不能解决此错误。"
            "请使用可信 CA，或检查是否有 HTTPS 代理替换证书。"
        )
    status = error.context.get("status")
    if status in {401, 403}:
        return "请检查该服务商的 API Key、账户权限及所属区域。"
    if discovery and status in {404, 405}:
        return "这个地址可能不提供模型列表，请核对 API 根地址，或手动填写控制台中的模型 ID。"
    if status == 429:
        return "接口限流或账户额度受限，请检查额度并稍后重试。"
    if error.code in {"model_unavailable", "model_timeout"}:
        return "请检查网络、代理和服务地址后重试。"
    return "请核对 API 根地址、请求协议、模型 ID 与凭证配置。"
