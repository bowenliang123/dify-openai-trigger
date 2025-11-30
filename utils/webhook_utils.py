from collections.abc import Mapping
from typing import Any

import standardwebhooks
from dify_plugin.entities.trigger import Variables
from dify_plugin.errors.trigger import TriggerProviderOAuthError
from werkzeug import Request


def verify_webhook_signature(parameters: Mapping[str, Any], request: Request):
    try:
        webhook_secret = parameters.get("webhook_secret")
        webhook = standardwebhooks.Webhook(webhook_secret)
        webhook.verify(request.data, request.headers)
    except standardwebhooks.WebhookVerificationError:
        raise TriggerProviderOAuthError("Invalid webhook signature or secret.")


def transform_webhook(parameters: Mapping[str, Any], request: Request) -> Variables:
    payload = request.get_json(silent=True) or {}

    # Verify webhook signature
    verify_webhook_signature(parameters, request)

    return Variables(variables={**payload})
