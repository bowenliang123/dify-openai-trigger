import logging
from collections.abc import Mapping
from typing import Any

import standardwebhooks
from dify_plugin.entities.trigger import Variables
from dify_plugin.errors.trigger import TriggerProviderOAuthError, EventIgnoreError
from werkzeug import Request


def verify_webhook_signature(
        webhook_secret: str,
        data: str | bytes,
        headers: dict[str, Any],
) -> None:
    try:
        webhook = standardwebhooks.Webhook(webhook_secret)
        webhook.verify(data, headers)
    except standardwebhooks.WebhookVerificationError as e:
        logging.exception(e)
        raise TriggerProviderOAuthError(f"Invalid webhook signature or secret, {str(e)}")


def transform_webhook(event_type: str,
                      request: Request,
                      parameters: Mapping[str, Any],
                      payload: Mapping[str, Any],
                      ) -> Variables:
    payload = request.get_json(silent=True) or {}
    if not payload:
        raise ValueError("No payload received")

    actual_event_type = payload.get("type")
    if event_type != actual_event_type:
        raise EventIgnoreError(f"Expecting event type '{event_type}', got '{actual_event_type}' in payload.")

    # Verify webhook signature
    webhook_secret = parameters.get("webhook_secret", "")
    # verify_webhook_signature(webhook_secret, request.data, request.headers)

    return Variables(variables={**payload})
