from collections.abc import Mapping
from typing import Any

from dify_plugin.entities.trigger import Variables
from dify_plugin.interfaces.trigger import Event
from werkzeug import Request

from utils.webhook_utils import transform_webhook


class OpenaiBatchCancelledEvent(Event):
    """
    OpenAI batch.cancelled webhook payload

    Doc:
    https://platform.openai.com/docs/api-reference/webhook-events/batch/cancelled
    """

    def _on_event(self, request: Request, parameters: Mapping[str, Any], payload: Mapping[str, Any]) -> Variables:
        return transform_webhook(request, parameters, payload)
