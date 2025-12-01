import time
from collections.abc import Mapping
from typing import Any

from werkzeug import Request, Response

from dify_plugin.entities.oauth import TriggerOAuthCredentials
from dify_plugin.entities.provider_config import CredentialType
from dify_plugin.entities.trigger import EventDispatch, Subscription, UnsubscribeResult
from dify_plugin.errors.trigger import (
    SubscriptionError,
    TriggerDispatchError,
    TriggerProviderCredentialValidationError,
    TriggerProviderOAuthError,
    UnsubscribeError,
)
from dify_plugin.interfaces.trigger import Trigger, TriggerSubscriptionConstructor

from utils.webhook_utils import verify_webhook_signature


class OpenaiTriggerTrigger(Trigger):
    """
    Handle the webhook event dispatch.
    """
    def _dispatch_event(self, subscription: Subscription, request: Request) -> EventDispatch:
        try:
            webhook_secret = subscription.properties.get("webhook_secret")
            if not webhook_secret:
                raise TriggerDispatchError("Webhook secret is required to validate request.")

            # very webhook signature with standardwebhooks sdk
            verify_webhook_signature(webhook_secret, request.data, request.headers)

            payload: Mapping[str, Any] = self._validate_payload(request)
            response = Response(response='{"status": "ok"}', status=200, mimetype="application/json")
            events: list[str] = self._dispatch_trigger_events(payload=payload)
            # print("events", events)

            return EventDispatch(events=events, response=response)
        except Exception as exc:
            print("exc", exc)
            raise exec

    def _dispatch_trigger_events(self, payload: Mapping[str, Any]) -> list[str]:
        """Dispatch events based on webhook payload."""
        events = []

        # Get the event type from the payload
        event_type = payload.get("type", "")

        if event_type:
            event_type = event_type.replace(".", "_")
            events.append(event_type)

        return events

    def _validate_payload(self, request: Request) -> Mapping[str, Any]:
        try:
            payload = request.get_json(force=True)
            if not payload:
                raise TriggerDispatchError("Empty request body")
            return payload
        except TriggerDispatchError:
            raise
        except Exception as exc:
            raise TriggerDispatchError(f"Failed to parse payload: {exc}") from exc
        
class OpenaiTriggerSubscriptionConstructor(TriggerSubscriptionConstructor):
    """Manage openai_trigger trigger subscriptions."""

    def _validate_api_key(self, credentials: dict[str, Any]) -> None:
        # api_key = credentials.get("api_key")
        # if not api_key:
        #     raise TriggerProviderCredentialValidationError("API key is required to validate credentials.")
        pass

    def _create_subscription(
        self,
        endpoint: str,
        parameters: Mapping[str, Any],
        credentials: Mapping[str, Any],
        credential_type: CredentialType,
    ) -> Subscription:
        
        events: list[str] = parameters.get("events", [])

        # Replace this placeholder with API calls to register a webhook
        return Subscription(
            expires_at=int(time.time()) + 7 * 24 * 60 * 60,
            endpoint=endpoint,
            properties={
                "external_id": "example-subscription",
                "events": events,
            },
        )

    def _delete_subscription(
        self,
        subscription: Subscription,
        credentials: Mapping[str, Any],
        credential_type: CredentialType,
    ) -> UnsubscribeResult:
        # Tear down any remote subscription that was created in `_subscribe`.
        return UnsubscribeResult(success=True, message="Subscription removed.")

    def _refresh_subscription(
        self,
        subscription: Subscription,
        credentials: Mapping[str, Any],
        credential_type: CredentialType,
    ) -> Subscription:
        # Extend the subscription lifetime or renew tokens with your upstream service.
        return Subscription(
            expires_at=int(time.time()) + 7 * 24 * 60 * 60,
            endpoint=subscription.endpoint,
            properties=subscription.properties,
        )
