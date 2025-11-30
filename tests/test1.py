import standardwebhooks


def test():
    data = '{"id": "evt_692c4a451d948190b86fa3a26e8e1162", "object": "event", "created_at": 1764510277, "type": "batch.completed", "data": {"id": "batch_abc123"}}'

    headers = {
        "user-agent": "OpenAI/1.0 (+https://platform.openai.com/docs/webhooks)",
        "content-length": "150",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "content-type": "application/json",
        "webhook-id": "wh_692c4a451d908190b3d413305f9921ff",
        "webhook-signature": "v1,03iQp2TC8hbqpw3rL/LmQ0tugX+Q9llaW3RqWMd3nok=",
        "webhook-timestamp": "1764510277",
        "x-forwarded-for": "13.65.138.124",
        "x-forwarded-host": "wh2f4a2551c4fb8844de.free.beeceptor.com",
        "x-forwarded-proto": "https"
    }

    webhook_secret = "whsec_gHTP6EurDXkCi248pZ7y3efkjTIELv7FUT0wSYapZN8="
    webhook = standardwebhooks.Webhook(webhook_secret)
    webhook.verify(str(data).encode(), headers)


if __name__ == '__main__':
    test()
