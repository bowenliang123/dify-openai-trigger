## OpenAI Trigger

**Author:** [bowenliang123](https://github.com/bowenliang123)

**Github Repository:** https://github.com/bowenliang123/dify-trigger-openai

**Dify Marketplace:** https://marketplace.dify.ai/plugins/bowenliang123/openai_trigger

### OpenAI Trigger Plugin User Guide

#### What This Plugin Does
The OpenAI Trigger plugin connects your Dify workflows with [OpenAI Webhook events](https://platform.openai.com/docs/api-reference/webhook-events). When something happens in your OpenAI workspace, like receiving an update for batch, evaluation , this trigger plugin automatically starts your Dify workflows to respond to these events.

### Get Started

#### Step 1: Create an OpenAI Webhook Trigger in Dify's workflow

![](_assets/img1.png)

#### Step 2: Create an subscription URL

![](_assets/img2.png)

#### Step 3: Copy the callback URL

![](_assets/img3.png)

#### Step 4: Create a Webhook endpoints in OpenAI platform settings

OpenAI platform settings: https://platform.openai.com/settings

1. fill the URL copied from Dify workflow
2. select subscription events

![](_assets/img4.png)

![](_assets/img5.png)

![](_assets/img6.png)

#### Step 5: Fill the Singing secret

1. Copy the OpenAI's Signing secret
2. Fill it in Dify's OpenAI Webhook trigger settings

![](_assets/img7.png)

![](_assets/img8.png)

#### Step 8: Setup Dify workflow

![](_assets/img9.png)

![](_assets/img10.png)



### Available Events

OpenAI's webhook events: https://platform.openai.com/docs/api-reference/webhook-events 

#### Response Events

- `response.completed`
    - Sent when a background response has been completed.
- `response.cancelled`
    - Sent when a background response has been cancelled.
- `response.failed`
    - Sent when a background response has failed.
- `response.incomplete`
    - Sent when a background response has been interrupted.

#### Batch Events

- `batch.completed`
    - Sent when a batch API request has been completed.
- `batch.cancelled`
    - Sent when a batch API request has been cancelled.
- `batch.expired`
    - Sent when a background response has failed.
- `batch.failed`
    - Sent when a batch API request has failed.

#### Finetuning Events

- `fine_tuning.job.succeeded`
    - Sent when a fine-tuning job has succeeded.
- `fine_tuning.job.failed`
    - Sent when a fine-tuning job has failed.
- `fine_tuning.job.cancelled`
    - Sent when a fine-tuning job has cancelled.
    
#### Eval Events
- `eval.run.succeeded`
    - Sent when an eval run has succeeded.
- `eval.run.failed`
    - Sent when an eval run has failed.
- `eval.run.canceled`
    - Sent when an eval run has been canceled.

#### Realtime Events
- `realtime.call.incoming`
    - Sent when Realtime API Receives a incoming SIP call.
