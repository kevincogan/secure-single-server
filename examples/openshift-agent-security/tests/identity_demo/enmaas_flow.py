# SPDX-License-Identifier: Apache-2.0
"""Browser qualification adapter for the production model execution flow."""
from model_execution import ModelExecutionFlow, private_inference, profile
from service_request_flow import ServiceRequestFlow


class EnmaasFlow(ModelExecutionFlow, ServiceRequestFlow):
    """Keep browser automation outside the deployed execution dependency graph."""
