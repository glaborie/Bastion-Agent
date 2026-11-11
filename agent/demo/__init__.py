"""Allow-listed demo scenarios for the Command Control dashboard (ADR-007).

The registry in :mod:`agent.demo.scenarios` is the only thing a run request can
name: a scenario id, never a command, a script path or argv. The worker owns
execution and writes each run's result into Redis, so a slow model scenario
cannot hold the gateway request.
"""
