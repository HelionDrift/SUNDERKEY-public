# Offline PE Permission Common Task

The existing GB-D08 PE layout specialist and the GE-D21 AMD64 section-policy
specialist can share a synthetic task while keeping separate original
requests, domain commanders, and independent validation. The
[common-task test](../tests/agents/test_offline_pe_permission_common_task_integration.py)
replays the task and rejects a late network grant or nonsynthetic source
before dispatch.

The two reports are partial, unsigned A7.4 evidence. They do not authenticate
the PE bytes, load the image, establish runtime permissions, prove a
vulnerability, or qualify either agent. No target or network is contacted.
