"""vuln-hunter execution engine (minimal viable version).

Layers:
  gate      - loads vuln-hunter/scripts/check_scope.py as the single source of truth
  policy    - mode -> risk ceiling, target scope matching, acknowledgement enforcement
  adapters  - ToolAdapter implementations (http_probe / nuclei / bandit)
  runner    - Executor: state machine + retry/backoff + quarantine + journal
  planner   - plan builder per mode
  report    - markdown report rendering
  __main__  - CLI entry (python -m vuln_hunter run ...)
"""

__version__ = "0.2.0rc1"
