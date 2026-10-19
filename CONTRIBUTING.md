# Contributing

Open an issue describing the change before large refactors. Keep security checks deterministic and explain their enforcement boundary. Add regression coverage for policy decisions and verify that blocked calls never reach the protected function. Do not commit credentials, private data, generated traffic, or untrusted model files. Run `python -m pytest -q` before submitting and report failures accurately.
