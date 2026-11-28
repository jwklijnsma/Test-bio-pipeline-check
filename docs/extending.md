# Extending

Add a new check by adding a method to `AnsibleChecker`, `HelmChecker`, or
`OpenShiftChecker` in `bio_pipeline_check.py`, returning `Finding` objects, then
add matching test cases (good + bad fixtures) to `test_bio_pipeline_check.py`.
