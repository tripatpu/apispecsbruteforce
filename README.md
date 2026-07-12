# Offline (no network) — just parse and clean
python api_verifier.py -f plusgradedalliv200urlswag -o clean.json

# With body re-probing for deeper SimHash analysis
python api_verifier.py -f plusgradedalliv200urlswag --reprobe -t 50 --rate 40 -o clean.json

# Keep FPs in output but tagged (for manual review)
python api_verifier.py -f plusgradedalliv200urlswag --include-fp -o full_audit.csv

# Tune thresholds for aggressive/conservative filtering
python api_verifier.py -f plusgradedalliv200urlswag --cl-pct 0.10 --cl-tol 5 -o strict.json



# Offline (no network) — just parse and clean
python api_verifier.py -f plusgradedalliv200urlswag -o clean.json

# With body re-probing for deeper SimHash analysis
python api_verifier.py -f plusgradedalliv200urlswag --reprobe -t 50 --rate 40 -o clean.json

# Keep FPs in output but tagged (for manual review)
python api_verifier.py -f plusgradedalliv200urlswag --include-fp -o full_audit.csv

# Tune thresholds for aggressive/conservative filtering
python api_verifier.py -f plusgradedalliv200urlswag --cl-pct 0.10 --cl-tol 5 -o strict.json
