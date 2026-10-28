import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import connect, make_client  # noqa: E402,F401


def report(**kw):
    print(json.dumps(kw))
