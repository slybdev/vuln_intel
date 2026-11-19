import atexit
import os
import tempfile


_test_data = tempfile.TemporaryDirectory(prefix="vuln-intel-tests-")
atexit.register(_test_data.cleanup)
os.environ.setdefault("VULN_DATABASE_URL", "")
os.environ.setdefault("VULN_DATA_DIR", _test_data.name)