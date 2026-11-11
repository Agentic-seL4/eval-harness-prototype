"""Export the pinned source into a small, credential-free Docker build context."""

from pathlib import Path
import shutil
import subprocess
import tarfile
import io

experiment = Path(__file__).resolve().parent
repository = experiment.parents[2] / "agentdojo"
revision = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
context = experiment / ".build-context"
context.mkdir(exist_ok=True)
source = context / "agentdojo"
source.mkdir(exist_ok=True)
archive = subprocess.check_output([
    "git", "-C", str(repository), "archive", revision,
    "pyproject.toml", "uv.lock", "README.md", "src", "tests",
])
with tarfile.open(fileobj=io.BytesIO(archive)) as contents:
    contents.extractall(source, filter="data")
shutil.copyfile(experiment / "Dockerfile", context / "Dockerfile")
print(f"Prepared {len(archive):,} bytes of source at {revision}")
