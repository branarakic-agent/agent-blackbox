"""The shipped Tomcat image must receive and retain Blackbox's JVM sizing."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest


@pytest.mark.parametrize("helper", ["scripts", "plugins/blackbox/setup"])
def test_effective_tomcat_heap_is_reused_without_replacing_store(tmp_path, helper):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    module = tmp_path / "node_modules/@origintrail-official/dkg/dist/daemon/blazegraph-docker.js"
    module.parent.mkdir(parents=True)
    (module.parents[2] / "package.json").write_text('{"type":"module"}')
    module.write_text(
        "export async function provisionBlazegraphDocker(options) {\n"
        " const existing = await options.docker.run(['inspect', 'dkg-blazegraph-test']);\n"
        " if (existing.exitCode !== 0) throw Error('configured store was replaced');\n"
        " return {url: 'http://127.0.0.1:10001/sparql', reused: true};\n"
        "}\n"
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls.log"
    inspect = json.dumps([{"Config": {"Env": ["JAVA_OPTS=-Xmx1g", "TOMCAT_JAVA_OPTS=-Xms512m -Xmx4g"]}}])
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(calls))}\n"
        "case \"$1\" in\n"
        f" inspect) printf '%s\\n' {shlex.quote(inspect)} ;;\n"
        " info) echo 4 ;;\n"
        " update) exit 0 ;;\n"
        " *) exit 2 ;;\n"
        "esac\n"
    )
    docker.chmod(0o755)
    source = Path(__file__).resolve().parents[3] / helper / "blackbox-blazegraph.mjs"
    result = subprocess.run(
        [node, str(source), str(tmp_path), "blackbox-test", "10001"],
        env={**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")},
        capture_output=True, text=True, check=True,
    )
    assert json.loads(result.stdout)["reused"] is True
    assert calls.read_text().splitlines() == [
        "inspect dkg-blazegraph-test", "info --format {{.NCPU}}",
        "update --cpus 4 dkg-blazegraph-test",
    ]
