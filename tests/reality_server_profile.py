"""Generate independent credentials and exercise Reality server profile loading."""
from test_paths import optional_fixture
import argparse
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile', type=pathlib.Path,
                    default=optional_fixture('reality-server-profile-test'), required=optional_fixture('reality-server-profile-test') is None)
parser.add_argument('--credential', type=pathlib.Path,
                    help='also exercise the Reality credential fixture')
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='nexus-reality-profile-') as directory:
    path = pathlib.Path(directory)
    def run(*args): subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for name in ('key', 'other'):
        run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(path/f'{name}.pem'))
        run('openssl', 'pkey', '-in', str(path/f'{name}.pem'), '-outform', 'DER', '-out', str(path/f'{name}.der'))
        (path/f'{name}.der').chmod(0o600)
    run('openssl', 'req', '-new', '-x509', '-key', str(path/'key.pem'), '-out', str(path/'cert.der'),
        '-outform', 'DER', '-subj', '/CN=localhost', '-days', '1')
    (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
    (path/'invalid').write_text('invalid\n'); (path/'invalid').chmod(0o600)
    subprocess.run([args.profile.resolve(),
                    path/'secret', path/'cert.der', path/'key.der', path/'invalid', path/'other.der'], check=True)
    if args.credential:
        subprocess.run([args.credential.resolve(), path/'cert.der', path/'key.der', path/'other.der'], check=True)
