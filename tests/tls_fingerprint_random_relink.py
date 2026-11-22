"""Relink the fingerprint entropy probe with the calibrated CSPRNG wrapper.

Uses the same existing Ninja/response-file/link-command implementation as the
QUIC RecordLayer probe; only the exact intercepted factory symbol differs.
"""
import quic_tls_relink as relink

relink.SYMBOL="_ZN5nexus6cryptoW5nexusW6crypto12random_bytesESt4spanIhLm18446744073709551615EE"
relink.__doc__=__doc__
if __name__=="__main__":relink.main()
