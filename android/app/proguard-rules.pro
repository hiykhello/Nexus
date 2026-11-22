# Android components declared in AndroidManifest.xml (NexusVpnService, NexusTileService,
# BootReceiver, MainActivity) are automatically kept by AAPT2-generated rules.
# Nexus uses a zero-JNI sidecar architecture (AF_UNIX IPC), so no broad { *; } keep rules
# are needed here; add targeted rules only if reflection-based serializers are introduced.
