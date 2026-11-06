from . import files, network, persistence, processes, sensitive_data, sniffer, system_config

# Order matters: later checks reuse the process/connection snapshot.
ALL_CHECKS = [processes, network, sniffer, persistence, system_config, files, sensitive_data]
