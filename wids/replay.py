from scapy.utils import PcapReader
from .monitoring import Pipeline


def replay_sync(path, storage, settings, provenance="user capture", model=True):
    """No wall-clock delays; identical packet processing for tests and CLI analysis."""
    pipeline = Pipeline(storage, settings, str(path), provenance, model)
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                pipeline.ingest(packet)
        pipeline.finish()
    except Exception as error:
        pipeline.finish("error", str(error))
        raise
    return pipeline.session_id
