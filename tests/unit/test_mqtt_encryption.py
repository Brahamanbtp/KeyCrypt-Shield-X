import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.iot.mqtt_encryption import (
    publish_encrypted,
    subscribe_encrypted,
    implement_e2e_mqtt_encryption,
    rotate_mqtt_keys,
)
from src.integrations.iot.edge_encryption import deploy_to_edge_device


def test_basic_publish_subscribe_roundtrip() -> None:
    topic = "devices/sensor/1"
    pub = "dev-pub"
    sub = "dev-sub"
    deploy_to_edge_device(pub)
    deploy_to_edge_device(sub)
    received = []

    def cb(msg: bytes) -> None:
        received.append(msg)

    implement_e2e_mqtt_encryption(pub, sub)
    subscribe_encrypted(topic, cb)
    publish_encrypted(topic, b"hello", qos=0)

    # allow threads to deliver
    import time

    time.sleep(0.1)
    assert received and received[0] == b"hello"


def test_rotate_keys_changes_ciphertext() -> None:
    topic = "devices/sensor/rotate"
    pub = "dev-pub-2"
    sub = "dev-sub-2"
    deploy_to_edge_device(pub)
    deploy_to_edge_device(sub)
    implement_e2e_mqtt_encryption(pub, sub)

    # capture ciphertext before rotation
    captured = []

    def capture_cb(payload: bytes) -> None:
        captured.append(payload)

    subscribe_encrypted(topic, capture_cb)
    publish_encrypted(topic, b"v1", qos=0)
    import time

    time.sleep(0.05)
    before = captured[0]

    rotate_mqtt_keys(topic)
    publish_encrypted(topic, b"v2", qos=0)
    time.sleep(0.05)
    after = captured[1]
    assert before != after
