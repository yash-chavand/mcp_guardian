"""
Sequence & Event Feature Encoder for MCP Guardian V2 (Feature 2).
Converts raw tool calls and session history into structured vector embeddings.
"""

from typing import List, Dict, Any, Tuple
import numpy as np


class SequenceFeatureEncoder:
    """Encodes discrete and continuous event attributes into fixed-size numerical vectors."""

    # Canonical tool vocabulary mapping
    DEFAULT_VOCAB = {
        "<PAD>": 0,
        "<UNK>": 1,
        "get_customer_order": 2,
        "send_email": 3,
        "read_database": 4,
        "write_database": 5,
        "read_file": 6,
        "write_file": 7,
        "execute_command": 8,
        "dispatch_notification": 9,
        "admin_override": 10
    }

    def __init__(self, vocab: Dict[str, int] = None, max_seq_len: int = 8):
        self.vocab = vocab or dict(self.DEFAULT_VOCAB)
        self.max_seq_len = max_seq_len
        self.feature_dim = len(self.vocab) + 4  # one-hot tool + [time_delta, records, is_outbound, mismatch]

    def encode_event(self, event: Dict[str, Any]) -> np.ndarray:
        """Encode a single event dict into a numerical vector."""
        tool_name = str(event.get("tool", event.get("tool_name", "<UNK>")))
        tool_idx = self.vocab.get(tool_name, self.vocab["<UNK>"])

        # One-hot vector for tool
        one_hot = np.zeros(len(self.vocab), dtype=np.float32)
        one_hot[tool_idx] = 1.0

        # Continuous / binary features
        time_delta = float(event.get("time_since_last_call", event.get("time_delta", 1.0)))
        # Normalize time delta logarithmically
        norm_time = float(np.log1p(max(0.0, time_delta)))

        records = float(event.get("records_requested", event.get("records", 1.0)))
        norm_records = float(np.log1p(max(0.0, records)))

        is_outbound = float(event.get("is_email", event.get("is_outbound", 0.0)))
        mismatch = float(event.get("recipient_mismatch", 0.0))

        extra_feats = np.array([norm_time, norm_records, is_outbound, mismatch], dtype=np.float32)
        return np.concatenate([one_hot, extra_feats])

    def encode_sequence(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Encode a list of events into a matrix of shape (max_seq_len, feature_dim)."""
        recent_events = events[-self.max_seq_len:]
        encoded_list = [self.encode_event(e) for e in recent_events]

        # Pad left with zeros if shorter than max_seq_len
        pad_len = self.max_seq_len - len(encoded_list)
        if pad_len > 0:
            padding = [np.zeros(self.feature_dim, dtype=np.float32) for _ in range(pad_len)]
            encoded_matrix = np.array(padding + encoded_list, dtype=np.float32)
        else:
            encoded_matrix = np.array(encoded_list, dtype=np.float32)

        return encoded_matrix
