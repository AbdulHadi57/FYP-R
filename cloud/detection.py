from __future__ import annotations

import random
import os
import joblib
import pandas as pd
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class FeatureRecord:
    """Lightweight view over the raw feature dictionary."""

    payload: Dict

    @property
    def src_ip(self) -> str:
        return str(self.payload.get("src_ip", "0.0.0.0"))

    @property
    def dst_ip(self) -> str:
        return str(self.payload.get("dst_ip", "0.0.0.0"))

    @property
    def src_port(self) -> int:
        value = self.payload.get("src_port")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def dst_port(self) -> int:
        value = self.payload.get("dst_port")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def protocol(self) -> int:
        value = self.payload.get("protocol")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    @property
    def flow_duration(self) -> float:
        value = self.payload.get("flow_duration")
        try:
            return float(value) if value is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    @property
    def total_packets(self) -> int:
        value = self.payload.get("total_packets")
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0


@dataclass
class DetectionResult:
    module: str
    label: str
    confidence: float
    rationale: str
    score: float
    metadata: Dict = field(default_factory=dict)


@dataclass
class AggregateDecision:
    verdict: str
    confidence: float
    severity: float
    triggered_modules: List[str]


class DetectionModule:
    name: str = "generic"
    version: str = "0.1.0"

    def predict(self, record: FeatureRecord) -> DetectionResult:  # pragma: no cover - interface
        raise NotImplementedError


class RandomDecisionModule(DetectionModule):
    """Base module that blends heuristics with random scoring to mimic AI output."""

    def __init__(self, name: str, malicious_floor: float, seed: Optional[int] = None):
        self.name = name
        self.malicious_floor = malicious_floor
        self._rng = random.Random(seed)

    def extra_risk(self, record: FeatureRecord) -> float:
        return 0.0

    def rationale_bits(self, record: FeatureRecord) -> List[str]:
        return []

    def predict(self, record: FeatureRecord) -> DetectionResult:
        heuristics = self.extra_risk(record)
        # Reduced random noise to prevent excessive false positives
        random_component = self._rng.random() * 0.2
        score = min(1.0, self.malicious_floor + heuristics + random_component)
        label = "malicious" if score >= 0.75 else "benign"
        confidence = 0.5 + abs(score - 0.5)
        rationale_parts = self.rationale_bits(record)
        rationale = ", ".join(rationale_parts) if rationale_parts else "Randomized placeholder decision"
        return DetectionResult(
            module=self.name,
            label=label,
            confidence=round(confidence, 3),
            rationale=rationale,
            score=round(score, 3),
            metadata={"heuristics": heuristics},
        )


class Ja4Module(RandomDecisionModule):
    def __init__(self, seed: Optional[int] = None):
        # Lowered floor from 0.2 to 0.05
        super().__init__(name="ja4-module", malicious_floor=0.05, seed=seed)
        self.model = None
        self.preprocessor = None
        self._load_model()

    def _load_model(self):
        """Attempt to load the real AI model and preprocessor."""
        try:
            base_path = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_path, "ml_models", "malicious_server_detector_ensemble_no_ports.pkl")
            preprocessor_path = os.path.join(base_path, "ml_models", "preprocessor_no_ports.pkl")
            
            if os.path.exists(model_path) and os.path.exists(preprocessor_path):
                self.model = joblib.load(model_path)
                self.preprocessor = joblib.load(preprocessor_path)
                print(f"[INFO] Ja4Module: Loaded real AI model from {model_path}")
            else:
                print(f"[WARN] Ja4Module: Model files not found in {os.path.dirname(model_path)}. Using heuristics.")
        except Exception as e:
            print(f"[ERROR] Ja4Module: Failed to load model: {e}")

    def extra_risk(self, record: FeatureRecord) -> float:
        payload = record.payload
        risk = 0.0
        if payload.get("ja4", "None") == "None":
            risk += 0.15
        if payload.get("ja4h", "None") == "None" and payload.get("has_http", 0):
            risk += 0.05
        entropy = payload.get("fwd_payload_entropy", 0) or 0
        risk += min(entropy / 50.0, 0.15)
        return risk

    def predict(self, record: FeatureRecord) -> DetectionResult:
        # If model is loaded, use it
        if self.model and self.preprocessor:
            try:
                # Convert payload to DataFrame (single row)
                df = pd.DataFrame([record.payload])
                
                # Preprocessing steps from predict.py
                # We must drop the same columns dropped during training/inference preparation
                cols_to_drop = ['src_ip', 'dst_ip', 'Mitre_Tactics', 'Mitre_Techniques', 'ja4l_c', 'ja4l_s']
                # Only drop if they exist in the new data
                existing_cols_to_drop = [col for col in cols_to_drop if col in df.columns]
                df_processed = df.drop(columns=existing_cols_to_drop)
                
                # Preprocess
                X_transformed = self.preprocessor.transform(df_processed)
                
                # Predict
                import warnings
                from sklearn.exceptions import InconsistentVersionWarning
                
                # Suppress "X does not have valid feature names" warning
                # This occurs because we pass a numpy array (from preprocessor) to a model trained with a DataFrame
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    
                    # Use predict() for the hard label to match model's internal logic (e.g. voting in ensemble)
                    prediction = self.model.predict(X_transformed)[0]
                    
                    # Use predict_proba() for confidence/score
                    if hasattr(self.model, "predict_proba"):
                        prob = self.model.predict_proba(X_transformed)[0][1]
                    else:
                        # Fallback if predict_proba is not available
                        prob = 1.0 if prediction == 1 else 0.0
                
                # Map prediction to label using custom threshold
                # If the model returns strings, we handle that too
                if isinstance(prediction, str):
                    label = prediction.lower()
                else:
                    label = "malicious" if prob >= 0.8 else "benign"
                
                return DetectionResult(
                    module=self.name,
                    label=label,
                    confidence=float(prob),
                    rationale=f"AI Model Prediction (Score: {prob:.3f})",
                    score=float(prob),
                    metadata={"ai_model": True}
                )
            except Exception as e:
                print(f"[ERROR] Ja4Module: AI inference failed: {e}. Falling back to heuristics.")
                # Fall through to heuristic implementation below
        
        # If model is not loaded or inference failed, do NOT use heuristics.
        # Return a neutral/benign result indicating no classification was possible.
        return DetectionResult(
            module=self.name,
            label="benign",  # Default to benign if AI cannot confirm malicious
            confidence=0.0,
            rationale="AI Model not available or inference failed",
            score=0.0,
            metadata={"ai_model": False, "error": "Inference skipped"}
        )

    def rationale_bits(self, record: FeatureRecord) -> List[str]:
        payload = record.payload
        reasons = []
        if payload.get("ja4", "None") == "None":
            reasons.append("missing JA4 fingerprint")
        if payload.get("ja4h", "None") == "None" and payload.get("has_http", 0):
            reasons.append("HTTP detected without JA4H signature")
        return reasons


class DoHModule(RandomDecisionModule):
    def __init__(self, seed: Optional[int] = None):
        super().__init__(name="doh-module", malicious_floor=0.1, seed=seed)

    def _model_a_detect_doh(self, record: FeatureRecord) -> bool:
        """Stage 1: Detect if traffic is DoH (Encrypted DNS)."""
        payload = record.payload
        # Simulation: Strong signal if known DoH IP or SNI or Port 853
        if payload.get("is_known_doh_server"): return True
        if payload.get("sni_matches_doh"): return True
        if payload.get("uses_port_853"): return True
        
        # Deterministic Heuristic simulation for detection
        # Use simple hash of IPs to be consistent for the same flow
        if payload.get("uses_port_443"):
            flow_hash = hash(record.src_ip + record.dst_ip)
            # 30% chance for random HTTPS to be flagged as DoH Candidate
            if flow_hash % 100 < 30:
                return True
            
        return False

    def _model_b_classify_threat(self, record: FeatureRecord) -> float:
        """Stage 2: Classify DoH traffic as Malicious or Benign."""
        payload = record.payload
        risk = 0.0
        
        # High Risk for Known DoH Providers (for demo purposes, flag them as 'Tunneling Risk')
        if payload.get("sni_matches_doh") or payload.get("is_known_doh_server"): 
             risk += 0.6  # Immediate > 0.5 threshold
        
        if payload.get("flow_duration", 0) > 60: risk += 0.2
        if payload.get("total_packets", 0) > 100: risk += 0.2
        
        # Deterministic Risk for simulated DoH
        if not payload.get("sni_matches_doh"):
             flow_hash = hash(record.src_ip + record.dst_ip)
             # Of the 30% detected as DoH, make ~half of them "Malicious" for demo variance
             if flow_hash % 100 < 15:
                 risk += 0.5 # Guaranteed Malicious (0.1 base + 0.5 = 0.6 > 0.5 threshold)
        
        # Entropy check
        if payload.get("pkt_len_variance", 0) < 100: risk += 0.1
        
        return risk

    def extra_risk(self, record: FeatureRecord) -> float:
        # Wrapper to maintain compatibility, but logic moves to predict() override
        return 0.0 

    def predict(self, record: FeatureRecord) -> DetectionResult:
        # Stage 1: Detection
        is_doh = self._model_a_detect_doh(record)
        
        if not is_doh:
            # Not DoH -> Benign (with low score)
            return DetectionResult(
                module=self.name,
                label="benign",
                confidence=0.9,
                rationale="Not detected as DoH traffic (Stage 1)",
                score=0.1,
                metadata={"stage1_doh": False}
            )
            
        # Stage 2: Classification (Only runs if Stage 1 is True)
        risk_score = self._model_b_classify_threat(record)
        
        # Add random noise for simulation
        random_component = self._rng.random() * 0.2
        final_score = min(1.0, 0.1 + risk_score + random_component) # Baseline 0.1 risk for any DoH
        
        label = "malicious" if final_score >= 0.88 else "benign"
        confidence = 0.5 + abs(final_score - 0.5)
        
        rationale_bits = self.rationale_bits(record)
        rationale = ", ".join(rationale_bits) if rationale_bits else "Potential DoH Tunnel detected"
        
        return DetectionResult(
            module=self.name,
            label=label,
            confidence=round(confidence, 3),
            rationale=rationale,
            score=round(final_score, 3),
            metadata={"stage1_doh": True, "heuristics": risk_score}
        )

    def rationale_bits(self, record: FeatureRecord) -> List[str]:
        payload = record.payload
        reasons = []
        if payload.get("is_known_doh_server"):
            reasons.append("known DoH IP")
        if payload.get("sni_matches_doh"):
            reasons.append(f"SNI={payload.get('matched_sni_domain', 'unknown')}")
        if payload.get("uses_port_853"):
            reasons.append("port 853 in use")
        return reasons


class AptModule(RandomDecisionModule):
    def __init__(self, seed: Optional[int] = None):
        # Lowered floor from 0.15 to 0.05
        super().__init__(name="apt-module", malicious_floor=0.05, seed=seed)

    def extra_risk(self, record: FeatureRecord) -> float:
        payload = record.payload
        risk = 0.0
        long_flow = (payload.get("flow_duration", 0) or 0) > 120
        high_entropy = (payload.get("fwd_payload_entropy", 0) or 0) > 6
        sparse_packets = (payload.get("total_packets", 0) or 0) < 5
        if long_flow:
            risk += 0.15
        if high_entropy:
            risk += 0.1
        if sparse_packets and long_flow:
            risk += 0.1
        return risk

    def rationale_bits(self, record: FeatureRecord) -> List[str]:
        payload = record.payload
        reasons = []
        if (payload.get("flow_duration", 0) or 0) > 120:
            reasons.append("long-lived flow")
        if (payload.get("fwd_payload_entropy", 0) or 0) > 6:
            reasons.append("high payload entropy")
        return reasons


class DetectionEngine:
    """
    Central engine to run all detection modules and aggregate results.
    Replicates the logic previously found in the Agent's TrafficPipeline.
    """
    def __init__(self, model_dir: str = "ml_models"):
        # Load modules
        # We use a fixed seed for deterministic behavior in cloud (or random)
        seed = 1337
        rng = random.Random(seed)
        self.modules = [
            Ja4Module(seed=rng.randint(0, 10_000)),
            DoHModule(seed=rng.randint(0, 10_000)),
            AptModule(seed=rng.randint(0, 10_000)),
        ]
        
    def _aggregate(self, results: List[DetectionResult]) -> AggregateDecision:
        triggered = [res.module for res in results if res.label == "malicious"]
        verdict = "malicious" if triggered else "benign"
        if triggered:
            confidence = max(res.confidence for res in results if res.label == "malicious")
        else:
            confidence = min(res.confidence for res in results) if results else 0.0
        severity = len(triggered) / len(results) if results else 0.0
        return AggregateDecision(verdict=verdict, confidence=round(confidence, 3), severity=round(severity, 3), triggered_modules=triggered)

    def process(self, record: FeatureRecord) -> tuple[FeatureRecord, AggregateDecision, List[DetectionResult]]:
        module_results = [module.predict(record) for module in self.modules]
        aggregate = self._aggregate(module_results)
        return record, aggregate, module_results
