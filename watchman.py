#!/usr/bin/env python3
"""
Oracle Defense - Phase 2: The Watchman AI
Real-time binary classifier with blockchain integration for detecting hostile interactions on honey-port 1337.
"""

import pyshark
import os
import sys
import time
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Optional, Tuple
from collections import deque
import joblib
from pathlib import Path
from web3 import Web3

# Scikit-learn imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# --- CONFIGURATION ---
INTERFACE = 'lo0'          # Use 'lo0' for localhost testing or 'en0' for Wi-Fi
FAKE_PORT = 1337           # The Honey Port
ADMIN_IP = '192.168.1.50'  # Phase 1 Baseline - Admin IP to filter out
TSHARK_PATH = '/Applications/Wireshark.app/Contents/MacOS/tshark'  # TShark path

# Model configuration
MODEL_PATH = 'models/watchman_model.joblib'
SCALER_PATH = 'models/watchman_scaler.joblib'
N_TREES = 100  # F-2.2: At least 100 decision trees for majority vote

# --- BLOCKCHAIN CONFIGURATION ---
# 1. Connect to Ganache (Default port is 7545)
BLOCKCHAIN_URL = "HTTP://127.0.0.1:7545" 
w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))

# 2. Contract Details (Replace these after deploying your Solidity contract)
CONTRACT_ADDRESS = "0xd9145CCE52D386f254917e481eB44e9943F39138"
# Copy the ABI from the Solidity Compiler in Remix
CONTRACT_ABI = json.loads('''[
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "intruderIP",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "details",
				"type": "string"
			}
		],
		"name": "AttackLogged",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_ip",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "_details",
				"type": "string"
			}
		],
		"name": "recordAttack",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "attackHistory",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "intruderIP",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "details",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_index",
				"type": "uint256"
			}
		],
		"name": "getAttack",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getAttackCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]''')


class FeatureExtractor:
    """
    Extracts 5-feature vector from packet metadata.
    Features: [packet_size, payload_size, inter_arrival_time, source_port, protocol_type]
    """
    
    def __init__(self):
        self.last_packet_time = {}
        self.packet_history = deque(maxlen=100)  # Track recent packets for context
    
    def extract_features(self, packet, source_ip: str) -> Optional[np.ndarray]:
        """
        Extract 5-feature vector from packet.
        F-2.1: Must complete in under 5ms.
        
        Returns:
            numpy array of shape (5,) or None if extraction fails
        """
        try:
            start_time = time.time()
            
            # Feature 1: Packet Size (bytes)
            packet_size = int(packet.length) if hasattr(packet, 'length') else 0
            
            # Feature 2: Payload Size (bytes)
            payload_size = 0
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                try:
                    payload_str = str(packet.tcp.payload).replace(':', '')
                    # Try to decode hex if it's hex-encoded
                    if payload_str and all(c in '0123456789abcdefABCDEF' for c in payload_str):
                        payload_size = len(bytes.fromhex(payload_str))
                    else:
                        payload_size = len(payload_str)
                except:
                    payload_size = len(str(packet.tcp.payload)) if packet.tcp.payload else 0
            elif hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
                try:
                    payload_str = str(packet.udp.payload).replace(':', '')
                    # Try to decode hex if it's hex-encoded
                    if payload_str and all(c in '0123456789abcdefABCDEF' for c in payload_str):
                        payload_size = len(bytes.fromhex(payload_str))
                    else:
                        payload_size = len(payload_str)
                except:
                    payload_size = len(str(packet.udp.payload)) if packet.udp.payload else 0
            
            # Feature 3: Inter-arrival Time (seconds since last packet from this source)
            current_time = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else time.time()
            if source_ip in self.last_packet_time:
                inter_arrival = current_time - self.last_packet_time[source_ip]
            else:
                inter_arrival = 0.0  # First packet from this source
            self.last_packet_time[source_ip] = current_time
            
            # Feature 4: Source Port
            source_port = 0
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport'):
                source_port = int(packet.tcp.srcport)
            elif hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport'):
                source_port = int(packet.udp.srcport)
            
            # Feature 5: Protocol Type (encoded as: TCP=1, UDP=2, Other=0)
            protocol_type = 0
            if hasattr(packet, 'tcp'):
                protocol_type = 1  # TCP
            elif hasattr(packet, 'udp'):
                protocol_type = 2  # UDP
            
            # Build feature vector
            feature_vector = np.array([
                packet_size,
                payload_size,
                inter_arrival,
                source_port,
                protocol_type
            ], dtype=np.float32)
            
            # Performance check (F-2.1: under 5ms)
            extraction_time = (time.time() - start_time) * 1000  # Convert to ms
            if extraction_time > 5.0:
                print(f"[!] WARNING: Feature extraction took {extraction_time:.2f}ms (target: <5ms)")
            
            return feature_vector
            
        except Exception as e:
            print(f"[!] Feature extraction error: {e}")
            return None


class WatchmanAI:
    """
    The Watchman AI - Real-time binary classifier using RandomForest.
    """
    
    def __init__(self, model_path: Optional[str] = None, scaler_path: Optional[str] = None):
        self.model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.model_path = model_path or MODEL_PATH
        self.scaler_path = scaler_path or SCALER_PATH
        
        # Load or create model
        self._load_or_create_model()
    
    def _load_or_create_model(self):
        """Load existing model or create a new one."""
        model_dir = Path(self.model_path).parent
        model_dir.mkdir(parents=True, exist_ok=True)
        
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            print(f"[*] Loading pre-trained model from {self.model_path}")
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            print(f"[+] Model loaded: {len(self.model.estimators_)} trees")
        else:
            print("[*] No pre-trained model found. Creating new model...")
            print("[!] NOTE: Model needs training data. Using default untrained model.")
            self._create_default_model()
    
    def _create_default_model(self):
        """Create a default RandomForest model (untrained - needs training data)."""
        # F-2.2: At least 100 decision trees
        self.model = RandomForestClassifier(
            n_estimators=N_TREES,
            max_depth=10,
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
        self.scaler = StandardScaler()
        
        # Create dummy training data to initialize scaler
        # In production, replace with actual training dataset
        dummy_X = np.random.rand(100, 5) * 1000
        self.scaler.fit(dummy_X)
        
        print(f"[+] Created default model with {N_TREES} trees")
        print("[!] WARNING: Model is untrained. Train with real data for production use.")
    
    def train_model(self, X: np.ndarray, y: np.ndarray, save: bool = True):
        """
        Train the RandomForest model.
        
        Args:
            X: Feature matrix (n_samples, 5)
            y: Labels (0=Benign, 1=Hostile)
            save: Whether to save the trained model
        """
        print(f"[*] Training model with {len(X)} samples...")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        print(f"[+] Training complete!")
        print(f"    Train accuracy: {train_score:.4f}")
        print(f"    Test accuracy: {test_score:.4f}")
        print(f"    Trees: {len(self.model.estimators_)}")
        
        if save:
            self.save_model()
    
    def save_model(self):
        """Save model and scaler to disk."""
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        print(f"[+] Model saved to {self.model_path}")
    
    def predict(self, feature_vector: np.ndarray) -> Tuple[int, float]:
        """
        Predict if packet is hostile (1) or benign (0).
        
        Args:
            feature_vector: 5-feature vector
            
        Returns:
            (prediction, confidence) where prediction is 0 or 1
        """
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model not loaded or initialized")
        
        # Reshape for single sample
        X = feature_vector.reshape(1, -1)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]
        
        # Get prediction probability for confidence
        proba = self.model.predict_proba(X_scaled)[0]
        confidence = proba[int(prediction)]
        
        return int(prediction), float(confidence)


def record_on_blockchain(intruder_ip: str, packet_id: str, details: str):
    """
    F-2.3: Alert Triggering - Logs the anomaly into the immutable blockchain ledger.
    
    Args:
        intruder_ip: Source IP address
        packet_id: Unique packet identifier
        details: Attack details/reason
    """
    if not w3.is_connected():
        print("[!] Blockchain not connected. Skipping log.")
        return False

    try:
        print(f"[*] Committing to Blockchain: {intruder_ip} -> {details}")
        
        # Initialize contract
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        
        # Use the first account from Ganache
        account = w3.eth.accounts[0]
        
        # Call the Solidity function: recordAttack(string ip, string details)
        tx_hash = contract.functions.recordAttack(
            intruder_ip, 
            f"{details} | Packet_ID: {packet_id}"
        ).transact({'from': account})
        
        # Wait for the block to be mined
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[+] Blockchain Transaction Confirmed in Block: {receipt.blockNumber}")
        return True

    except Exception as e:
        print(f"[!] Blockchain Error: {e}")
        return False


def start_watchman():
    """
    Main Watchman execution loop.
    Listen -> Filter -> Vectorize -> Predict -> Respond
    """
    print("\n" + "="*60)
    print("[*] PHASE 2: THE WATCHMAN AI - ACTIVE")
    print("="*60)
    print(f"[*] Interface: {INTERFACE}")
    print(f"[*] Monitoring Honey Port: {FAKE_PORT}")
    print(f"[*] Admin IP Filter: {ADMIN_IP}")
    print(f"[*] Model: {N_TREES} decision trees")
    
    # Check blockchain connection
    if w3.is_connected():
        print(f"[*] Blockchain: Connected to {BLOCKCHAIN_URL}")
        print(f"[*] Contract: {CONTRACT_ADDRESS}")
    else:
        print(f"[!] Blockchain: Not connected to {BLOCKCHAIN_URL}")
        print("[!] Alerts will not be logged to blockchain")
    
    print("="*60 + "\n")
    
    if not os.path.exists(TSHARK_PATH):
        print(f"[!] ERROR: TShark not found at {TSHARK_PATH}")
        print("[!] Please install Wireshark or update TSHARK_PATH")
        return
    
    # Initialize Watchman AI
    try:
        watchman = WatchmanAI()
    except Exception as e:
        print(f"[!] Failed to initialize Watchman AI: {e}")
        return
    
    # Initialize feature extractor
    feature_extractor = FeatureExtractor()
    
    try:
        # Define the capture filter for port 1337
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            display_filter=f'tcp.port == {FAKE_PORT} or udp.port == {FAKE_PORT}',
            tshark_path=TSHARK_PATH
        )
        
        print("[*] Listening for traffic on honey-port 1337...")
        print("[*] Press Ctrl+C to stop\n")
        
        packet_count = 0
        
        # Main Watchman Loop
        for packet in capture.sniff_continuously():
            try:
                # Extract packet metadata
                if 'IP' not in packet:
                    continue
                
                src_ip = packet.ip.src
                dst_port = 0
                
                if 'TCP' in packet:
                    dst_port = int(packet.tcp.dstport)
                elif 'UDP' in packet:
                    dst_port = int(packet.udp.dstport)
                else:
                    continue
                
                # Filter: Ignore packets from Admin IP (Phase 1 Baseline)
                if src_ip == ADMIN_IP:
                    continue
                
                # Only process packets targeting honey-port
                if dst_port != FAKE_PORT:
                    continue
                
                packet_count += 1
                packet_id = f"PKT-{int(time.time()*1000)}-{packet_count}"
                
                # Vectorize: Extract 5-feature vector
                feature_vector = feature_extractor.extract_features(packet, src_ip)
                
                if feature_vector is None:
                    continue
                
                # Predict: Run through RandomForest model
                prediction, confidence = watchman.predict(feature_vector)
                
                # Log packet analysis
                print(f"[{packet_count}] Source: {src_ip:15s} | "
                      f"Prediction: {'HOSTILE' if prediction == 1 else 'BENIGN':8s} | "
                      f"Confidence: {confidence:.2%}")
                
                # Respond: If hostile (prediction == 1), trigger alert
                if prediction == 1:
                    print("\n" + "!"*60)
                    print(f" [CRITICAL BREACH DETECTED]")
                    print(f" SOURCE IP: {src_ip}")
                    print(f" PACKET ID: {packet_id}")
                    print(f" CONFIDENCE: {confidence:.2%}")
                    print(f" REASON: AI Model classified as hostile interaction")
                    print("!"*60 + "\n")
                    
                    # F-2.3: Trigger blockchain alert
                    record_on_blockchain(
                        intruder_ip=src_ip,
                        packet_id=packet_id,
                        details=f"AI-detected hostile interaction on port {FAKE_PORT}"
                    )
                
            except AttributeError as e:
                # Skip packets missing required fields
                continue
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"[!] Error processing packet: {e}")
                continue
    
    except KeyboardInterrupt:
        print("\n[*] Watchman deactivated.")
    except Exception as e:
        print(f"\n[!] Critical Crash: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    start_watchman()
