#!/usr/bin/env python3
"""
Training script for Watchman AI model.
Generates training data and trains the RandomForest classifier.
"""

import numpy as np
from watchman import WatchmanAI

def generate_training_data(n_benign=1000, n_hostile=1000):
    """
    Generate realistic training data for network packet classification.
    
    Args:
        n_benign: Number of benign samples to generate
        n_hostile: Number of hostile samples to generate
        
    Returns:
        X: Feature matrix (n_samples, 5)
        y: Labels (0=Benign, 1=Hostile)
    """
    np.random.seed(42)  # For reproducibility
    
    print(f"[*] Generating {n_benign} benign and {n_hostile} hostile samples...")
    
    # ===== BENIGN TRAFFIC PATTERNS =====
    # Normal network traffic characteristics:
    # - Moderate packet sizes (typical TCP packets)
    # - Small to medium payloads
    # - Regular inter-arrival times (human-like patterns)
    # - High source ports (ephemeral ports)
    # - Mostly TCP
    
    benign_X = np.array([
        # Feature 1: Packet Size (bytes) - Normal range: 40-1500 bytes
        np.random.normal(64, 15, n_benign).clip(40, 1500),
        
        # Feature 2: Payload Size (bytes) - Small payloads: 0-100 bytes
        np.random.exponential(20, n_benign).clip(0, 200),
        
        # Feature 3: Inter-arrival Time (seconds) - Regular intervals: 0.5-5 seconds
        np.random.gamma(2.0, 1.0, n_benign).clip(0.1, 10.0),
        
        # Feature 4: Source Port - High ports (ephemeral): 32768-65535
        np.random.randint(32768, 65536, n_benign),
        
        # Feature 5: Protocol Type - Mostly TCP (1)
        np.random.choice([1, 2], n_benign, p=[0.9, 0.1])  # 90% TCP, 10% UDP
    ]).T
    
    # ===== HOSTILE TRAFFIC PATTERNS =====
    # Malicious traffic characteristics:
    # - Larger packet sizes (scanning/exploitation attempts)
    # - Larger payloads (injection attempts, data exfiltration)
    # - Very fast inter-arrival (burst attacks, scanning)
    # - Low source ports (suspicious - not using ephemeral ports)
    # - Mostly TCP (but some UDP for evasion)
    
    hostile_X = np.array([
        # Feature 1: Packet Size (bytes) - Larger packets: 100-1500 bytes
        np.random.normal(300, 100, n_hostile).clip(100, 1500),
        
        # Feature 2: Payload Size (bytes) - Larger payloads: 50-500 bytes
        np.random.exponential(100, n_hostile).clip(50, 800),
        
        # Feature 3: Inter-arrival Time (seconds) - Very fast: 0.001-0.5 seconds (burst)
        np.random.exponential(0.05, n_hostile).clip(0.001, 1.0),
        
        # Feature 4: Source Port - Low ports (suspicious): 1-1024
        np.random.randint(1, 1025, n_hostile),
        
        # Feature 5: Protocol Type - Mostly TCP (1), some UDP (2)
        np.random.choice([1, 2], n_hostile, p=[0.85, 0.15])  # 85% TCP, 15% UDP
    ]).T
    
    # Combine datasets
    X = np.vstack([benign_X, hostile_X])
    y = np.hstack([np.zeros(n_benign, dtype=int), np.ones(n_hostile, dtype=int)])
    
    # Shuffle the data
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]
    
    return X, y


def generate_extended_training_data(n_benign=2000, n_hostile=2000):
    """
    Generate extended training data with more variety for better model performance.
    Includes edge cases and mixed patterns.
    
    Args:
        n_benign: Number of benign samples
        n_hostile: Number of hostile samples
        
    Returns:
        X: Feature matrix (n_samples, 5)
        y: Labels (0=Benign, 1=Hostile)
    """
    np.random.seed(42)
    
    print(f"[*] Generating extended dataset: {n_benign} benign + {n_hostile} hostile samples...")
    
    # Split into different traffic patterns for more realistic data
    
    # === BENIGN TRAFFIC ===
    benign_samples = []
    
    # Pattern 1: Normal web traffic (60%)
    n1 = int(n_benign * 0.6)
    benign_samples.append(np.array([
        np.random.normal(64, 10, n1).clip(40, 150),      # Small packets
        np.random.exponential(15, n1).clip(0, 100),     # Small payloads
        np.random.gamma(2.0, 1.5, n1).clip(0.5, 8.0),   # Regular intervals
        np.random.randint(49152, 65536, n1),            # High ports
        np.ones(n1)                                      # TCP
    ]).T)
    
    # Pattern 2: Normal file transfer (20%)
    n2 = int(n_benign * 0.2)
    benign_samples.append(np.array([
        np.random.normal(1500, 50, n2).clip(1000, 1500), # Large packets (MTU)
        np.random.normal(1440, 40, n2).clip(1000, 1440), # Large payloads
        np.random.gamma(1.5, 0.5, n2).clip(0.1, 3.0),    # Fast but regular
        np.random.randint(32768, 65536, n2),            # High ports
        np.ones(n2)                                      # TCP
    ]).T)
    
    # Pattern 3: Normal UDP traffic (20%)
    n3 = n_benign - n1 - n2
    benign_samples.append(np.array([
        np.random.normal(100, 30, n3).clip(40, 500),     # Medium packets
        np.random.exponential(50, n3).clip(0, 200),      # Medium payloads
        np.random.gamma(1.0, 2.0, n3).clip(0.2, 10.0),   # Variable intervals
        np.random.randint(32768, 65536, n3),             # High ports
        np.full(n3, 2)                                   # UDP
    ]).T)
    
    benign_X = np.vstack(benign_samples)
    
    # === HOSTILE TRAFFIC ===
    hostile_samples = []
    
    # Pattern 1: Port scanning (40%)
    n1 = int(n_hostile * 0.4)
    hostile_samples.append(np.array([
        np.random.normal(60, 5, n1).clip(40, 100),       # Small packets (SYN scans)
        np.random.exponential(10, n1).clip(0, 50),       # Minimal payloads
        np.random.exponential(0.01, n1).clip(0.001, 0.1), # Very fast (scanning)
        np.random.randint(1, 1024, n1),                  # Low ports
        np.ones(n1)                                       # TCP
    ]).T)
    
    # Pattern 2: Exploitation attempts (30%)
    n2 = int(n_hostile * 0.3)
    hostile_samples.append(np.array([
        np.random.normal(400, 100, n2).clip(200, 1000),  # Medium-large packets
        np.random.exponential(200, n2).clip(100, 600),   # Large payloads (exploits)
        np.random.exponential(0.1, n2).clip(0.01, 1.0),  # Fast bursts
        np.random.randint(1, 1024, n2),                  # Low ports
        np.ones(n2)                                      # TCP
    ]).T)
    
    # Pattern 3: Data exfiltration (20%)
    n3 = int(n_hostile * 0.2)
    hostile_samples.append(np.array([
        np.random.normal(1200, 200, n3).clip(800, 1500), # Large packets
        np.random.normal(1100, 150, n3).clip(700, 1440), # Large payloads
        np.random.exponential(0.05, n3).clip(0.01, 0.5), # Fast continuous
        np.random.randint(1, 1024, n3),                  # Low ports
        np.ones(n3)                                      # TCP
    ]).T)
    
    # Pattern 4: UDP-based attacks (10%)
    n4 = n_hostile - n1 - n2 - n3
    hostile_samples.append(np.array([
        np.random.normal(200, 50, n4).clip(100, 500),    # Medium packets
        np.random.exponential(150, n4).clip(50, 400),    # Medium payloads
        np.random.exponential(0.02, n4).clip(0.001, 0.2), # Very fast (flooding)
        np.random.randint(1, 1024, n4),                  # Low ports
        np.full(n4, 2)                                   # UDP
    ]).T)
    
    hostile_X = np.vstack(hostile_samples)
    
    # Combine and shuffle
    X = np.vstack([benign_X, hostile_X])
    y = np.hstack([
        np.zeros(len(benign_X), dtype=int),
        np.ones(len(hostile_X), dtype=int)
    ])
    
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]
    
    return X, y


def main():
    """Main training function."""
    print("="*60)
    print("[*] Watchman AI - Model Training")
    print("="*60)
    
    # Generate training data
    print("\n[*] Generating training data...")
    # Use extended dataset for better model performance
    X, y = generate_extended_training_data(n_benign=2000, n_hostile=2000)
    
    print(f"[+] Generated {len(X)} training samples")
    print(f"    Benign samples: {np.sum(y == 0)}")
    print(f"    Hostile samples: {np.sum(y == 1)}")
    
    # Display feature statistics
    print("\n[*] Feature Statistics:")
    print(f"    Packet Size:     min={X[:, 0].min():.1f}, max={X[:, 0].max():.1f}, mean={X[:, 0].mean():.1f}")
    print(f"    Payload Size:    min={X[:, 1].min():.1f}, max={X[:, 1].max():.1f}, mean={X[:, 1].mean():.1f}")
    print(f"    Inter-arrival:   min={X[:, 2].min():.4f}, max={X[:, 2].max():.2f}, mean={X[:, 2].mean():.2f}")
    print(f"    Source Port:     min={X[:, 3].min()}, max={X[:, 3].max()}, mean={X[:, 3].mean():.1f}")
    print(f"    Protocol Type:   TCP={np.sum(X[:, 4] == 1)}, UDP={np.sum(X[:, 4] == 2)}")
    
    # Initialize Watchman AI
    print("\n[*] Initializing Watchman AI...")
    watchman = WatchmanAI()
    
    # Train model
    print("\n[*] Training RandomForest classifier...")
    watchman.train_model(X, y, save=True)
    
    # Test prediction on sample data
    print("\n[*] Testing model on sample predictions...")
    test_samples = [
        np.array([64, 20, 2.0, 50000, 1]),    # Benign pattern
        np.array([300, 150, 0.01, 80, 1]),    # Hostile pattern
        np.array([1500, 1440, 0.05, 22, 1]),  # Hostile pattern (large)
    ]
    
    for i, sample in enumerate(test_samples):
        pred, conf = watchman.predict(sample)
        label = "HOSTILE" if pred == 1 else "BENIGN"
        print(f"    Sample {i+1}: {label} (confidence: {conf:.2%})")
    
    print("\n" + "="*60)
    print("[+] Training complete! Model saved and ready for deployment.")
    print("[*] You can now run: python watchman.py")
    print("="*60)


if __name__ == "__main__":
    main()
