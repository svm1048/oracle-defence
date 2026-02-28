import pyshark
import os
import sys
import json
from web3 import Web3

# --- CONFIGURATION ---
INTERFACE = 'lo0'          # Use 'lo0' for localhost testing or 'en0' for Wi-Fi
FAKE_PORT = 1337           
TSHARK_PATH = '/Applications/Wireshark.app/Contents/MacOS/tshark'

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

def record_on_blockchain(intruder_ip, reason):
    """Logs the anomaly into the immutable blockchain ledger."""
    if not w3.is_connected():
        print("[!] Blockchain not connected. Skipping log.")
        return

    try:
        print(f"[*] Committing to Blockchain: {intruder_ip} -> {reason}")
        
        # Initialize contract
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        
        # Use the first account from Ganache
        account = w3.eth.accounts[0]
        
        # Call the Solidity function: recordAttack(string ip, string details)
        tx_hash = contract.functions.recordAttack(
            intruder_ip, 
            reason
        ).transact({'from': account})
        
        # Wait for the block to be mined
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[+] Blockchain Transaction Confirmed in Block: {receipt.blockNumber}")

    except Exception as e:
        print(f"[!] Blockchain Error: {e}")

def start_watchman():
    print("\n" + "="*60)
    print(f"[*] PHASE 2: THE WATCHMAN (BLOCKCHAIN EDITION)")
    print(f"[*] Interface: {INTERFACE} | Port: {FAKE_PORT}")
    print("="*60 + "\n")

    if not os.path.exists(TSHARK_PATH):
        print(f"[!] ERROR: TShark not found at {TSHARK_PATH}")
        return

    try:
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            display_filter='tcp', 
            tshark_path=TSHARK_PATH
        )
        
        print("[*] Listening for traffic... (Press Ctrl+C to stop)")

        for packet in capture.sniff_continuously():
            try:
                if 'IP' in packet and 'TCP' in packet:
                    src_ip = packet.ip.src
                    dst_port = int(packet.tcp.dstport)
                    
                    # === THE TRAP ===
                    if dst_port == FAKE_PORT:
                        print("\n" + "!"*60)
                        print(f" [CRITICAL BREACH CONFIRMED]")
                        print(f" SOURCE IP: {src_ip}")
                        print("!"*60 + "\n")
                        
                        # NEW: Send data to the blockchain
                        record_on_blockchain(src_ip, f"Unauthorized access to port {FAKE_PORT}")

            except AttributeError:
                continue 

    except KeyboardInterrupt:
        print("\n[*] Watchman deactivated.")

if __name__ == "__main__":
    start_watchman()