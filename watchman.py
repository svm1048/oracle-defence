import pyshark
import os
import sys

# --- CONFIGURATION ---
INTERFACE = 'lo0'          # Wi-Fi on Mac
FAKE_PORT = 1337           # The Honey Port
# CRITICAL: Point to the TShark app inside Wireshark
TSHARK_PATH = '/Applications/Wireshark.app/Contents/MacOS/tshark'

def start_watchman():
    print("\n" + "="*60)
    print(f"[*] PHASE 2: THE WATCHMAN - ACTIVE")
    print(f"[*] Interface: {INTERFACE}")
    print(f"[*] Monitoring Honey Port: {FAKE_PORT}")
    print("="*60 + "\n")

    if not os.path.exists(TSHARK_PATH):
        print(f"[!] ERROR: TShark not found at {TSHARK_PATH}")
        return

    try:
        # Define the capture
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            display_filter='tcp', 
            tshark_path=TSHARK_PATH
        )
        
        print("[*] Listening for traffic... (Press Ctrl+C to stop)")

        # STANDARD SYNC LOOP (No Asyncio needed)
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
                        print(f" REASON:    Direct interaction with Trap Port {FAKE_PORT}")
                        print("!"*60 + "\n")

            except AttributeError:
                continue 
            except Exception as e:
                print(f"[!] Error: {e}")

    except KeyboardInterrupt:
        print("\n[*] Watchman deactivated.")
    except Exception as e:
        print(f"\n[!] Critical Crash: {e}")

if __name__ == "__main__":
    start_watchman()