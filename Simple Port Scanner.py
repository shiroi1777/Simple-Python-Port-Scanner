import socket
from IPy import IP
import threading
from queue import Queue
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)

JUMLAH_THREAD = 100

class PortScanner:
    def __init__(self, target_host, port_range):
        self.target_host = target_host.strip()
        self.port_range = port_range
        self.ip_address = self._cek_host()
        self.antrian_port = Queue()
        self.port_terbuka = []
        self.lock = threading.Lock()

    def _cek_host(self):
        try:
            IP(self.target_host)
            return self.target_host
        except ValueError:
            try:
                return socket.gethostbyname(self.target_host)
            except socket.gaierror:
                print(f"{Fore.RED}[!] Error: Hostname '{self.target_host}' not found.")
                return None

    def _pindai_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((self.ip_address, port)) == 0:
                    banner = self._dapatkan_banner(s)
                    with self.lock:
                        self.port_terbuka.append(port)
                        if banner:
                            print(f"{Fore.GREEN}[+] Open Port {port}: {Fore.CYAN}{banner}")
                        else:
                            print(f"{Fore.GREEN}[+] Open Port {port}")
        except Exception:
            pass

    def _dapatkan_banner(self, s):
        try:
            banner_bytes = s.recv(1024)
            return banner_bytes.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None

    def _worker(self):
        while not self.antrian_port.empty():
            port = self.antrian_port.get()
            self._pindai_port(port)
            self.antrian_port.task_done()

    def jalankan_pemindaian(self):
        if not self.ip_address:
            return

        print(f"\n{Style.BRIGHT}🔍 Scanning target: {self.target_host} ({self.ip_address})")

        for port in range(self.port_range[0], self.port_range[1] + 1):
            self.antrian_port.put(port)
        
        progress = tqdm(total=self.antrian_port.qsize(), desc="Scanning Ports", unit="port")

        threads = []
        for _ in range(JUMLAH_THREAD):
            thread = threading.Thread(target=self._worker, daemon=True)
            threads.append(thread)
            thread.start()

        initial_qsize = self.antrian_port.qsize()
        while not self.antrian_port.empty():
            progress.update(initial_qsize - self.antrian_port.qsize() - progress.n)
        
        self.antrian_port.join()
        progress.close()

        for thread in threads:
            thread.join()

        self._cetak_hasil()

    def _cetak_hasil(self):
        print(f"\n{Fore.YELLOW}--- ✨ Scan Results for {self.target_host} Complete ✨ ---")
        if self.port_terbuka:
            print(f"Found {len(self.port_terbuka)} open ports:")
            self.port_terbuka.sort()
            print(", ".join(map(str, self.port_terbuka)))
        else:
            print("No open ports found in the scanned range.")
        print("-" * 50)


def main():
    banner = r"""
██████╗  ██████╗ ██████╗ ████████╗                          
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝                          
██████╔╝██║   ██║██████╔╝   ██║                             
██╔═══╝ ██║   ██║██╔══██╗   ██║                             
██║     ╚██████╔╝██║  ██║   ██║                             
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                             
                                                            
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}--- Welcome to the Simple Port Scanner ---")
    targets_input = input("🎯 Enter Target/s (split multiple targets with a comma): ")

    while True:
        ports_input = input("🔢 Enter Port Range (e.g., 1-1000): ")
        try:
            start_port, end_port = map(int, ports_input.split('-'))
            
            if start_port > end_port:
                print(f"{Fore.RED}[!] Starting port cannot be greater than end port. Please try again.")
                continue 

            port_range = (start_port, end_port)
            break 
        except ValueError:
            print(f"{Fore.RED}[!] Invalid port format. Use 'start-end' format, e.g., 1-1000. Please try again.")
            
    targets = [target.strip() for target in targets_input.split(',')]
    
    for target in targets:
        if target:
            scanner = PortScanner(target, port_range)
            scanner.jalankan_pemindaian()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Program terminated by user. Goodbye!")