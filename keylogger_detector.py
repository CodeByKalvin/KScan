import os
import psutil
import logging
import argparse
import platform
import json
import win32api
import win32con
import win32gui
import win32process
import ctypes
import winreg
import subprocess
from abc import ABC, abstractmethod

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

print("""
  ______            __        __
 /_  __/   ____ _ / /____   / /
  / /    / __ `/ / / ___/  / /
 / /    / /_/ / / / /__   / /
/_/     \__,_/ /_/\___/  /_/
        CodeByKalvin
""")

# Configuration file name
CONFIG_FILE_NAME = "detector_config.json"

class ConfigManager:
    """Handles loading, updating, and creating config files."""
    def __init__(self, config_file=CONFIG_FILE_NAME):
        """Initialize with the config file name"""
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        """Loads the configuration file."""
        try:
          with open(self.config_file, 'r') as f:
            config = json.load(f)
            logging.info("Configuration loaded.")
            return config
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Error loading config file: {e}")
            return {}
        except Exception as e:
           logging.error(f"Unexpected error loading config file: {e}")
           return {}

    def create_default_config(self):
        """Creates a sample config file."""
        default_config = {
            "suspicious_process_names": ["keylogger.exe", "logger.exe"],
            "suspicious_process_paths": ["C:\\Windows\\Temp", "C:\\ProgramData"],
            "suspicious_file_names": ["keylog.dll", "hook.dll"],
             "suspicious_file_locations": [
                 os.path.expanduser("~\\AppData\\Roaming"),
                  os.path.expanduser("~\\AppData\\Local"),
                "C:\\Windows\\System32",
                "C:\\Windows"
              ],
            "suspicious_registry_keys": [r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"]
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
                logging.info(f"Created default config at '{self.config_file}'")
        except Exception as e:
            logging.error(f"Error creating default config: {e}")

class KeyloggerDetector(ABC):
    """Abstract base class for Keylogger Detectors."""

    def __init__(self, config_manager):
      """Initialize with config manager."""
      self.config_manager = config_manager
      self.suspicious_processes = 0
      self.suspicious_hooks = 0
      self.suspicious_files = 0
      self.suspicious_registry = 0
    @abstractmethod
    def detect(self):
        """Abstract method to detect keyloggers."""
        pass
    def _check_for_suspicious_process_name(self, process):
        """Check if process name is in list of suspicious names."""
        return process.name() in self.config_manager.config.get("suspicious_process_names", [])

    def _check_for_suspicious_process_path(self, process):
        """Check if process path is in list of suspicious paths."""
        try:
            return any(path in process.exe() for path in self.config_manager.config.get("suspicious_process_paths", []))
        except:
            return False
    def _check_for_suspicious_file_name(self, file_path):
       """Check if the file path matches a suspicious file name."""
       return any(file_path.endswith(file) for file in self.config_manager.config.get("suspicious_file_names",[]))

    def _check_for_suspicious_registry_key(self, key):
        """Check if the key is in the list of suspicious registry keys"""
        return any(key in key_name for key_name in self.config_manager.config.get("suspicious_registry_keys", []))
    def _print_scan_results(self):
      """Prints a summary of scan results."""
      logging.info("Printing scan results")
      print("--------------------------")
      print("Scan Summary:")
      print(f"Suspicious processes found: {self.suspicious_processes}")
      print(f"Suspicious low-level keyboard hooks: {self.suspicious_hooks}")
      print(f"Suspicious files found: {self.suspicious_files}")
      print(f"Suspicious registry entries: {self.suspicious_registry}")
      total_suspicious = self.suspicious_processes + self.suspicious_files + self.suspicious_hooks + self.suspicious_registry
      print(f"Total suspicious activities found: {total_suspicious}")
      print("--------------------------")

class WindowsKeyloggerDetector(KeyloggerDetector):
    """Windows implementation for a keylogger detector."""
    def __init__(self, config_manager):
        """Initialise with config manager."""
        super().__init__(config_manager)
        self.hook_handle = None

    def detect(self):
        """Detects keylogging activity in Windows."""
        logging.info("Starting keylogger detection in Windows...")
        self.suspicious_processes = 0
        self.suspicious_hooks = 0
        self.suspicious_files = 0
        self.suspicious_registry = 0

        # Process enumeration
        for process in psutil.process_iter(['name', 'exe', 'cmdline']):
            if self._check_for_suspicious_process_name(process):
                logging.warning(f"Suspicious process name detected: {process.info['name']} (PID: {process.pid})")
                self.suspicious_processes += 1
            if self._check_for_suspicious_process_path(process):
                logging.warning(f"Suspicious process path detected: {process.info['exe']} (PID: {process.pid})")
                self.suspicious_processes += 1
            if self._check_for_suspicious_process_cmdline(process):
              logging.warning(f"Suspicious process cmdline detected: {process.info['cmdline']} (PID: {process.pid})")
              self.suspicious_processes += 1
        self._detect_windows_hooks()
        self._check_windows_startup_folders()
        self._check_registry()
        logging.info("Finished keylogger detection in Windows.")
        self._print_scan_results()

    def _check_for_suspicious_process_cmdline(self, process):
        """Check if the process cmdline has any suspicious command line arguments."""
        try:
           cmdline = process.cmdline()
           if cmdline and any(arg in cmd for arg in ["-keylog", "--keylog", "-log", "--log"] for cmd in cmdline):
            return True
        except:
           return False

    def _detect_windows_hooks(self):
        """Detects windows hooks."""
        logging.info("Checking for windows hooks")
        user32 = ctypes.windll.user32
        thread_id = 0
        hook_type = win32con.WH_KEYBOARD_LL
        try:
            def hook_proc(n_code, w_param, l_param):
                  return win32api.CallNextHookEx(None, n_code, w_param, l_param)
            HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
            callback = HOOKPROC(hook_proc)
            hook_handle = user32.SetWindowsHookExW(hook_type, callback, 0, thread_id)
            if hook_handle:
                logging.warning(f"Suspicious low level keyboard hook detected.")
                self.suspicious_hooks+=1
                thread_id, process_id = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
                try:
                    process = psutil.Process(process_id)
                    logging.warning(f"Process ID: {process_id}, name: {process.name()}, path: {process.exe()}")
                except:
                     logging.warning(f"Could not get process information for {process_id}")

            else:
                logging.info("No suspicious keyboard hook detected")
        except Exception as e:
           logging.error(f"Error when checking for windows hooks: {e}")
        finally:
            if self.hook_handle:
                user32.UnhookWindowsHookEx(self.hook_handle)

    def _check_windows_startup_folders(self):
        """Checks for suspicious files in common startup folders."""
        logging.info("Checking Windows startup folders")
        for location in self.config_manager.config.get("suspicious_file_locations",[]):
            try:
              logging.info(f"Checking folder {location}")
              if os.path.isdir(location):
                  for filename in os.listdir(location):
                      full_path = os.path.join(location,filename)
                      if os.path.isfile(full_path):
                          if self._check_for_suspicious_file_name(full_path):
                            logging.warning(f"Suspicious file found: {full_path}")
                            self.suspicious_files+=1
                          if self._check_file_content(full_path):
                                logging.warning(f"Suspicious content found at: {full_path}")
                                self.suspicious_files +=1
                  hidden_files = self._check_hidden_files(location)
                  if hidden_files:
                     logging.warning(f"Suspicious hidden files found {', '.join(hidden_files)} at location: {location}")
                     self.suspicious_files += len(hidden_files)
            except Exception as e:
              logging.error(f"Error checking startup folder: {e}")

    def _check_file_content(self, file_path):
        """Check the content of a file for suspicious keywords"""
        try:
            with open(file_path, "r") as f:
                content = f.read().lower()
                return any(keyword in content for keyword in ["keylog","hook","logger","keyboard"])
        except:
            return False
    def _check_hidden_files(self, location):
        """Check for hidden files in a directory using the command line."""
        try:
           command = f'dir /a:h /b "{location}"'
           result = subprocess.run(command, shell=True, capture_output=True, text=True, check = False)
           if result.returncode == 0:
              output = result.stdout.strip()
              if output:
                   return output.split("\n")
           return []
        except:
          return []

    def _check_registry(self):
      """Checks for suspicious keys in the registry."""
      logging.info("Checking registry for suspicious entries")
      try:
        for key_path in self.config_manager.config.get("suspicious_registry_keys",[]):
             try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
                logging.info(f"Checking registry key: {key_path}")
                index = 0
                while True:
                   try:
                       name, value, value_type = winreg.EnumValue(key, index)
                       if isinstance(value,str) and any(keyword in value.lower() for keyword in ["keylog", "hook", "logger"]):
                           logging.warning(f"Suspicious value found at key: {key_path}, name: {name}, value: {value}")
                           self.suspicious_registry += 1
                       index+=1
                   except OSError:
                     break
             except FileNotFoundError:
                logging.info(f"Key not found: {key_path}")
             except Exception as e:
                logging.error(f"Error checking registry key {key_path}: {e}")
      except Exception as e:
         logging.error(f"Error accessing registry: {e}")

class LinuxKeyloggerDetector(KeyloggerDetector):
    """Linux implementation for a keylogger detector."""
    def __init__(self, config_manager):
      """Initialise with config manager."""
      super().__init__(config_manager)
    def detect(self):
        """Detects keylogging activity in Linux."""
        logging.info("Starting keylogger detection in Linux...")
        # TODO Implement keylogger detection in linux using the correct linux libraries.
        logging.info("Finished keylogger detection in Linux.")

def create_keylogger_detector(config_manager):
    """Creates a keylogger detector based on the OS."""
    system = platform.system()
    if system == "Windows":
      return WindowsKeyloggerDetector(config_manager)
    elif system == "Linux":
      return LinuxKeyloggerDetector(config_manager)
    else:
      logging.error(f"Unsupported system: {system}")
      return None

def main():
    """Main entry point of the application."""
    parser = argparse.ArgumentParser(description="Keylogger Detector")
    parser.add_argument("-c", "--create_config", action="store_true", help="Create the config file.")
    parser.add_argument("-s", "--scan", action="store_true", help="Start the keylogger scan.")
    args = parser.parse_args()

    config_manager = ConfigManager()
    if args.create_config:
        config_manager.create_default_config()
    elif config_manager.config:
      detector = create_keylogger_detector(config_manager)
      if detector:
          if args.scan:
            detector.detect()
          else:
              print("Use -s to start scanning.")
      else:
        logging.error("Could not create monitor for the current OS.")
    else:
       logging.error("No configuration file found. Use -c to create one.")

if __name__ == "__main__":
    main()
