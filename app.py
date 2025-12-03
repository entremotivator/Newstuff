"""
WordPress Management Pro - Ultimate Edition
Complete WordPress management with 20i API & cPanel support
Features: Restore, Backup, File Edit, Database, Domains, SSL, Email,
          Security Scanner, Performance, Migration, Logs & more.
"""

import base64
import hashlib
import json
import random
import re
import string
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

# =========================================================
# Constants & Configuration
# =========================================================
DEFAULT_20I_BASE_URL = "https://api.20i.com"
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_DOCROOT_TEMPLATE = "/home/stackcp/{domain}/public_html"
SPECIAL_CHARS = "!@#$%^&*"
API_TIMEOUT = 30

MAIN_TABS = [
    "Dashboard",
    "Restore",
    "Backup Manager",
    "File Editor",
    "Database Manager",
    "Domain Manager",
    "SSL Manager",
    "Email Manager",
    "Security Scanner",
    "Performance",
    "Migration Tool",
    "Cron Jobs",
    "Logs Viewer",
    "FTP/SFTP",
    "Settings",
]

RESTORE_STEPS = [
    "Select Package / Domain",
    "Upload ZIP Backup",
    "Document Root",
    "Database Setup",
    "Restore Plan",
]

FILE_SYNTAX_MAP = {
    ".php": "php",
    ".js": "javascript",
    ".css": "css",
    ".html": "html",
    ".json": "json",
    ".xml": "xml",
    ".sql": "sql",
    ".py": "python",
    ".sh": "bash",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".md": "markdown",
    ".txt": "text",
    ".htaccess": "apache",
    ".conf": "nginx",
}

SECURITY_PATTERNS = {
    "malicious_functions": [
        r"eval\s*\(",
        r"base64_decode\s*\(",
        r"system\s*\(",
        r"exec\s*\(",
        r"passthru\s*\(",
        r"shell_exec\s*\(",
        r"assert\s*\(",
        r"preg_replace.*\/e",
        r"create_function\s*\(",
    ],
    "backdoor_patterns": [
        r"c99",
        r"r57",
        r"FilesMan",
        r"@include.*\$_",
        r"@require.*\$_",
    ],
    "sql_injection": [
        r"\$_(GET|POST|REQUEST|COOKIE)\[.*\].*\s+(SELECT|INSERT|UPDATE|DELETE)",
        r"mysql_query.*\$_(GET|POST|REQUEST)",
    ],
}

# =========================================================
# Helper Functions
# =========================================================
def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def b64decode(s: str) -> str:
    return base64.b64decode(s.encode("ascii")).decode("utf-8")


def make_20i_bearer(api_key: str) -> str:
    return f"Bearer {b64(api_key.strip())}"


def generate_strong_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    chars = string.ascii_letters + string.digits + SPECIAL_CHARS
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(SPECIAL_CHARS),
    ]
    password += [random.choice(chars) for _ in range(length - 4)]
    random.shuffle(password)
    return "".join(password)


def normalize_domain_name(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9.-]", "", name)
    name = re.sub(r"-{2,}", "-", name)
    name = re.sub(r"\.{2,}", ".", name)
    return name.strip(".-") or "default-site"


def format_timestamp(ts: Optional[str]) -> str:
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts[:16] if ts else "N/A"


def format_file_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def get_file_syntax(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return FILE_SYNTAX_MAP.get(ext, "text")


def extract_wp_config_values(content: str) -> Dict[str, str]:
    patterns = {
        "DB_NAME": r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_USER": r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_PASSWORD": r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        "DB_HOST": r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    }
    values: Dict[str, str] = {}
    for key, pattern in patterns.items():
        m = re.search(pattern, content)
        if m:
            values[key] = m.group(1)
    return values


def calculate_file_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def scan_file_for_malware(content: str, filename: str) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    for category, patterns in SECURITY_PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                issues.append(
                    {
                        "file": filename,
                        "line": line_num,
                        "category": category,
                        "pattern": pattern,
                        "match": match.group(0),
                    }
                )
    return issues


# =========================================================
# 20i API Client
# =========================================================
class TwentyIClient:
    def __init__(self, api_key: str, base_url: str = DEFAULT_20I_BASE_URL) -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": make_20i_bearer(self.api_key),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _request(
        self, path: str, method: str = "GET", data: Optional[Dict] = None
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(method, url, json=data, timeout=API_TIMEOUT)
            resp.raise_for_status()
            return resp.json() if resp.text else {}
        except requests.exceptions.RequestException as e:
            raise Exception(f"20i API error [{method} {path}]: {e}")

    # Packages
    def list_packages(self) -> Dict[str, Any]:
        raw = self._request("/package")
        return {"packages": raw} if isinstance(raw, list) else raw

    def get_package(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}")

    def get_package_resources(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/resources")

    # Domains
    def list_domains(self) -> Dict[str, Any]:
        raw = self._request("/domain")
        return {"domains": raw} if isinstance(raw, list) else raw

    def add_domain_to_package(
        self, pkg_id: str, domain: str, docroot: str = ""
    ) -> Dict[str, Any]:
        payload = {
            "domain_name": domain,
            "document_root": docroot or f"/home/stackcp/{domain}/public_html",
        }
        return self._request(f"/package/{pkg_id}/addDomain", "POST", payload)

    def remove_domain_from_package(self, pkg_id: str, domain: str) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/removeDomain", "POST", {"domain_name": domain}
        )

    # Databases
    def list_databases(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/databases")

    def create_database(self, pkg_id: str, db_name: str) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/database", "POST", {"database_name": db_name}
        )

    def delete_database(self, pkg_id: str, db_name: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/database/{db_name}", "DELETE")

    def create_database_user(
        self, pkg_id: str, username: str, password: str
    ) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/databaseUser",
            "POST",
            {"username": username, "password": password},
        )

    def grant_database_access(
        self, pkg_id: str, db_name: str, username: str
    ) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/databaseAccess",
            "POST",
            {"database_name": db_name, "username": username},
        )

    # SSL
    def list_ssl_certificates(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/ssl")

    def install_free_ssl(self, pkg_id: str, domain: str) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/ssl/free", "POST", {"domain": domain}
        )

    # Email
    def list_email_accounts(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/email")

    def create_email_account(
        self, pkg_id: str, email: str, password: str, quota_mb: int = 1000
    ) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/email",
            "POST",
            {"email": email, "password": password, "quota": quota_mb},
        )

    def delete_email_account(self, pkg_id: str, email: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/email/{email}", "DELETE")

    # Backups
    def list_backups(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/backups")

    def create_backup(self, pkg_id: str, backup_name: str) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/backup", "POST", {"name": backup_name}
        )

    def download_backup(self, pkg_id: str, backup_id: str) -> bytes:
        url = f"{self.base_url}/package/{pkg_id}/backup/{backup_id}/download"
        resp = self.session.get(url, timeout=API_TIMEOUT)
        resp.raise_for_status()
        return resp.content

    def restore_backup(self, pkg_id: str, backup_id: str) -> Dict[str, Any]:
        return self._request(
            f"/package/{pkg_id}/backup/{backup_id}/restore", "POST"
        )

    # Utility
    @staticmethod
    def build_domain_choices(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        choices: List[Dict[str, Any]] = []
        for pkg in raw.get("packages", []):
            if not isinstance(pkg, dict):
                continue
            pkg_id = str(pkg.get("id", ""))
            pkg_name = pkg.get("label", f"Package {pkg_id}")
            for domain in pkg.get("names", []):
                if isinstance(domain, str):
                    choices.append(
                        {
                            "label": f"{domain} ({pkg_name})",
                            "domain": domain,
                            "package_id": pkg_id,
                            "package_label": pkg_name,
                        }
                    )
        return sorted(choices, key=lambda c: c["domain"])

    def get_account_info(self) -> Dict[str, Any]:
        return self._request("/account")


# =========================================================
# cPanel API Client
# =========================================================
class CPanelClient:
    def __init__(
        self, cpanel_url: str, username: str, password: str = "", api_token: str = ""
    ) -> None:
        self.cpanel_url = cpanel_url.rstrip("/")
        if not self.cpanel_url.startswith(("http://", "https://")):
            self.cpanel_url = f"https://{self.cpanel_url}"

        parts = self.cpanel_url.split("/")
        if len(parts) > 3:
            self.cpanel_url = "/".join(parts[:3])

        if ":2083" not in self.cpanel_url and ":2082" not in self.cpanel_url:
            self.cpanel_url = self.cpanel_url.rstrip("/") + ":2083"

        self.username = username
        self.password = password
        self.api_token = api_token

        if api_token:
            self.headers = {
                "Authorization": f"cpanel {username}:{api_token}",
                "Content-Type": "application/json",
            }
            self.auth = None
        else:
            self.headers = {"Content-Type": "application/json"}
            self.auth = (username, password)

        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _request(self, module: str, function: str, params: Dict = None) -> Any:
        url = f"{self.cpanel_url}/execute/{module}/{function}"
        try:
            resp = self.session.get(
                url,
                params=params or {},
                auth=self.auth,
                timeout=API_TIMEOUT,
                verify=False,  # self-signed common
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and data.get("status") == 0:
                msg = data.get("errors", ["Unknown error"])[0]
                raise Exception(f"cPanel API error: {msg}")
            return data
        except requests.exceptions.RequestException as e:
            raise Exception(f"cPanel API request failed: {e}")

    # Domains
    def list_domains(self) -> List[str]:
        result = self._request("DomainInfo", "list_domains")
        if result.get("status") == 1:
            return [
                d.get("domain")
                for d in result.get("data", [])
                if isinstance(d, dict) and d.get("domain")
            ]
        return []

    def add_addon_domain(self, domain: str, subdomain: str, docroot: str) -> Dict:
        return self._request(
            "AddonDomain",
            "addaddondomain",
            {"domain": domain, "subdomain": subdomain, "dir": docroot},
        )

    def remove_addon_domain(self, domain: str) -> Dict:
        return self._request("AddonDomain", "deladdondomain", {"domain": domain})

    # Databases
    def list_databases(self) -> List[str]:
        result = self._request("Mysql", "list_databases")
        if result.get("status") == 1:
            return [db.get("database") for db in result.get("data", []) if db]
        return []

    def create_database(self, name: str) -> Dict:
        return self._request("Mysql", "create_database", {"name": name})

    def delete_database(self, name: str) -> Dict:
        return self._request("Mysql", "delete_database", {"name": name})

    def create_database_user(self, username: str, password: str) -> Dict:
        return self._request(
            "Mysql", "create_user", {"name": username, "password": password}
        )

    def grant_database_privileges(self, user: str, db: str) -> Dict:
        return self._request(
            "Mysql",
            "set_privileges_on_database",
            {"user": user, "database": db, "privileges": "ALL PRIVILEGES"},
        )

    # Files
    def list_files(self, directory: str = "/public_html") -> List[Dict[str, Any]]:
        result = self._request("Fileman", "list_files", {"dir": directory})
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def read_file(self, path: str) -> str:
        result = self._request("Fileman", "get_file_content", {"path": path})
        if result.get("status") == 1:
            return result.get("data", {}).get("content", "")
        return ""

    def write_file(self, path: str, content: str) -> Dict:
        return self._request(
            "Fileman", "save_file_content", {"path": path, "content": content}
        )

    def delete_file(self, path: str) -> Dict:
        return self._request("Fileman", "delete_files", {"files": path})

    # SSL
    def list_ssl_certificates(self) -> List[Dict[str, Any]]:
        result = self._request("SSL", "list_certs")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def install_ssl_certificate(
        self, domain: str, cert: str, key: str, cabundle: str = ""
    ) -> Dict:
        params = {"domain": domain, "cert": cert, "key": key}
        if cabundle:
            params["cabundle"] = cabundle
        return self._request("SSL", "install_ssl", params)

    # Email
    def list_email_accounts(self) -> List[Dict[str, Any]]:
        result = self._request("Email", "list_pops")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def create_email_account(
        self, email: str, password: str, quota: int = 250
    ) -> Dict:
        local, domain = email.split("@", 1)
        params = {
            "email": local,
            "domain": domain,
            "password": password,
            "quota": quota,
        }
        return self._request("Email", "add_pop", params)

    def delete_email_account(self, email: str) -> Dict:
        local, domain = email.split("@", 1)
        return self._request(
            "Email", "delete_pop", {"email": local, "domain": domain}
        )

    # Backups
    def create_backup(self) -> Dict:
        return self._request("Backup", "fullbackup_to_homedir")

    def list_backups(self) -> List[Dict[str, Any]]:
        result = self._request("Backup", "list_backups")
        if result.get("status") == 1:
            return result.get("data", [])
        return []


# =========================================================
# Session State Management
# =========================================================
def init_session_state() -> None:
    defaults = {
        "api_type": "20i",
        "twentyi_client": None,
        "cpanel_client": None,
        "connected": False,
        "account_info": None,
        "packages_raw": None,
        "domain_choices": [],
        "selected_package": None,
        "selected_domain": "",
        "all_domains": [],
        # Restore
        "docroot": "",
        "upload_filename": "",
        "uploaded_zip": None,
        "db_details": {},
        "restore_step": 0,
        # File manager
        "current_directory": "/public_html",
        "file_list": [],
        "selected_file": None,
        "file_content": "",
        # DB manager
        "db_list": [],
        # Security
        "scan_results": [],
        "last_scan": None,
        # Backups
        "backup_list": [],
        # UI
        "current_tab": 0,
        "debug_mode": False,
        "last_error": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def get_client():
    return (
        st.session_state.twentyi_client
        if st.session_state.api_type == "20i"
        else st.session_state.cpanel_client
    )


# =========================================================
# Sidebar: API Connection
# =========================================================
def render_sidebar() -> None:
    st.header("API Connection")

    api_type_choice = st.radio(
        "Select API Type",
        ["20i", "cPanel"],
        horizontal=True,
    )
    st.session_state.api_type = "20i" if api_type_choice == "20i" else "cpanel"

    st.divider()
    if api_type_choice == "20i":
        render_20i_auth()
    else:
        render_cpanel_auth()

    if st.session_state.connected:
        st.success("Connected")
        if st.session_state.account_info:
            with st.expander("Account Info"):
                st.json(st.session_state.account_info)

    st.divider()
    st.session_state.debug_mode = st.checkbox(
        "Debug Mode", value=st.session_state.debug_mode
    )


def render_20i_auth() -> None:
    st.subheader("20i API")
    api_key = st.text_input("20i General API Key", type="password")

    if st.button("Connect to 20i", use_container_width=True):
        if not api_key:
            st.error("Please enter your 20i API key.")
            return
        try:
            with st.spinner("Connecting to 20i..."):
                client = TwentyIClient(api_key)
                st.session_state.twentyi_client = client
                st.session_state.packages_raw = client.list_packages()
                st.session_state.domain_choices = TwentyIClient.build_domain_choices(
                    st.session_state.packages_raw
                )
                try:
                    st.session_state.account_info = client.get_account_info()
                except Exception as e:
                    st.warning(f"Could not fetch account info: {e}")
                    st.session_state.account_info = {"error": str(e)}
                st.session_state.connected = True
                st.success(
                    f"Connected to 20i. Found {len(st.session_state.domain_choices)} sites."
                )
                st.rerun()
        except Exception as e:
            st.error(f"Connection failed: {e}")
            st.session_state.connected = False


def render_cpanel_auth() -> None:
    st.subheader("cPanel API")

    cpanel_url = st.text_input("cPanel URL", placeholder="https://yourdomain.com:2083")
    username = st.text_input("Username")
    auth_method = st.radio("Auth Method", ["Password", "API Token"], horizontal=True)

    if auth_method == "Password":
        password = st.text_input("Password", type="password")
        api_token = ""
    else:
        password = ""
        api_token = st.text_input("API Token", type="password")

    if st.button("Connect to cPanel", use_container_width=True):
        if not cpanel_url or not username or not (password or api_token):
            st.error("Please fill in all required fields.")
            return
        try:
            with st.spinner("Connecting to cPanel..."):
                client = CPanelClient(cpanel_url, username, password, api_token)
                st.session_state.cpanel_client = client
                st.session_state.all_domains = client.list_domains()
                st.session_state.account_info = {
                    "username": username,
                    "cpanel_url": cpanel_url,
                    "domains_found": len(st.session_state.all_domains),
                }
                st.session_state.connected = True
                st.success(
                    f"Connected to cPanel. Found {len(st.session_state.all_domains)} domains."
                )
                st.rerun()
        except Exception as e:
            st.error(f"Connection failed: {e}")
            st.session_state.connected = False


# =========================================================
# Tab: Dashboard
# =========================================================
def render_dashboard_tab() -> None:
    st.header("Dashboard")

    if not st.session_state.connected:
        st.info("Connect via the sidebar to see your dashboard overview.")
        return

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total_sites = (
            len(st.session_state.domain_choices)
            if st.session_state.api_type == "20i"
            else len(st.session_state.all_domains)
        )
        st.metric("Total Sites", total_sites)

    with col2:
        st.metric("Databases", len(st.session_state.db_list))

    with col3:
        st.metric("Backups", len(st.session_state.backup_list))

    with col4:
        issues = len(st.session_state.scan_results)
        st.metric("Security Issues", issues)

    st.divider()
    st.subheader("Quick Actions")

    qc1, qc2, qc3 = st.columns(3)
    with qc1:
        if st.button("New Backup", use_container_width=True):
            st.session_state.current_tab = MAIN_TABS.index("Backup Manager")
            st.experimental_rerun()
    with qc2:
        if st.button("Restore Wizard", use_container_width=True):
            st.session_state.current_tab = MAIN_TABS.index("Restore")
            st.experimental_rerun()
    with qc3:
        if st.button("Security Scan", use_container_width=True):
            st.session_state.current_tab = MAIN_TABS.index("Security Scanner")
            st.rerun()


# =========================================================
# Tab: Restore Wizard
# =========================================================
def render_restore_tab() -> None:
    st.header("WordPress Restore Wizard")

    if not st.session_state.connected:
        st.info("Connect via the sidebar first.")
        return

    step = st.session_state.restore_step
    progress = (step + 1) / len(RESTORE_STEPS)
    st.progress(progress)
    st.caption(f"Step {step + 1} of {len(RESTORE_STEPS)}: {RESTORE_STEPS[step]}")
    st.divider()

    if step == 0:
        restore_step_1()
    elif step == 1:
        restore_step_2()
    elif step == 2:
        restore_step_3()
    elif step == 3:
        restore_step_4()
    elif step == 4:
        restore_step_5()


def restore_step_1() -> None:
    st.subheader("Select Package / Domain")

    if st.session_state.api_type == "20i":
        if not st.session_state.domain_choices:
            st.warning("No 20i packages/domains found.")
            return

        labels = [d["label"] for d in st.session_state.domain_choices]
        default_idx = 0
        if st.session_state.selected_domain:
            for i, d in enumerate(st.session_state.domain_choices):
                if d["domain"] == st.session_state.selected_domain:
                    default_idx = i
                    break

        idx = st.selectbox("Select Site", range(len(labels)), format_func=lambda i: labels[i], index=default_idx)
        selected = st.session_state.domain_choices[idx]
        st.session_state.selected_package = selected
        st.session_state.selected_domain = selected["domain"]
    else:
        if not st.session_state.all_domains:
            st.warning("No cPanel domains found.")
            return
        default_idx = (
            st.session_state.all_domains.index(st.session_state.selected_domain)
            if st.session_state.selected_domain in st.session_state.all_domains
            else 0
        )
        domain = st.selectbox(
            "Select Domain",
            st.session_state.all_domains,
            index=default_idx,
        )
        st.session_state.selected_domain = domain

    st.info(f"Selected: {st.session_state.selected_domain or 'None'}")

    if st.button("Next", use_container_width=True):
        st.session_state.restore_step = 1
        st.rerun()


def restore_step_2() -> None:
    st.subheader("Upload WordPress Backup ZIP")

    uploaded = st.file_uploader("Upload ZIP file", type="zip")
    if uploaded:
        st.session_state.upload_filename = uploaded.name
        st.session_state.uploaded_zip = BytesIO(uploaded.read())

        try:
            with zipfile.ZipFile(st.session_state.uploaded_zip) as zf:
                files = zf.namelist()
                st.success(f"Valid ZIP: {len(files)} files.")
                wp_files = [
                    f
                    for f in files
                    if "wp-config.php" in f or f.startswith("wp-")
                ]
                if wp_files:
                    st.info(f"Detected {len(wp_files)} WordPress-related files.")
        except Exception:
            st.error("Invalid ZIP file.")
            return

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 0
            st.experimental_rerun()
    with col2:
        if (uploaded or st.session_state.uploaded_zip) and st.button(
            "Next", use_container_width=True
        ):
            st.session_state.restore_step = 2
            st.experimental_rerun()


def restore_step_3() -> None:
    st.subheader("Document Root Path")

    domain = st.session_state.selected_domain or "example.com"
    default_path = DEFAULT_DOCROOT_TEMPLATE.format(domain=domain)
    st.session_state.docroot = st.text_input(
        "Document Root",
        value=st.session_state.docroot or default_path,
    )
    st.info(f"Files will be extracted to: {st.session_state.docroot}")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 1
            st.experimental_rerun()
    with col2:
        if st.button("Next", use_container_width=True):
            st.session_state.restore_step = 3
            st.experimental_rerun()


def restore_step_4() -> None:
    st.subheader("Database Setup")

    if not st.session_state.db_details:
        domain = st.session_state.selected_domain or "site"
        base = normalize_domain_name(domain.split(".")[0])
        st.session_state.db_details = {
            "name": f"{base}_wp",
            "user": f"{base}_user",
            "password": generate_strong_password(),
            "host": "localhost",
            "created": False,
        }

    db = st.session_state.db_details

    c1, c2 = st.columns(2)
    with c1:
        db["name"] = st.text_input("Database Name", value=db["name"])
        db["user"] = st.text_input("Database User", value=db["user"])
    with c2:
        db["password"] = st.text_input(
            "Database Password", value=db["password"], type="password"
        )
        db["host"] = st.text_input("Database Host", value=db["host"])

    st.divider()

    if st.button("Auto-Create Database", use_container_width=True):
        try:
            client = get_client()
            if st.session_state.api_type == "20i":
                if not st.session_state.selected_package:
                    st.error(
                        "Select a package/domain in Step 1 before auto-creating the database."
                    )
                    return
                pkg_id = st.session_state.selected_package["package_id"]
                client.create_database(pkg_id, db["name"])
                client.create_database_user(pkg_id, db["user"], db["password"])
                client.grant_database_access(pkg_id, db["name"], db["user"])
            else:
                client.create_database(db["name"])
                client.create_database_user(db["user"], db["password"])
                client.grant_database_privileges(db["user"], db["name"])

            db["created"] = True
            st.session_state.db_details = db
            st.success("Database and user created successfully.")
        except Exception as e:
            st.error(f"Failed to create database: {e}")

    st.divider()
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 2
            st.experimental_rerun()
    with c2:
        if st.button("Next", use_container_width=True):
            st.session_state.restore_step = 4
            st.experimental_rerun()


def restore_step_5() -> None:
    st.subheader("Restore Plan & Commands")

    domain = st.session_state.selected_domain or "example.com"
    docroot = st.session_state.docroot
    filename = st.session_state.upload_filename
    db = st.session_state.db_details

    tab1, tab2, tab3 = st.tabs(["Manual Steps", "Automation Script", "Checklist"])

    with tab1:
        st.markdown("### 1. Upload & Extract Files")
        st.code(
            f"""# Upload {filename} to your server (SFTP/FTP) under {docroot}
cd {docroot}
unzip {filename}
rm {filename}
""",
            language="bash",
        )

        st.markdown("### 2. Secure Permissions")
        st.code(
            """find . -type d -exec chmod 755 {} \\;
find . -type f -exec chmod 644 {} \\;
[ -f wp-config.php ] && chmod 600 wp-config.php
""",
            language="bash",
        )

        st.markdown("### 3. Update wp-config.php")
        st.code(
            f"""define('DB_NAME', '{db["name"]}');
define('DB_USER', '{db["user"]}');
define('DB_PASSWORD', '{db["password"]}');
define('DB_HOST', '{db["host"]}');
""",
            language="php",
        )

        st.markdown("### 4. Import Database & Fix URLs")
        st.code(
            f"""mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} < backup.sql

mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} << EOF
UPDATE wp_options SET option_value = 'https://{domain}'
  WHERE option_name IN ('siteurl', 'home');
EOF
""",
            language="bash",
        )

    with tab2:
        st.markdown("### Single Restore Script")
        script = f"""#!/bin/bash
set -e

DOMAIN="{domain}"
DOCROOT="{docroot}"
BACKUP_ZIP="{filename}"
DB_NAME="{db['name']}"
DB_USER="{db['user']}"
DB_PASS="{db['password']}"
DB_HOST="{db['host']}"

cd "$DOCROOT"
unzip -q "$BACKUP_ZIP"
rm "$BACKUP_ZIP"

find . -type d -exec chmod 755 {{}} \\;
find . -type f -exec chmod 644 {{}} \\;
[ -f wp-config.php ] && chmod 600 wp-config.php

sed -i "s/define('DB_NAME'.*/define('DB_NAME', '$DB_NAME');/" wp-config.php || true
sed -i "s/define('DB_USER'.*/define('DB_USER', '$DB_USER');/" wp-config.php || true
sed -i "s/define('DB_PASSWORD'.*/define('DB_PASSWORD', '$DB_PASS');/" wp-config.php || true
sed -i "s/define('DB_HOST'.*/define('DB_HOST', '$DB_HOST');/" wp-config.php || true

SQL_FILE=$(find . -maxdepth 2 -name "*.sql" -type f | head -n 1)
if [ -n "$SQL_FILE" ]; then
  mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" < "$SQL_FILE"
fi

mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" <<EOF
UPDATE wp_options SET option_value = 'https://$DOMAIN'
  WHERE option_name IN ('siteurl', 'home');
EOF

echo "Restore complete: https://$DOMAIN"
"""
        st.code(script, language="bash")
        st.download_button(
            "Download Script",
            data=script,
            file_name=f"restore_{domain.replace('.', '_')}.sh",
            mime="text/x-shellscript",
            use_container_width=True,
        )

    with tab3:
        st.markdown("### Post-Restore Checklist")
        checks = [
            "Homepage loads without fatal errors",
            "Admin login (/wp-admin) works",
            "Permalinks work (no 404s)",
            "Media library shows images",
            "Contact forms send emails",
            "SSL is valid / no mixed content",
        ]
        for c in checks:
            st.checkbox(c, key=f"restore_check_{hash(c)}")

    st.divider()
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 3
            st.experimental_rerun()
    with c2:
        if st.button("Start Over", use_container_width=True):
            st.session_state.restore_step = 0
            st.session_state.uploaded_zip = None
            st.session_state.db_details = {}
            st.experimental_rerun()


# =========================================================
# Tab: Backup Manager
# =========================================================
def render_backup_manager_tab() -> None:
    st.header("Backup Manager")

    if not st.session_state.connected:
        st.info("Connect via the sidebar first.")
        return

    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        backup_name = st.text_input(
            "Backup Name",
            placeholder="backup_YYYY_MM_DD",
        )
    with c2:
        if st.button("Create Backup", use_container_width=True):
            try:
                client = get_client()
                if st.session_state.api_type == "20i":
                    if not st.session_state.selected_package:
                        st.error(
                            "For 20i, select a package/domain in the Restore wizard first."
                        )
                        return
                    pkg_id = st.session_state.selected_package["package_id"]
                    client.create_backup(pkg_id, backup_name or "manual_backup")
                else:
                    client.create_backup()
                st.success("Backup creation triggered successfully.")
            except Exception as e:
                st.error(f"Failed to create backup: {e}")
    with c3:
        if st.button("Refresh List", use_container_width=True):
            st.rerun()

    st.divider()
    st.subheader("Existing Backups")

    try:
        client = get_client()
        backups: List[Any] = []
        pkg_id = None
        if st.session_state.api_type == "20i":
            if st.session_state.selected_package:
                pkg_id = st.session_state.selected_package["package_id"]
                resp = client.list_backups(pkg_id)
                backups = resp.get("backups", [])
        else:
            backups = client.list_backups()

        st.session_state.backup_list = backups

        if not backups:
            st.info("No backups found.")
            return

        for b in backups:
            name = b.get("name", "backup")
            with st.expander(name):
                col_i, col_a = st.columns([2, 1])
                with col_i:
                    st.write(f"**Name:** {name}")
                    st.write(f"**Status:** {b.get('status', 'Unknown')}")
                    st.write(
                        f"**Created:** {format_timestamp(b.get('created_at') or b.get('created'))}"
                    )
                    if "size" in b:
                        st.write(f"**Size:** {format_file_size(b.get('size', 0))}")
                with col_a:
                    if st.session_state.api_type == "20i" and pkg_id:
                        bid = b.get("id")
                        if st.button("Restore", key=f"restore_{bid}"):
                            try:
                                client.restore_backup(pkg_id, bid)
                                st.success("Restore initiated.")
                            except Exception as e:
                                st.error(f"Restore failed: {e}")
    except Exception as e:
        st.error(f"Failed to fetch backups: {e}")


# =========================================================
# Tab: File Editor (cPanel only)
# =========================================================
def render_file_editor_tab() -> None:
    st.header("File Editor")

    if not st.session_state.connected:
        st.info("Connect via the sidebar first.")
        return

    if st.session_state.api_type == "20i":
        st.warning(
            "20i REST API does not expose a file manager. Use SFTP / control panel for file edits."
        )
        return

    client = get_client()
    col_b, col_e = st.columns([1, 2])

    with col_b:
        st.subheader("Browser")
        current_dir = st.text_input(
            "Directory", value=st.session_state.current_directory
        )
        st.session_state.current_directory = current_dir

        if st.button("List Files", use_container_width=True):
            try:
                st.session_state.file_list = client.list_files(current_dir)
            except Exception as e:
                st.error(f"Failed to list files: {e}")

        for f in st.session_state.file_list:
            name = f.get("file", f.get("name", ""))
            ftype = f.get("type", "file")
            icon = "📁" if ftype == "dir" else "📄"
            if st.button(f"{icon} {name}", key=f"f_{hash(current_dir + name)}"):
                if ftype == "dir":
                    st.session_state.current_directory = (
                        current_dir.rstrip("/") + "/" + name
                    )
                    st.rerun()
                else:
                    path = current_dir.rstrip("/") + "/" + name
                    st.session_state.selected_file = path
                    try:
                        st.session_state.file_content = client.read_file(path)
                    except Exception as e:
                        st.error(f"Failed to read file: {e}")

    with col_e:
        st.subheader("Editor")
        if not st.session_state.selected_file:
            st.info("Select a file from the browser.")
            return

        st.caption(f"Editing: {st.session_state.selected_file}")
        content = st.text_area(
            "Content",
            value=st.session_state.file_content,
            height=420,
            key="editor_content",
        )

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("Save", use_container_width=True):
                try:
                    client.write_file(st.session_state.selected_file, content)
                    st.session_state.file_content = content
                    st.success("File saved.")
                except Exception as e:
                    st.error(f"Save failed: {e}")
        with c2:
            st.download_button(
                "Download",
                data=content,
                file_name=Path(st.session_state.selected_file).name,
                mime="text/plain",
                use_container_width=True,
            )
        with c3:
            if st.button("Close", use_container_width=True):
                st.session_state.selected_file = None
                st.session_state.file_content = ""
                st.experimental_rerun()

        if "wp-config.php" in st.session_state.selected_file:
            st.markdown("#### wp-config.php Helper")
            extracted = extract_wp_config_values(content)
            if extracted:
                st.json(extracted)


# =========================================================
# Tab: Database Manager
# =========================================================
def render_database_manager_tab() -> None:
    st.header("Database Manager")

    if not st.session_state.connected:
        st.info("Connect via the sidebar first.")
        return

    client = get_client()

    c1, c2 = st.columns([2, 1])
    with c1:
        if st.button("Refresh Databases", use_container_width=True):
            try:
                if st.session_state.api_type == "20i":
                    if not st.session_state.selected_package:
                        st.error(
                            "For 20i, select a package/domain in the Restore wizard first."
                        )
                        return
                    pkg_id = st.session_state.selected_package["package_id"]
                    res = client.list_databases(pkg_id)
                    st.session_state.db_list = res.get("databases", [])
                else:
                    st.session_state.db_list = client.list_databases()
                st.success("Database list refreshed.")
            except Exception as e:
                st.error(f"Failed to list databases: {e}")
    with c2:
        new_db = st.text_input("New DB Name")
        if st.button("Create", use_container_width=True) and new_db:
            try:
                if st.session_state.api_type == "20i":
                    if not st.session_state.selected_package:
                        st.error(
                            "For 20i, select a package/domain in the Restore wizard first."
                        )
                        return
                    pkg_id = st.session_state.selected_package["package_id"]
                    client.create_database(pkg_id, new_db)
                else:
                    client.create_database(new_db)
                st.success(f"Database '{new_db}' created.")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Failed to create DB: {e}")

    st.divider()

    if not st.session_state.db_list:
        st.info("No databases loaded yet. Click 'Refresh Databases'.")
        return

    for db in st.session_state.db_list:
        name = db if isinstance(db, str) else db.get("name", "Unknown")
        with st.expander(f"DB: {name}"):
            col_i, col_a = st.columns([3, 1])
            with col_i:
                st.write(f"**Name:** {name}")
                if isinstance(db, dict) and "size" in db:
                    st.write(f"**Size:** {format_file_size(db['size'])}")
            with col_a:
                if st.button("Delete", key=f"del_{name}"):
                    try:
                        if st.session_state.api_type == "20i":
                            if not st.session_state.selected_package:
                                st.error(
                                    "For 20i, select a package/domain in the Restore wizard first."
                                )
                                return
                            pkg_id = st.session_state.selected_package["package_id"]
                            client.delete_database(pkg_id, name)
                        else:
                            client.delete_database(name)
                        st.success(f"Database '{name}' deleted.")
                        st.experimental_rerun()
                    except Exception as e:
                        st.error(f"Delete failed: {e}")


# =========================================================
# Tab: Domain Manager
# =========================================================
def render_domain_manager_tab() -> None:
    st.header("Domain Manager")

    if not st.session_state.connected:
        st.info("Connect via the sidebar first.")
        return

    client = get_client()

    if st.session_state.api_type == "20i":
        if not st.session_state.packages_raw:
            st.info("Fetch packages from the 20i connection first.")
            return

        st.subheader("Domains by Package")
        for pkg in st.session_state.packages_raw.get("packages", []):
            if not isinstance(pkg, dict):
                continue
            label = pkg.get("label") or f"Package {pkg.get('id')}"
            with st.expander(label):
                for d in pkg.get("names", []):
                    st.write(f"- {d}")

        st.divider()
        st.subheader("Add Domain to Package")
        if not st.session_state.domain_choices:
            st.warning("No packages available.")
            return
        pkg_idx = st.selectbox(
            "Select Package",
            range(len(st.session_state.domain_choices)),
            format_func=lambda i: st.session_state.domain_choices[i]["package_label"]
            + " ("
            + st.session_state.domain_choices[i]["domain"]
            + ")",
        )
        new_domain = st.text_input("New Domain (example.com)")
        docroot = st.text_input(
            "Document Root (optional)",
            placeholder="/home/stackcp/example.com/public_html",
        )
        if st.button("Add Domain", use_container_width=True):
            if not new_domain:
                st.error("Enter a domain name.")
            else:
                try:
                    pkg = st.session_state.domain_choices[pkg_idx]
                    client.add_domain_to_package(
                        pkg["package_id"], new_domain.strip(), docroot.strip()
                    )
                    st.success("Domain added. Refresh packages to see it.")
                except Exception as e:
                    st.error(f"Failed to add domain: {e}")

    else:
        st.subheader("Existing Domains (cPanel)")
        domains = st.session_state.all_domains or client.list_domains()
        st.session_state.all_domains = domains
        if not domains:
            st.info("No domains found.")
        else:
            for d in domains:
                st.write(f"- {d}")

        st.divider()
        st.subheader("Add Addon Domain")
        new_domain = st.text_input("New Domain")
        subdomain = st.text_input("Subdomain", help="e.g. example or client1")
        docroot = st.text_input("Document Root", value="public_html/newsite")
        if st.button("Add Addon Domain", use_container_width=True):
            try:
                client.add_addon_domain(new_domain, subdomain, docroot)
                st.success("Addon domain added.")
            except Exception as e:
                st.error(f"Failed: {e}")


# =========================================================
# Tab: SSL Manager
# =========================================================
def render_ssl_manager_tab() -> None:
    st.header("SSL Manager")

    if not st.session_state.connected:
        st.info("Connect via the sidebar first.")
        return

    client = get_client()

    if st.session_state.api_type == "20i":
        if not st.session_state.selected_package:
            st.info("Select a package/domain in the Restore wizard first.")
            return
        pkg_id = st.session_state.selected_package["package_id"]
        try:
            certs = client.list_ssl_certificates(pkg_id).get("certs", [])
        except Exception as e:
            st.error(f"Failed to list SSL certs: {e}")
            return

        st.subheader("Existing Certificates")
        if not certs:
            st.info("No certificates found.")
        else:
            for c in certs:
                with st.expander(c.get("domain", "Unknown")):
                    st.write(f"**Domain:** {c.get('domain')}")
                    st.write(f"**Status:** {c.get('status', 'Unknown')}")
                    st.write(
                        f"**Expiry:** {format_timestamp(c.get('expires') or c.get('expiry'))}"
                    )

        st.divider()
        st.subheader("Install Free SSL")
        domain = st.text_input("Domain for Free SSL", value=st.session_state.selected_domain)
        if st.button("Install Free SSL", use_container_width=True):
            try:
                client.install_free_ssl(pkg_id, domain)
                st.success("Free SSL installation initiated.")
            except Exception as e:
                st.error(f"Failed: {e}")

    else:
        st.subheader("Existing Certificates (cPanel)")
        try:
            certs = client.list_ssl_certificates()
        except Exception as e:
            st.error(f"Failed to list certs: {e}")
            return
        if not certs:
            st.info("No certificates found.")
        else:
            for c in certs:
                with st.expander(c.get("domains", ["Unknown"])[0]):
                    st.json(c)

        st.divider()
        st.subheader("Install SSL Certificate")
        domain = st.text_input("Domain")
        cert = st.text_area("Certificate (CRT)")
        key = st.text_area("Private Key")
        cab = st.text_area("(Optional) CA Bundle")
        if st.button("Install SSL", use_container_width=True):
            try:
                client.install_ssl_certificate(domain, cert, key, cab)
                st.success("SSL installation requested.")
            except Exception as e:
                st.error(f"Failed: {e}")


# =========================================================
# Tab: Email Manager
# =========================================================
def render_email_manager_tab() -> None:
    st.header("Email Manager")

    if not st.session_state.connected:
        st.info("Connect via the sidebar first.")
        return

    client = get_client()

    if st.session_state.api_type == "20i":
        if not st.session_state.selected_package:
            st.info("Select a package/domain in the Restore wizard first.")
            return
        pkg_id = st.session_state.selected_package["package_id"]
        try:
            emails = client.list_email_accounts(pkg_id).get("emails", [])
        except Exception as e:
            st.error(f"Failed to list accounts: {e}")
            return
    else:
        try:
            emails = client.list_email_accounts()
        except Exception as e:
            st.error(f"Failed to list accounts: {e}")
            return

    st.subheader("Existing Accounts")
    if not emails:
        st.info("No email accounts found.")
    else:
        for acc in emails:
            with st.expander(acc.get("email") or acc.get("user", "account")):
                st.json(acc)

    st.divider()
    st.subheader("Create New Account")

    email = st.text_input("Email", placeholder="user@example.com")
    password = st.text_input("Password", type="password", value=generate_strong_password())
    quota = st.number_input("Quota (MB)", value=1000, min_value=50, step=50)

    if st.button("Create Email", use_container_width=True):
        try:
            if st.session_state.api_type == "20i":
                client.create_email_account(
                    st.session_state.selected_package["package_id"],
                    email,
                    password,
                    quota_mb=int(quota),
                )
            else:
                client.create_email_account(email, password, int(quota))
            st.success("Email account created.")
        except Exception as e:
            st.error(f"Failed to create email: {e}")


# =========================================================
# Tab: Security Scanner
# =========================================================
def render_security_scanner_tab() -> None:
    st.header("Security Scanner")

    st.info("Upload individual files or a ZIP of your WordPress site for a quick pattern-based scan.")

    uploaded = st.file_uploader("Upload file or ZIP", type=["zip", "php", "txt", "js"])
    issues: List[Dict[str, Any]] = []

    if uploaded and st.button("Run Scan", use_container_width=True):
        if uploaded.name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(BytesIO(uploaded.read())) as zf:
                    for name in zf.namelist():
                        if name.endswith("/"):
                            continue
                        try:
                            content = zf.read(name).decode(errors="ignore")
                        except Exception:
                            continue
                        issues.extend(scan_file_for_malware(content, name))
            except Exception as e:
                st.error(f"Failed to scan ZIP: {e}")
        else:
            try:
                content = uploaded.read().decode(errors="ignore")
                issues.extend(scan_file_for_malware(content, uploaded.name))
            except Exception as e:
                st.error(f"Failed to scan file: {e}")

        st.session_state.scan_results = issues
        st.session_state.last_scan = datetime.utcnow().isoformat()

    if st.session_state.scan_results:
        st.subheader("Scan Results")
        st.caption(f"Last scan: {st.session_state.last_scan}")
        for issue in st.session_state.scan_results:
            st.warning(
                f"[{issue['category']}] {issue['file']}:{issue['line']} → pattern `{issue['match']}`"
            )
    else:
        st.info("No issues reported yet.")


# =========================================================
# Lightweight tabs (Performance, Migration, Cron, Logs, FTP, Settings)
# =========================================================
def render_performance_tab() -> None:
    st.header("Performance")
    st.info(
        "Use this section as a checklist around caching, PHP version, database size and slow queries.\n\n"
        "Host-level performance metrics are not directly exposed via 20i or cPanel APIs, "
        "so this tab focuses on guidance and manual checks."
    )


def render_migration_tool_tab() -> None:
    st.header("Migration Tool")
    st.info("Plan migrations between hosts or packages.")
    c1, c2 = st.columns(2)
    with c1:
        src_host = st.text_input("Source Host / Panel URL")
        src_site = st.text_input("Source Domain")
    with c2:
        dst_host = st.text_input("Destination Host / Panel URL")
        dst_site = st.text_input("Destination Domain")
    notes = st.text_area("Migration Notes / Steps")
    if st.button("Save Plan", use_container_width=True):
        st.success("Migration plan saved locally in this session.")
        st.json(
            {
                "source": {"host": src_host, "site": src_site},
                "destination": {"host": dst_host, "site": dst_site},
                "notes": notes,
            }
        )


def render_cron_jobs_tab() -> None:
    st.header("Cron Jobs")
    st.info(
        "Most hosts expose cron management via their panel UI rather than the public API.\n"
        "Use this area as a helper for building cron expressions for WordPress tasks."
    )
    schedule = st.text_input("Cron Expression", value="0 2 * * *")
    command = st.text_input(
        "Command", value="php /home/user/public_html/wp-cron.php >/dev/null 2>&1"
    )
    st.code(f"{schedule} {command}", language="bash")


def render_logs_viewer_tab() -> None:
    st.header("Logs Viewer")
    st.info(
        "Web server and PHP logs are usually not exposed over 20i / cPanel public APIs.\n"
        "Use SSH or the panel's built-in log viewers. You can paste snippets here for analysis."
    )
    snippet = st.text_area("Paste Log Snippet")
    if snippet:
        st.code(snippet, language="text")


def render_ftp_tab() -> None:
    st.header("FTP / SFTP")
    st.info(
        "For security reasons, FTP/SFTP credentials are not fetched via APIs in this tool.\n"
        "Store and manage them in a secure password manager."
    )


def render_settings_tab() -> None:
    st.header("Settings")
    st.info("Local-only settings (this app does not persist these server-side).")
    st.checkbox("Enable debug mode", key="debug_mode")


# =========================================================
# Main App
# =========================================================
def main():
    st.set_page_config(
        page_title="WordPress Management Pro – Ultimate Edition",
        page_icon="🛠️",
        layout="wide",
    )

    init_session_state()

    left, right = st.columns([1.1, 2.3])
    with left:
        render_sidebar()
    with right:
        tab_objs = st.tabs(MAIN_TABS)
        st.session_state.current_tab = st.session_state.current_tab or 0

        with tab_objs[0]:
            render_dashboard_tab()
        with tab_objs[1]:
            render_restore_tab()
        with tab_objs[2]:
            render_backup_manager_tab()
        with tab_objs[3]:
            render_file_editor_tab()
        with tab_objs[4]:
            render_database_manager_tab()
        with tab_objs[5]:
            render_domain_manager_tab()
        with tab_objs[6]:
            render_ssl_manager_tab()
        with tab_objs[7]:
            render_email_manager_tab()
        with tab_objs[8]:
            render_security_scanner_tab()
        with tab_objs[9]:
            render_performance_tab()
        with tab_objs[10]:
            render_migration_tool_tab()
        with tab_objs[11]:
            render_cron_jobs_tab()
        with tab_objs[12]:
            render_logs_viewer_tab()
        with tab_objs[13]:
            render_ftp_tab()
        with tab_objs[14]:
            render_settings_tab()


if __name__ == "__main__":
    main()
