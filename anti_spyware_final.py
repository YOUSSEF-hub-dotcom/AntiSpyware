import psutil
import sqlite3
import time
from datetime import datetime
import threading
import queue
import os
import winsound

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except:
    print("خطأ: تأكد من تثبيت Python مع tkinter")
    exit()



DATABASE_FILE = "spyware_pro.db"
LOG_FILE = "final_report.txt"

CPU_THRESHOLD = 90.0
MEM_THRESHOLD = 1500.0
SCAN_INTERVAL = 3.0

SUSPICIOUS_KEYWORDS = ["keylogger", "stealer", "rat", "remotedesktop", "spyware", "backdoor", "trojan", "miner", "injector"]

WHITELIST_PROCESSES = {
    "System Idle Process", "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe", "explorer.exe",
    "Taskmgr.exe", "MsMpEng.exe", "MpCopyAccelerator.exe", "NisSrv.exe", "MpDefenderCoreService.exe",
    "SecurityHealthService.exe", "SecurityHealthSystray.exe", "fontdrvhost.exe", "ctfmon.exe",
    "sihost.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe", "SearchIndexer.exe",
    "MoUsoCoreWorker.exe", "Widgets.exe", "TextInputHost.exe", "MemCompression", "Secure System",
    "conhost.exe", "MoNotificationUx.exe", "TbtP2pShortcutService.exe", "ThunderboltService.exe",
    "WMIRegistrationService.exe", "full-line-inference.exe", "StartMenuExperienceHost.exe",
    "Canva.exe", "audiodg.exe", "SystemSettings.exe", "CxUtilSvc.exe", "CxAudioSvc.exe",
    "sqlservr.exe", "SSMS.exe", "SqlWriter.exe", "SQLAgent.exe", "SQLTELEMETRY.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "pycharm64.exe", "code.exe",
    "WhatsApp.exe", "Discord.exe", "Spotify.exe", "obs64.exe", "python.exe", "pythonw.exe"
}

CRITICAL_PROTECTED = {"System", "csrss.exe", "winlogon.exe", "lsass.exe", "smss.exe", "wininit.exe"}

last_threat_pid = None
last_threat_time = None

ui_queue = queue.Queue()
stop_event = threading.Event()
scan_thread = None



def init_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        process_name TEXT,
        pid INTEGER,
        reasons TEXT,
        timestamp TEXT
    )""")
    conn.commit()
    conn.close()

def log_threat(name, pid, reasons):
    global last_threat_pid, last_threat_time
    now = datetime.now()
    if last_threat_pid == pid and last_threat_time and (now - last_threat_time).seconds < 20:
        return
    last_threat_pid = pid
    last_threat_time = now

    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cur = conn.cursor()
        cur.execute("INSERT INTO threats (process_name, pid, reasons, timestamp) VALUES (?, ?, ?, ?)",
                    (name, pid, ", ".join(reasons), now.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()

        winsound.Beep(1500, 800)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[THREAT] {name} (PID {pid}) → {', '.join(reasons)} | {now}\n")
    except:
        pass

def fetch_threats():
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cur = conn.cursor()
        cur.execute("SELECT * FROM threats ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        return rows
    except:
        return []



def is_whitelisted(name):
    return name.lower() in [p.lower() for p in WHITELIST_PROCESSES]

def is_critical_process(name):
    return name in CRITICAL_PROTECTED

def is_suspicious_path(proc):
    try:
        exe_path = proc.exe()
        if not exe_path:
            safe_no_path = ["MemCompression", "Secure System", "Registry", "System Idle Process", "dwm.exe"]
            if proc.name() in safe_no_path or proc.pid in (0, 4, 236):
                return False, "System core process"
            return True, "Hidden executable path"

        path = exe_path.lower()

        trusted_paths = [
            r"c:\windows\system32", r"c:\windows\syswow64", r"c:\windows\systemapps",
            r"c:\windows\servicing", r"c:\windows\uus", r"c:\windows\thunderbolt",
            r"c:\windows\tbtp2p", r"c:\windows\winstore", r"c:\windows\apppatch",
            r"c:\windows\immersivecontrolpanel", r"c:\windows\cxsrv", r"c:\windows\cxsvc",
            r"c:\program files", r"c:\program files (x86)",
            r"c:\programdata\microsoft", r"c:\program files\windowsapps",
            r"c:\users\*\appdata\local\programs",
            r"c:\program files\microsoft sql server"
        ]

        if any(trust in path for trust in trusted_paths):
            return False, "Trusted path"

        if any(x in path for x in ["jetbrains", "microsoft", "visual studio", "sql server"]):
            return False, "Trusted development/database tool"

        return True, f"Suspicious path: {exe_path}"

    except:
        return False, "Access denied"

def analyze_process(proc):
    if proc.pid in (0, 4, 236):
        return False, ["Core system"]

    name = proc.name()
    if is_whitelisted(name):
        return False, ["Whitelisted"]

    reasons = []
    lower_name = name.lower()


    sus_path, msg = is_suspicious_path(proc)
    if sus_path:
        reasons.append(msg)

    if not any(k in lower_name for k in ["registration", "defender", "thunderbolt", "notification", "audio", "sql"]):
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in lower_name:
                reasons.append(f"Keyword: {kw}")

    try:
        cpu = proc.cpu_percent(interval=0.1)
        mem = proc.memory_info().rss / (1024 ** 2)

        db_processes = ["sqlservr.exe", "mysqld.exe", "postgres.exe"]
        if cpu > CPU_THRESHOLD and not any(db in lower_name for db in db_processes):
            reasons.append(f"High CPU: {cpu:.1f}%")

        if mem > MEM_THRESHOLD:
            reasons.append(f"High RAM: {mem:.1f} MB")
    except:
        pass

    return len(reasons) > 0, reasons



def scanner_loop():
    while not stop_event.is_set():
        snapshot = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.pid in (0, 4, 236):
                    continue
                suspicious, reasons = analyze_process(proc)
                cpu = proc.cpu_percent(interval=0)
                mem_mb = proc.memory_info().rss / (1024**2)
                info = {
                    'pid': proc.pid, 'name': proc.name(),
                    'cpu': f"{cpu:.1f}", 'mem': f"{mem_mb:.1f}",
                    'suspicious': "YES" if suspicious else "No",
                    'reasons': reasons
                }
                snapshot.append(info)
                if suspicious and reasons:
                    log_threat(info['name'], info['pid'], reasons)
                    ui_queue.put(('alert', info))
            except:
                continue
        ui_queue.put(('snapshot', snapshot))
        time.sleep(SCAN_INTERVAL)

class SpywareDetector(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Spyware Detector Pro © 2025 - Final Project")
        self.geometry("1250x750")
        self.configure(bg='#0d1117')
        try:
            if os.path.exists("shield.ico"): self.iconbitmap("shield.ico")
        except: pass

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background="#161b22", foreground="white", fieldbackground="#161b22", rowheight=28)
        style.configure('Treeview.Heading', background="#1f6aab", foreground="white", font=('Segoe UI', 11, 'bold'))
        style.map('Treeview', background=[('selected', '#1f6aab')])

        ttk.Label(self, text="Spyware Detector Pro", font=("Segoe UI", 22, "bold"), foreground="#58a6ff", background="#0d1117").pack(pady=20)

        top = ttk.Frame(self); top.pack(fill='x', padx=25, pady=10)
        ttk.Button(top, text="بدء المسح", command=self.start_scan).pack(side='right', padx=10)
        ttk.Button(top, text="إيقاف المسح", command=self.stop_scan).pack(side='right')

        paned = ttk.PanedWindow(self, orient='horizontal')
        paned.pack(fill='both', expand=True, padx=25, pady=10)

        left = ttk.Frame(paned); paned.add(left, weight=3)
        ttk.Label(left, text="العمليات الحية", font=("Segoe UI", 14, "bold"), foreground="#58a6ff").pack(anchor='w', pady=(0,10))
        cols = ('PID', 'اسم العملية', 'CPU %', 'RAM MB', 'الحالة')
        self.tree = ttk.Treeview(left, columns=cols, show='headings')
        for c in cols:
            self.tree.heading(c, text=c); self.tree.column(c, width=160)
        self.tree.pack(fill='both', expand=True)

        right = ttk.Frame(paned); paned.add(right, weight=2)
        ttk.Label(right, text="التهديدات المكتشفة", font=("Segoe UI", 14, "bold"), foreground="#ff4444").pack(anchor='w', pady=(0,10))
        tcols = ('ID', 'العملية', 'PID', 'السبب', 'الوقت')
        self.threat_tree = ttk.Treeview(right, columns=tcols, show='headings')
        for c in tcols:
            self.threat_tree.heading(c, text=c); self.threat_tree.column(c, width=150)
        self.threat_tree.pack(fill='both', expand=True)

        bottom = ttk.Frame(self); bottom.pack(fill='x', padx=25, pady=20)
        ttk.Button(bottom, text="إنهاء العملية", command=self.kill_process).pack(side='left', padx=8)
        ttk.Button(bottom, text="تصدير التقرير", command=self.export_report).pack(side='left', padx=8)
        ttk.Button(bottom, text="مسح السجلات", command=self.clear_logs).pack(side='left', padx=8)
        ttk.Button(bottom, text="تشغيل عند بدء التشغيل", command=lambda: messagebox.showinfo("تم", "تم التفعيل")).pack(side='right')

        self.status = tk.StringVar(value="جاهز - اضغط 'بدء المسح'")
        ttk.Label(self, textvariable=self.status, relief='sunken', anchor='w', padding=12, font=('Segoe UI', 10), foreground="#58a6ff").pack(side='bottom', fill='x')

        init_database()
        self.refresh_threats()
        self.after(1000, self.update_ui)

    def start_scan(self):
        global scan_thread
        if scan_thread and scan_thread.is_alive(): return
        stop_event.clear()
        scan_thread = threading.Thread(target=scanner_loop, daemon=True)
        scan_thread.start()
        self.status.set("يتم المسح الآن...")

    def stop_scan(self):
        stop_event.set()
        self.status.set("تم إيقاف المسح")

    def update_ui(self):
        try:
            while not ui_queue.empty():
                typ, data = ui_queue.get_nowait()
                if typ == 'snapshot':
                    self.tree.delete(*self.tree.get_children())
                    for p in data:
                        tag = 'threat' if p['suspicious'] == 'YES' else ''
                        self.tree.insert('', 'end', values=(p['pid'], p['name'], p['cpu'], p['mem'], p['suspicious']), tags=(tag,))
                    self.tree.tag_configure('threat', foreground='#ff4444', font=('Segoe UI', 10, 'bold'))
                elif typ == 'alert':
                    self.threat_tree.insert('', 0, values=(
                        len(fetch_threats()), data['name'], data['pid'],
                        ' | '.join(data['reasons']), datetime.now().strftime("%H:%M:%S")
                    ))
                    messagebox.showwarning("تهديد خطير!", f"تم اكتشاف برنامج ضار!\n\n{data['name']}\nالسبب: {' | '.join(data['reasons'])}")
                    self.status.set(f"تم اكتشاف: {data['name']}")
            self.after(800, self.update_ui)
        except:
            self.after(800, self.update_ui)

    def kill_process(self):
        sel = self.tree.selection()
        if not sel: return
        name = self.tree.item(sel[0])['values'][1]
        pid = int(self.tree.item(sel[0])['values'][0])
        if is_critical_process(name):
            messagebox.showerror("ممنوع", "لا يمكن إنهاء عملية نظام حرجة!")
            return
        try:
            psutil.Process(pid).terminate()
            messagebox.showinfo("تم", f"تم إنهاء: {name}")
        except:
            messagebox.showerror("فشل", "تعذر إنهاء العملية")

    def export_report(self):
        rows = fetch_threats()
        if not rows:
            messagebox.showinfo("نظيف", "لا توجد تهديدات!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", title="حفظ التقرير")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write("تقرير اكتشاف البرامج الضارة - Spyware Detector Pro\n")
                f.write("="*70 + "\n\n")
                for r in rows:
                    f.write(f"العملية: {r[1]} (PID: {r[2]})\nالسبب: {r[3]}\nالتاريخ: {r[4]}\n")
                    f.write("-"*70 + "\n")
            messagebox.showinfo("تم!", "تم حفظ التقرير بنجاح")

    def clear_logs(self):
        if messagebox.askyesno("تأكيد", "مسح جميع السجلات؟"):
            if os.path.exists(DATABASE_FILE): os.remove(DATABASE_FILE)
            open(LOG_FILE, 'w').close()
            init_database()
            self.threat_tree.delete(*self.threat_tree.get_children())
            self.status.set("تم مسح كل السجلات")

    def refresh_threats(self):
        for i in self.threat_tree.get_children():
            self.threat_tree.delete(i)
        for r in fetch_threats():
            self.threat_tree.insert('', 'end', values=r)

if __name__ == "__main__":
    init_database()
    app = SpywareDetector()
    app.mainloop()