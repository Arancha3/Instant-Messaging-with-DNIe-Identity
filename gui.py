# filename: gui.py
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import queue
from datetime import datetime, timezone
from PIL import Image, ImageTk 
import os

# Colores del tema
BG_TEAL_DARK = "#004d4d"    # Sidebar
BG_TEAL_LIGHT = "#e0f7fa"   # Fondo general
BG_SAND = "#f0e6d2"         # Cabecera chat
TEXT_DARK = "#2c3e50"
ACCENT_BLUE = "#3498db"
SECURITY_GREEN = "#27ae60"
ERROR_RED = "#e74c3c"

class DniIMGUI:
    def __init__(self, on_send_message, on_connect_to_peer):
        self.root = tk.Tk()
        self.root.title("DNI-IM Raccoon Edition (Síncrono)")
        self.root.geometry("1000x650")

        self.on_send_message = on_send_message
        self.on_connect_to_peer = on_connect_to_peer
        
        # Estado
        self.my_nickname = "..."
        self.selected_fp = None
        self.chat_history = {} 
        self.msg_queue = queue.Queue()

        # --- IMAGEN DE FONDO ---
        self.bg_image_pil = None
        self.bg_photo = None
        
        img_path = "image_0.png"
        if os.path.exists(img_path):
            try:
                self.bg_image_pil = Image.open(img_path)
                # Bind para redimensionar el fondo del chat
                self.root.bind("<Configure>", self._resize_chat_background)
            except Exception as e:
                print(f"Error cargando imagen: {e}")

        self._setup_styles()
        self._build_layout()
        
        self.root.after(100, self._process_queue)

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Segoe UI", 10), background=BG_SAND, foreground=TEXT_DARK)
        style.map("TButton", background=[('active', ACCENT_BLUE), ('pressed', BG_TEAL_DARK)], foreground=[('active', 'white')])
        style.configure("Sidebar.TFrame", background=BG_TEAL_DARK)

    def _resize_chat_background(self, event):
        """Redimensiona la imagen y asegura el orden de capas (Texto > Burbuja > Fondo)"""
        if not self.bg_image_pil or not hasattr(self, 'chat_canvas'):
            return
        
        # Solo reaccionar si el chat o root cambia de tamaño
        if event.widget != self.chat_canvas and event.widget != self.root:
            return

        w = self.chat_canvas.winfo_width()
        h = self.chat_canvas.winfo_height()
        
        if w < 50 or h < 50: return 

        # Copia y redimensiona
        img_copy = self.bg_image_pil.copy()
        resized_image = img_copy.resize((w, h), Image.LANCZOS)
        self.bg_photo = ImageTk.PhotoImage(resized_image)
        
        self.chat_canvas.delete("chat_bg")
        self.chat_canvas.create_image(0, 0, image=self.bg_photo, anchor="nw", tags="chat_bg")
        
        # --- CORRECCIÓN DE CAPAS ---
        # 1. Fondo al fondo absoluto
        self.chat_canvas.lower("chat_bg")
        # 2. Burbujas encima del fondo
        self.chat_canvas.tag_raise("bubble")
        # 3. Texto y Hora encima de las burbujas (IMPORTANTE)
        self.chat_canvas.tag_raise("text")
        self.chat_canvas.tag_raise("time")

    def _build_layout(self):
        # Contenedor principal limpio
        self.main_container = tk.Frame(self.root, bg=BG_TEAL_LIGHT)
        self.main_container.pack(fill=tk.BOTH, expand=True)

        main_paned = tk.PanedWindow(self.main_container, orient=tk.HORIZONTAL, sashwidth=4, bg=BG_TEAL_DARK)
        main_paned.pack(fill=tk.BOTH, expand=True)

        # === SIDEBAR ===
        self.sidebar_frame = tk.Frame(main_paned, bg=BG_TEAL_DARK, width=280)
        self.sidebar_frame.pack_propagate(False)
        main_paned.add(self.sidebar_frame)

        lbl_header = tk.Label(self.sidebar_frame, text="🦝 DNIe Chat Peers", bg=BG_TEAL_DARK, fg="white", height=3, font=("Segoe UI", 12, "bold"))
        lbl_header.pack(fill=tk.X, pady=(0, 10))

        # Lista Contactos
        self.contact_canvas = tk.Canvas(self.sidebar_frame, bg=BG_TEAL_DARK, highlightthickness=0)
        self.contact_scrollbar = ttk.Scrollbar(self.sidebar_frame, orient="vertical", command=self.contact_canvas.yview)
        self.contact_list_frame = tk.Frame(self.contact_canvas, bg=BG_TEAL_DARK)

        self.contact_list_frame.bind("<Configure>", lambda e: self.contact_canvas.configure(scrollregion=self.contact_canvas.bbox("all")))
        self.contact_canvas.create_window((0, 0), window=self.contact_list_frame, anchor="nw", width=260)
        self.contact_canvas.configure(yscrollcommand=self.contact_scrollbar.set)

        self.contact_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.contact_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        btn_connect = ttk.Button(self.sidebar_frame, text="➕ Conectar Manualmente", command=self._ask_connect)
        btn_connect.pack(fill=tk.X, padx=10, pady=10, side=tk.BOTTOM)

        # === CHAT AREA ===
        self.chat_frame = tk.Frame(main_paned, bg=BG_TEAL_LIGHT)
        main_paned.add(self.chat_frame)

        # Header Chat
        self.header_chat_frame = tk.Frame(self.chat_frame, bg=BG_SAND, height=50)
        self.header_chat_frame.pack(fill=tk.X)
        self.lbl_chat_name = tk.Label(self.header_chat_frame, text="Selecciona un contacto...", bg=BG_SAND, fg=TEXT_DARK, font=("Segoe UI", 12, "bold"), padx=20, pady=10, anchor="w")
        self.lbl_chat_name.pack(fill=tk.BOTH, expand=True)

        # Canvas del Chat
        chat_area_container = tk.Frame(self.chat_frame, bg=BG_TEAL_LIGHT)
        chat_area_container.pack(fill=tk.BOTH, expand=True)

        self.chat_canvas = tk.Canvas(chat_area_container, bg="white", highlightthickness=0)
        self.chat_scrollbar = ttk.Scrollbar(chat_area_container, orient="vertical", command=self.chat_canvas.yview)
        
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Input Area
        input_frame = tk.Frame(self.chat_frame, bg=BG_TEAL_LIGHT, pady=10, padx=10)
        input_frame.pack(fill=tk.X)

        self.entry_msg = ttk.Entry(input_frame, font=("Segoe UI", 11))
        self.entry_msg.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10), ipady=5)
        self.entry_msg.bind("<Return>", self._on_enter_pressed)

        btn_send = ttk.Button(input_frame, text="Enviar ➤", command=self._send_action, style="TButton")
        btn_send.pack(side=tk.RIGHT, ipadx=10, ipady=2)

    def get_pin_dialog(self) -> (str, str):
        self.root.update_idletasks() 
        pin = simpledialog.askstring("Acceso DNIe", "Introduce el PIN de tu DNIe:", show='*', parent=self.root)
        if not pin:
            messagebox.showerror("Error", "El PIN es necesario.")
            self.root.destroy()
            return None, None
        nickname = simpledialog.askstring("Configuración", "Tu Nickname:", parent=self.root)
        if not nickname: nickname = "Mapache"
        self.my_nickname = nickname
        self.root.title(f"DNI-IM ({nickname}) 🦝")
        return pin, nickname

    def start(self):
        self.root.mainloop()

    def _process_queue(self):
        try:
            while True:
                action, args = self.msg_queue.get_nowait()
                if action == "update_peers":
                    self._refresh_contacts_list(*args)
                elif action == "show_message":
                    self._render_incoming_message(*args)
                elif action == "show_security_info":
                    self._render_security_info(*args)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_queue)

    def _format_last_seen(self, iso_timestamp):
        if not iso_timestamp: return "Nunca visto"
        try:
            ts = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            diff = now - ts
            minutes = int(diff.total_seconds() / 60)
            if minutes < 1: return "Visto ahora"
            if minutes < 60: return f"Visto hace {minutes} min"
            hours = int(minutes / 60)
            if hours < 24: return f"Visto hace {hours}h"
            days = int(hours / 24)
            return f"Visto hace {days} días"
        except:
            return "Fecha inválida"

    def _refresh_contacts_list(self, mdns_peers, saved_contacts):
        for widget in self.contact_list_frame.winfo_children():
            widget.destroy()

        all_fps = set(mdns_peers.keys()) | set(saved_contacts.keys())
        sorted_fps = sorted(list(all_fps))

        for fp in sorted_fps:
            mdns_info = mdns_peers.get(fp)
            contact_info = saved_contacts.get(fp)
            is_online = mdns_info is not None
            
            nick = f"Peer {fp[:6]}"
            if contact_info and contact_info.name: nick = contact_info.name
            elif mdns_info and mdns_info.get("nickname"): nick = mdns_info.get("nickname")

            if is_online:
                status_color = SECURITY_GREEN
                status_text = "Online Ahora"
            else:
                status_color = "#95a5a6"
                if contact_info and contact_info.last_seen:
                    status_text = self._format_last_seen(contact_info.last_seen)
                else:
                    status_text = "Desconectado"

            f_container = tk.Frame(self.contact_list_frame, bg=BG_TEAL_DARK)
            f_container.pack(fill=tk.X, pady=1)
            f = tk.Frame(f_container, bg=BG_TEAL_DARK, pady=8, padx=10, cursor="hand2")
            f.pack(fill=tk.X)
            tk.Frame(f_container, bg="#1a252f", height=1).pack(fill=tk.X, side=tk.BOTTOM)

            ind = tk.Label(f, text="●", fg=status_color, bg=BG_TEAL_DARK, font=("Arial", 18))
            ind.pack(side=tk.LEFT, padx=(0, 10))

            text_frame = tk.Frame(f, bg=BG_TEAL_DARK)
            text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            lbl_name = tk.Label(text_frame, text=nick, justify=tk.LEFT, bg=BG_TEAL_DARK, fg="white", font=("Segoe UI", 11, "bold"))
            lbl_name.pack(anchor="w")
            lbl_status = tk.Label(text_frame, text=status_text, justify=tk.LEFT, bg=BG_TEAL_DARK, fg="#bdc3c7", font=("Segoe UI", 9))
            lbl_status.pack(anchor="w")

            for w in [f, ind, text_frame, lbl_name, lbl_status]:
                w.bind("<Button-1>", lambda e, f=fp, n=nick: self._select_chat(f, n))

    def _select_chat(self, fp, name):
        self.selected_fp = fp
        self.lbl_chat_name.config(text=f"💬 {name}")
        self._redraw_chat_window()
        self.on_connect_to_peer(fp)

    def _redraw_chat_window(self):
        self.chat_canvas.delete("all")
        if self.bg_photo:
            self.chat_canvas.create_image(0, 0, image=self.bg_photo, anchor="nw", tags="chat_bg")

        y_pos = 20
        canvas_width = self.chat_canvas.winfo_width()
        if canvas_width < 100: canvas_width = 600

        if self.selected_fp in self.chat_history:
            for msg in self.chat_history[self.selected_fp]:
                y_pos = self._draw_bubble(msg, y_pos, canvas_width)

        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        self.chat_canvas.yview_moveto(1.0)

    def _draw_bubble(self, msg, y_pos, canvas_width):
        text = msg["text"]
        time_str = msg.get("time", "")
        sender = msg["sender"]
        msg_type = msg.get("type", "text")
        
        # Estilos por tipo de mensaje
        if msg_type == "security":
            bg_color = "#e8f5e9"
            fg_color = SECURITY_GREEN
            anchor = "center"
            x_pos = canvas_width / 2
            max_w = canvas_width * 0.85
            font_text = ("Segoe UI", 9, "bold")
            font_time = ("Segoe UI", 7)
            text_to_show = f"🔒 {text}"
        elif msg_type == "error":
            bg_color = "#fce4ec"
            fg_color = ERROR_RED
            anchor = "center"
            x_pos = canvas_width / 2
            max_w = canvas_width * 0.85
            font_text = ("Segoe UI", 9, "bold")
            font_time = ("Segoe UI", 7)
            text_to_show = f"⚠️ {text}"
        elif sender == "yo":
            bg_color = "#dcf8c6"
            fg_color = "black"
            anchor = "ne" 
            x_pos = canvas_width - 20
            max_w = canvas_width * 0.65
            font_text = ("Segoe UI", 11)
            font_time = ("Segoe UI", 8)
            text_to_show = text
        else: # them
            bg_color = "white"
            fg_color = "black"
            anchor = "nw"
            x_pos = 20
            max_w = canvas_width * 0.65
            font_text = ("Segoe UI", 11)
            font_time = ("Segoe UI", 8)
            text_to_show = text

        # 1. Crear Texto principal (Se crea primero)
        text_id = self.chat_canvas.create_text(
            x_pos, y_pos + 10,
            text=text_to_show, width=max_w, anchor=anchor, font=font_text, fill=fg_color, tags="text"
        )
        bbox = list(self.chat_canvas.bbox(text_id))
        
        # 2. Crear Hora
        bbox[3] += 15
        time_x = bbox[2] - 5
        time_y = bbox[3] - 8
        time_id = self.chat_canvas.create_text(
            time_x, time_y,
            text=time_str, anchor="se", font=font_time, fill="#7f8c8d", tags="time"
        )
        bbox_time = self.chat_canvas.bbox(time_id)
        
        final_bbox = [
            min(bbox[0], bbox_time[0]),
            min(bbox[1], bbox_time[1]),
            max(bbox[2], bbox_time[2]),
            max(bbox[3], bbox_time[3])
        ]

        # 3. Crear Rectángulo (Se crea al final, por lo que taparía al texto)
        padding = 8
        rect_id = self.chat_canvas.create_rectangle(
            final_bbox[0] - padding, final_bbox[1] - padding,
            final_bbox[2] + padding, final_bbox[3] + padding,
            fill=bg_color, outline="#bdc3c7", width=1, tags="bubble"
        )
        
        # 4. CORRECCIÓN: Levantar el texto y la hora explícitamente sobre el rectángulo
        self.chat_canvas.tag_raise(text_id)
        self.chat_canvas.tag_raise(time_id)
        
        return final_bbox[3] + 25

    def _on_enter_pressed(self, event):
        self._send_action()

    def _send_action(self):
        msg = self.entry_msg.get().strip()
        if not msg: return
        if not self.selected_fp:
            messagebox.showwarning("Aviso", "Selecciona contacto.")
            return
        
        self._add_to_history(self.selected_fp, "yo", msg)
        self.entry_msg.delete(0, tk.END)
        self._redraw_chat_window()
        self.on_send_message(self.selected_fp, msg)

    def _ask_connect(self):
        target = simpledialog.askstring("Conectar", "Alias o Fingerprint:", parent=self.root)
        if target: self.on_connect_to_peer(target)

    def _add_to_history(self, fp, sender, text, msg_type="text"):
        if fp not in self.chat_history:
            self.chat_history[fp] = []
        
        now_str = datetime.now().strftime("%H:%M")
        self.chat_history[fp].append({
            "sender": sender, 
            "text": text, 
            "type": msg_type,
            "time": now_str
        })

    # Thread-Safe Calls
    def update_contacts_threadsafe(self, mdns_peers, saved_contacts):
        self.msg_queue.put(("update_peers", (mdns_peers, saved_contacts)))

    def show_message_threadsafe(self, fp, display_name, text):
        self.msg_queue.put(("show_message", (fp, display_name, text)))

    def show_security_info_threadsafe(self, fp, text):
        self.msg_queue.put(("show_security_info", (fp, text)))

    def _render_incoming_message(self, fp, display_name, text):
        self._add_to_history(fp, display_name, text)
        if self.selected_fp == fp:
            self._redraw_chat_window()
    
    def _render_security_info(self, fp, text):
        mtype = "error" if "Error" in text or "NO ENVIADO" in text else "security"
        self._add_to_history(fp, "info", text, msg_type=mtype)
        if self.selected_fp == fp:
            self._redraw_chat_window()