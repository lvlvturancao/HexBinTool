
# HexBinTool.py 是HexBinTool的主程序文件，主要功能是打开、编辑、合并、保存hex或bin文件，并提供文件预览功能。
# 该文件依赖于intelhex、tkinter、tkinterdnd2、binascii等模块。
# 该文件使用Python 3.7.3编写，依赖于Tkinter、TkinterDnD、IntelHex、binascii等模块。
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinterdnd2 import DND_FILES, TkinterDnD
from intelhex import IntelHex
import os
import binascii
# 版本信息
VERSION_INFO = "V1.1.1_2024.06.28"
# 关于信息
ABOUT_INFO = "HexBinTool是一款hex、bin文件处理工具，提供打开、查看、编辑、合并以及保存hex或bin文件等功能。"
# 全局变量
current_file_path = None  # 当前文件路径
current_start_address = None  # 当前文件起始地址
current_end_address = None  # 当前文件结束地址
# 文件合并器窗口
class FileMerger:
    def __init__(self, parent_frame, file_preview):
        # 创建文件合并窗口
        self.merge_window = tk.Toplevel(parent_frame)
        self.merge_window.title("文件合并")
        self.merge_window.attributes('-topmost', True)  # 保持窗口置顶
        # 文件列表
        self.files_list = []
        # 文件路径列表和起始地址列表
        self.files_start_addresses = []
        self.files_end_addresses = []
        self.create_ui(file_preview)
        # 初始化IntelHex对象
        self.ih = IntelHex()
    def create_ui(self, file_preview):
        # 创建文件窗口容器
        files_frame = ttk.Frame(self.merge_window)
        files_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # 创建文件列表
        self.files_listbox = tk.Listbox(files_frame)
        self.files_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        # 创建滚动条
        scrollbar = ttk.Scrollbar(files_frame, orient=tk.VERTICAL, command=self.files_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        # 设置滚动条与文件列表框关联
        self.files_listbox.config(yscrollcommand=scrollbar.set)
        # 创建按钮容器
        button_frame = ttk.Frame(self.merge_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(button_frame, text="添加文件", command=self.add_merge_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="删除文件", command=self.remove_merge_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="合并", command=self.perform_merge).pack(side=tk.LEFT, padx=(200, 5))
        # 主窗口的文本预览窗口
        self.main_window = file_preview
        self.file_preview = tk.Text(file_preview)
        self.file_preview.pack(fill=tk.BOTH, expand=True)
    # 添加要合并的文件
    def add_merge_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Hex and Bin files", "*.hex *.bin")])
        if file_path:
            # 读取文件并获取起始和结束地址
            start_address, end_address = self.get_file_addresses(file_path)
            if self.check_address_conflict(start_address, end_address):
                self.files_list.append(file_path)
                self.files_start_addresses.append(start_address)
                self.files_end_addresses.append(end_address)
                self.files_listbox.insert(tk.END, f"{os.path.basename(file_path)} (Start Address: 0x{start_address:08X}, End Address: 0x{end_address:08X})")
    def get_file_addresses(self, file_path):
        if file_path.endswith('.hex'):
            # 获取hex文件的起始和结束地址
            ih = IntelHex()
            ih.loadfile(file_path, format='hex')
            start_address = ih.minaddr()
            end_address = ih.maxaddr()
        elif file_path.endswith('.bin'):
            # 获取bin文件起始地址和结束地址
            start_address = simpledialog.askinteger("输入起始地址", "请输入文件的起始地址:", minvalue=0)
            with open(file_path, 'rb') as file:
                data = file.read()
                end_address = start_address + len(data) - 1
        return start_address, end_address
    # 判断添加的文件是否和已有文件地址冲突
    def check_address_conflict(self, start_address, end_address):
        for existing_start_address, existing_end_address in zip(self.files_start_addresses, self.files_end_addresses):
            if (start_address <= existing_start_address <= end_address) or (existing_start_address <= start_address <= existing_end_address):
                messagebox.showerror("错误", "添加的文件与已有文件地址冲突，请重新选择文件")
                return False
        return True
    def remove_merge_file(self):
        # 删除要合并的文件
        selected = self.files_listbox.curselection()
        if selected:
            index = selected[0]
            self.files_list.pop(index)
            self.files_start_addresses.pop(index)
            self.files_end_addresses.pop(index)
            self.files_listbox.delete(index)
    def perform_merge(self):
        # 询问保存路径和文件格式
        output_path = filedialog.asksaveasfilename(defaultextension=".hex", filetypes=[("Hex files", "*.hex"), ("Bin files", "*.bin")])
        # 进行文件合并
        for i, file_path in enumerate(self.files_list):
            if file_path.endswith('.hex'):
                self.ih.merge(IntelHex(file_path), overlap='replace')  # 合并hex文件到self.ih对象
            elif file_path.endswith('.bin'):
                # 获取bin文件的起始地址
                bin_start = self.files_start_addresses[i]
                with open(file_path, 'rb') as file:
                    data = file.read()
                    for j in range(len(data)):
                        self.ih[bin_start + j] = data[j]
        # 保存合并后的文件
        if output_path:
            self.save_merged_file(output_path)
            # 关闭文件合并窗口
            self.merge_window.destroy()
            # 打开合并后的文件到预览窗口
            open_file(output_path, self.file_preview)
    def save_merged_file(self, output_path):
        if output_path.endswith('.hex'):
            self.ih.tofile(output_path, format='hex')
        elif output_path.endswith('.bin'):
            with open(output_path, 'wb') as file:
                file.write(self.ih.tobinarray())
        global current_file_path, current_start_address, current_end_address
        # 处理全局变量
        # 获取hex文件的起始和结束地址(调试用)
        current_file_path = output_path
        current_start_address = self.ih.minaddr()
        current_end_address = self.ih.maxaddr()
        messagebox.showinfo("合并完成", "文件已合并并保存")
# 主窗口类
class HexBinTool:
    def __init__(self, root):
        # 初始化主窗口和设置标题
        self.root = root
        self.root.title("HexBinTool")
        self.create_main_frame()  # 先创建主框架
        # self.file_handler = FileHandler()  # 初始化 file_handler
        self.create_menu()  # 然后创建菜单
        self.setup_drag_and_drop()  # 设置拖拽功能
    def create_menu(self):
        # 创建菜单栏和各个子菜单
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="打开", command=self.open_file)
        self.file_menu.add_command(label="保存", command=self.save_file)
        self.file_menu.add_command(label="另存为", command=self.save_as_file)
        self.menu_bar.add_cascade(label="文件", menu=self.file_menu)
        self.tool_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.tool_menu.add_command(label="文件合并", command=self.merge_files)
        self.tool_menu.add_command(label="文件对比", command=compare_files)
        self.menu_bar.add_cascade(label="工具", menu=self.tool_menu)
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.help_menu.add_command(label="使用说明", command=show_usage)
        self.help_menu.add_command(label="版本信息", command=show_version)
        self.help_menu.add_command(label="关于", command=show_about)
        self.menu_bar.add_cascade(label="帮助", menu=self.help_menu)
    def create_main_frame(self):
        # 创建主框架和界面元素
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        # 创建一个 Frame 作为容器
        self.control_frame = tk.Frame(self.main_frame)
        self.control_frame.pack(side=tk.TOP, fill=tk.X, padx=5)
        # 添加标签显示文件路径
        self.file_path_label = ttk.Label(self.control_frame, text="", foreground="grey", width=50)
        self.file_path_label.pack(side=tk.LEFT, padx=5)
        # 创建地址栏和跳转按钮
        self.address_var = tk.StringVar()
        self.address_entry = ttk.Entry(self.control_frame, textvariable=self.address_var, width=10)
        self.address_entry.pack(side=tk.LEFT, padx=5)
        # 跳转按钮
        self.jump_button = ttk.Button(self.control_frame, text="跳转", command=self.jump_to_address)
        self.jump_button.pack(side=tk.LEFT, padx=5)
        # 创建滚动条
        self.scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        # 创建文本区域
        self.file_preview = tk.Text(self.main_frame, wrap=tk.NONE, yscrollcommand=self.scrollbar.set)
        self.file_preview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # 将滚动条与文本区域关联
        self.scrollbar.config(command=self.file_preview.yview)
    def setup_drag_and_drop(self):
        # 设置拖拽功能
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.handle_drop)
    def handle_drop(self, event):
        # 处理拖拽文件事件
        file_path = event.data
        if file_path:
            if file_path.endswith('.hex') or file_path.endswith('.bin'):
                open_file(file_path, self.file_preview)
            else:
                messagebox.showerror("错误", "不支持的文件格式（或文件名含有空格），仅支持 .hex 和 .bin 文件。")
        # 更新文件路径标签
        update_file_path_label(self.file_path_label, current_file_path)
    def open_file(self):
        # 通过对话打开文件
        open_file_dialog(self.file_preview)
        # 更新文件路径标签
        update_file_path_label(self.file_path_label, current_file_path)
    def jump_to_address(self):
        # 跳转到指定地址
        try:
            address = int(self.address_var.get(), 16)
            if current_start_address is not None and current_end_address is not None:
                if current_start_address <= address <= current_end_address:
                    relative_address = address - current_start_address
                    total_range = current_end_address - current_start_address
                    self.file_preview.yview_moveto(relative_address / float(total_range))
                else:
                    messagebox.showerror("错误", "地址超出有效范围")
            else:
                messagebox.showerror("错误", "文件未打开或地址范围未设置")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制地址")
    def save_file(self):
        # 保存文件
        file_path = current_file_path
        if file_path:
            if file_path.endswith('.hex'):
                ih = self.convert_text_to_hex(self.file_preview.get(1.0, tk.END))
                ih.tofile(file_path, format='hex')  # 保存 IntelHex 对象到文件
            elif file_path.endswith('.bin'):
                with open(file_path, 'wb') as file:
                    file.write(self.convert_text_to_bin(self.file_preview.get(1.0, tk.END)))
        else:
            messagebox.showinfo("提示", "请先打开一个文件")
    def save_as_file(self):
        # 另存为文件
        if current_file_path:
            file_path = filedialog.asksaveasfilename(defaultextension=".hex", filetypes=[("Hex files", "*.hex"), ("Bin files", "*.bin")])
            if file_path:
                if file_path.endswith('.hex'):
                    ih = self.convert_text_to_hex(self.file_preview.get(1.0, tk.END))
                    ih.tofile(file_path, format='hex')  # 保存 IntelHex 对象到文件
                elif file_path.endswith('.bin'):
                    with open(file_path, 'wb') as file:
                        file.write(self.convert_text_to_bin(self.file_preview.get(1.0, tk.END)))
        else:
            messagebox.showinfo("提示", "请先打开一个文件")
    def convert_text_to_hex(self, text):
        # 将text widget中的内容转换为IntelHex对象
        ih = IntelHex()  # 创建 IntelHex 对象
        lines = text.strip().split('\n')
        for line in lines:
            if line.startswith('0x'):
                address_str, data_str = line.split(': ')
                address = int(address_str, 16)
                data_values = data_str.split()
                for offset, value in enumerate(data_values):
                    current_address = address + offset
                    ih[current_address] = int(value, 16)
        return ih
    def convert_text_to_bin(self, text):
        # 将text widget中的内容转换为二进制数据
        lines = text.splitlines()
        bin_data = b""
        for line in lines:
            if line.startswith('0x'):
                parts = line.split(':')
                if len(parts) == 2:
                    data_str = parts[1].strip().replace(' ', '')
                    bin_data += bytes.fromhex(data_str)
        return bin_data
    def merge_files(self):
        # 打开文件合并器
        file_merger = FileMerger(self.main_frame, self.file_preview)  # 初始化文件合并器
# 更新标签显示文件路径
def update_file_path_label(file_path_label, file_path):
    if not isinstance(file_path_label, ttk.Label):
        raise TypeError("file_path_label must be a ttk.Label instance")
    file_path_label.config(text=file_path)
# 通过路径打开文件到文件预览框
def open_file(file_path, file_preview):
    global current_file_path, current_start_address, current_end_address
    # 判断file_preview是否为文本组件
    if not isinstance(file_preview, tk.Text):
        raise TypeError("file_preview must be a tk.Text instance")
    if file_path.endswith('.hex'):
        open_hex_file(file_path, file_preview)
    elif file_path.endswith('.bin'):
        # 询问bin文件起始地址
        current_start_address = simpledialog.askinteger("输入起始地址", "请输入文件的起始地址:", minvalue=0)
        open_bin_file(file_path, current_start_address, file_preview)
    print(f"File start address: 0x{current_start_address:08X}, end address: 0x{current_end_address:08X}")
# 通过对话框打开文件到文件预览框
def open_file_dialog(file_preview):
    global current_file_path, current_start_address, current_end_address
    # 判断file_preview是否为文本组件
    if not isinstance(file_preview, tk.Text):
        raise TypeError("file_preview must be a tk.Text instance")
    file_path = filedialog.askopenfilename(filetypes=[("Hex and Bin files", "*.hex *.bin")])
    if file_path.endswith('.hex'):
        open_hex_file(file_path, file_preview)
    elif file_path.endswith('.bin'):
        # 询问bin文件起始地址
        start = simpledialog.askinteger("输入起始地址", "请输入文件的起始地址:", minvalue=0)
        open_bin_file(file_path, start, file_preview)
    print(f"File start address: 0x{current_start_address:08X}, end address: 0x{current_end_address:08X}")
# 打开hex文件到文件预览框
def open_hex_file(hex_file_path, file_preview):
    global current_file_path, current_start_address, current_end_address
    # 先清空文本框
    file_preview.delete(1.0, tk.END)
    # 打开hex文件
    ih = IntelHex()
    ih.loadfile(hex_file_path, format='hex')
    # 将hex文件数据转为字典再使用，避免重复按字节读取hex文件，导致程序无响应
    data_dict = {address: ih[address] for address in range(ih.minaddr(), ih.maxaddr() + 1)}
    
    for address in range(ih.minaddr(), ih.maxaddr() + 1, 16):
        file_preview.insert(tk.END, f"0x{address:08X}: ")
        for offset in range(16):
            current_address = address + offset
            if current_address in data_dict:
                file_preview.insert(tk.END, f"{data_dict[current_address]:02X} ")
            elif current_address <= ih.maxaddr():
                file_preview.insert(tk.END, "FF ")
        file_preview.insert(tk.END, "\n")
    current_file_path = hex_file_path
    current_start_address = ih.minaddr()
    current_end_address = ih.maxaddr()
# 打开bin文件到文件预览框
def open_bin_file(bin_file_path, start, file_preview):
    global current_file_path, current_start_address, current_end_address
    # 先清空文本框
    file_preview.delete(1.0, tk.END)
    # 打开bin文件
    with open(bin_file_path, 'rb') as file:
        data = file.read()
        current_file_path = bin_file_path
        current_start_address = start
        current_end_address = current_start_address + len(data) - 1
    # 将bin文件数据转为预览文本
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_chunk = binascii.hexlify(chunk).decode('utf-8').upper()  # 转换为大写
        spaced_hex_chunk = ' '.join(hex_chunk[j:j+2] for j in range(0, len(hex_chunk), 2))
        file_preview.insert(tk.END, f"0x{current_start_address+i:08X}: {spaced_hex_chunk}\n")
# 打开文件对比器
def compare_files():
    # TODO: 文件对比器尚未实现
    messagebox.showinfo("提示", "文件对比器尚未实现")
    # file_merger = FileComparer(self.main_frame, self.file_preview)  # 初始化文件对比器
# 显示使用说明
def show_usage():
    usage_text = """
    1. 打开: 打开查看和编辑hex或bin文件。
    2. 保存：保存当前查看文件。
    3. 另存为：将当前文件另存为hex或bin文件。
    4. 文件合并：选择多个文件并将它们合并为一个文件，并进行预览。
    """
    messagebox.showinfo("使用说明", usage_text)
# 显示版本信息
def show_version():
    messagebox.showinfo("版本信息", VERSION_INFO)
# 显示关于信息
def show_about():
    messagebox.showinfo("关于", ABOUT_INFO)
if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = HexBinTool(root)
    root.mainloop()
