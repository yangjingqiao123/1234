




import os
import shutil
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# 模拟的恶意软件签名（可以是文件哈希值或特征）
MALICIOUS_SIGNATURES = [
    'd41d8cd98f00b204e9800998ecf8427e',  # 示例哈希值，实际应是恶意文件的哈希
    'd41d8cd98f00b204e9800998ecf8427e'
]

# 隔离区目录
ISOLATION_FOLDER = './quarantine'


# 检查文件是否包含恶意签名
def check_file_for_malware(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        file_hash = hash_md5.hexdigest()
        return file_hash in MALICIOUS_SIGNATURES
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False


# 扫描目录中的所有文件
def scan_directory(directory, progress_bar, text_output):
    malicious_files = []
    total_files = 0
    scanned_files = 0

    # 计算总文件数
    for root, dirs, files in os.walk(directory):
        total_files += len(files)

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            progress_bar['value'] = (scanned_files / total_files) * 100
            progress_bar.update()

            # 显示当前正在扫描的文件
            text_output.insert(tk.END, f"扫描: {file_path}\n")
            text_output.yview(tk.END)  # 自动滚动到最新内容
            scanned_files += 1

            if check_file_for_malware(file_path):
                malicious_files.append(file_path)

    return malicious_files


# 隔离恶意文件
def isolate_files(files):
    if not os.path.exists(ISOLATION_FOLDER):
        os.makedirs(ISOLATION_FOLDER)

    for file in files:
        try:
            file_name = os.path.basename(file)
            isolation_path = os.path.join(ISOLATION_FOLDER, file_name)
            shutil.move(file, isolation_path)  # 将恶意文件移动到隔离区
        except Exception as e:
            print(f"无法隔离文件 {file}: {e}")


# 打印报告
def print_report(malicious_files, text_output):
    if malicious_files:
        text_output.insert(tk.END, "\nСканирование завершено, и вредоносный файл найден：\n")
        for file in malicious_files:
            text_output.insert(tk.END, f"- {file}\n")
    else:
        text_output.insert(tk.END, "\n扫描完成，未发现恶意文件。\n")


# 主函数
def start_scan(directory, progress_bar, text_output):
    if not directory:
        messagebox.showwarning("警告", "请先选择要扫描的目录！")
        return

    malicious_files = scan_directory(directory, progress_bar, text_output)
    print_report(malicious_files, text_output)

    if malicious_files:
        isolate_files(malicious_files)
        messagebox.showinfo("扫描完成", f"основывать {len(malicious_files)} 1 вредоносный файл, и помещен на карантин!")
    else:
        messagebox.showinfo("扫描完成", "未发现恶意文件。")


# 打开文件夹选择对话框
def select_directory():
    directory = filedialog.askdirectory()
    return directory


# 创建GUI界面
def create_gui():
    # 初始化主窗口
    root = tk.Tk()
    root.title("Сканер вредоносных программ")
    root.geometry("600x400")

    # 选择扫描目录按钮
    select_button = tk.Button(root, text="Выбрать каталог", command=lambda: select_directory())
    select_button.pack(pady=10)

    # 显示选定目录
    directory_label = tk.Label(root, text="Пожалуйста, выберите каталог для сканирования")
    directory_label.pack(pady=5)

    # 创建进度条
    progress_bar = ttk.Progressbar(root, length=400, mode='determinate')
    progress_bar.pack(pady=20)

    # 创建文本框，用于显示扫描输出
    text_output = tk.Text(root, height=10, width=70)
    text_output.pack(pady=10)

    # 扫描按钮
    scan_button = tk.Button(root, text="Начать сканирование",
                            command=lambda: start_scan(select_directory(), progress_bar, text_output))
    scan_button.pack(pady=10)

    # 运行GUI主循环
    root.mainloop()


# 运行程序
if __name__ == "__main__":
    create_gui()
