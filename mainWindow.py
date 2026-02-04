from PyQt5.QtWidgets import *
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon
import sys
import os
import time
import json

from main import *

PLUGINS_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "plugins", "plugins.json")


class SettingsWindow(QDialog):
    """设置窗口"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.setFixedSize(300, 150)
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        layout = QVBoxLayout(self)

        self.del_checkbox = QCheckBox("解密后删除原音频文件")
        layout.addWidget(self.del_checkbox)

        self.wheel_checkbox = QCheckBox("循环运行")
        layout.addWidget(self.wheel_checkbox)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self.save_settings)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def load_settings(self):
        """从JSON加载设置"""
        if os.path.exists(PLUGINS_CONFIG_PATH):
            try:
                with open(PLUGINS_CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
                self.del_checkbox.setChecked(config.get("del", False))
                self.wheel_checkbox.setChecked(config.get("wheel", False))
            except Exception as e:
                print(f"加载设置失败: {e}")

    def save_settings(self):
        """保存设置到JSON"""
        try:
            config = {}
            if os.path.exists(PLUGINS_CONFIG_PATH):
                with open(PLUGINS_CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
            config["del"] = self.del_checkbox.isChecked()
            config["wheel"] = self.wheel_checkbox.isChecked()
            os.makedirs(os.path.dirname(PLUGINS_CONFIG_PATH), exist_ok=True)
            with open(PLUGINS_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=4)
            self.accept()
        except Exception as e:
            QMessageBox.warning(self, "错误", f"保存设置失败: {e}")


class DecryptThread(QThread):
    """解密工作线程 - 避免阻塞GUI"""
    progress_signal = pyqtSignal(int)
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, qq_music_dir, output_dir, del_flag, wheel_flag):
        super().__init__()
        self.qq_music_dir = qq_music_dir
        self.output_dir = output_dir
        self.del_flag = del_flag
        self.wheel_flag = wheel_flag

    def run(self):
        # 如果不是轮询模式，则只执行一次
        if not self.wheel_flag:
            try:
                self.log_signal.emit("开始解密过程...")

                print(self.qq_music_dir, self.output_dir, self.del_flag)
                # 执行解密
                success, message = Decryptor_main(self.qq_music_dir, self.output_dir, self.del_flag)

                self.finished_signal.emit(success, message)

            except Exception as e:
                self.finished_signal.emit(False, f"线程执行错误: {str(e)}")

        # 如果是轮询模式，则循环执行
        else:
            while(self.wheel_flag):
                try:
                    # self.log_signal.emit("开始解密过程...")

                    # 执行解密
                    success, message = Decryptor_main(self.qq_music_dir, self.output_dir, self.del_flag)


                except Exception as e:
                    self.finished_signal.emit(False, f"线程执行错误: {str(e)}")

            self.finished_signal.emit(success, message)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.qq_music_dir = ""
        self.output_dir = ""
        self.decrypt_thread = None

        self.setWindowTitle("QQ音乐解密工具")
        self.setFixedSize(600, 400)
        self._init_ui()

        # 先创建 status_bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")

        # 读取插件配置（此时status_bar已存在）
        self.load_plugins_config()

    def load_plugins_config(self):
        """从 plugins/plugins.json 加载上次保存的路径"""
        if os.path.exists(PLUGINS_CONFIG_PATH):
            try:
                with open(PLUGINS_CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
                self.qq_music_dir = config.get("input", "")
                self.output_dir = config.get("output", "")
                if self.qq_music_dir:
                    self.qq_music_label.setText(self.qq_music_dir)
                if self.output_dir:
                    self.output_label.setText(self.output_dir)
                self._update_ui_state()
                if self.qq_music_dir and self.output_dir:
                    self._add_log(f"已加载上次配置: 输入={self.qq_music_dir}, 输出={self.output_dir}")
            except Exception as e:
                self._add_log(f"加载配置失败: {e}")

    def save_plugins_config(self):
        """保存当前路径到 plugins/plugins.json"""
        try:
            os.makedirs(os.path.dirname(PLUGINS_CONFIG_PATH), exist_ok=True)
            config = {
                "input": self.qq_music_dir,
                "output": self.output_dir
            }
            # 保留 del 和 wheel 设置
            if os.path.exists(PLUGINS_CONFIG_PATH):
                with open(PLUGINS_CONFIG_PATH, "r", encoding="utf-8") as f:
                    old_config = json.load(f)
                config["del"] = old_config.get("del", False)
                config["wheel"] = old_config.get("wheel", False)
            with open(PLUGINS_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            self._add_log(f"保存配置失败: {e}")

    def _init_ui(self):
        # 主窗口部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 使用垂直布局
        main_layout = QVBoxLayout(central_widget)

        # 标题
        title_label = QLabel("QQ音乐加密文件解密器")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        main_layout.addWidget(title_label)

        # 目录选择区域
        self._create_directory_selection(main_layout)

        # 日志显示区域
        self._create_log_area(main_layout)

        # 控制按钮区域
        self._create_control_buttons(main_layout)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

    def _create_directory_selection(self, parent_layout):
        """创建目录选择区域"""
        # QQ音乐目录选择
        qq_music_group = QGroupBox("QQ音乐下载目录")
        qq_music_layout = QHBoxLayout()

        self.qq_music_label = QLabel("未选择")
        self.qq_music_label.setStyleSheet("border: 1px solid gray; padding: 5px;")
        qq_music_layout.addWidget(self.qq_music_label)

        open_qq_music_btn = QPushButton("选择目录")
        open_qq_music_btn.clicked.connect(self.open_qq_music_dialog)
        qq_music_layout.addWidget(open_qq_music_btn)

        qq_music_group.setLayout(qq_music_layout)
        parent_layout.addWidget(qq_music_group)

        # 输出目录选择
        output_group = QGroupBox("输出目录")
        output_layout = QHBoxLayout()

        self.output_label = QLabel("未选择")
        self.output_label.setStyleSheet("border: 1px solid gray; padding: 5px;")
        output_layout.addWidget(self.output_label)

        open_output_btn = QPushButton("选择目录")
        open_output_btn.clicked.connect(self.open_output_dialog)
        output_layout.addWidget(open_output_btn)

        output_group.setLayout(output_layout)
        parent_layout.addWidget(output_group)

    def _create_log_area(self, parent_layout):
        """创建日志显示区域"""
        log_group = QGroupBox("处理日志")
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        log_layout.addWidget(self.log_text)

        # 清空日志按钮
        clear_log_btn = QPushButton("清空日志")
        clear_log_btn.clicked.connect(self.log_text.clear)
        log_layout.addWidget(clear_log_btn)

        log_group.setLayout(log_layout)
        parent_layout.addWidget(log_group)

    def _create_control_buttons(self, parent_layout):
        """创建控制按钮区域"""
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("开始解密")
        self.start_btn.clicked.connect(self.start_decrypt)
        self.start_btn.setEnabled(False)
        button_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.stop_decrypt)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)

        settings_btn = QPushButton("设置")
        settings_btn.clicked.connect(self.open_settings)
        button_layout.addWidget(settings_btn)

        parent_layout.addLayout(button_layout)

    def open_settings(self):
        """打开设置窗口"""
        dlg = SettingsWindow(self)
        dlg.exec_()

    def open_qq_music_dialog(self):
        """选择QQ音乐下载目录"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "选择QQ音乐下载目录",
            "",
            QFileDialog.ShowDirsOnly
        )
        if directory:
            self.qq_music_dir = directory
            self.qq_music_label.setText(directory)
            self._update_ui_state()
            self._add_log(f"QQ音乐目录: {directory}")
            self.save_plugins_config()

    def open_output_dialog(self):
        """选择输出目录"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "选择输出目录",
            "",
            QFileDialog.ShowDirsOnly
        )
        if directory:
            self.output_dir = directory
            self.output_label.setText(directory)
            self._update_ui_state()
            self._add_log(f"输出目录: {directory}")
            self.save_plugins_config()

    def _update_ui_state(self):
        """更新UI状态"""
        has_qq_music_dir = bool(self.qq_music_dir)
        has_output_dir = bool(self.output_dir)

        self.start_btn.setEnabled(has_qq_music_dir and has_output_dir)

        if has_qq_music_dir and has_output_dir:
            self.status_bar.showMessage("就绪，可以开始解密")
        else:
            self.status_bar.showMessage("请选择目录")

    def _add_log(self, message):
        """添加日志消息"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )

    def start_decrypt(self):
        """开始解密（使用多线程）"""
        if not self.qq_music_dir or not self.output_dir:
            self._add_log("错误：请先选择QQ音乐目录和输出目录")
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self._add_log("开始解密过程...")
        self.status_bar.showMessage("解密进行中...")

        # 读取设置
        del_enabled = False
        if os.path.exists(PLUGINS_CONFIG_PATH):
            try:
                with open(PLUGINS_CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
                del_enabled = config.get("del", False)
            except Exception:
                pass

        wheel_enabled = False
        if os.path.exists(PLUGINS_CONFIG_PATH):
            try:
                with open(PLUGINS_CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
                wheel_enabled = config.get("wheel", False)
            except Exception:
                pass

        if wheel_enabled:
            self._add_log("开启轮播模式")
            # 设置进度条为未知进度
            self.progress_bar.setRange(0, 0)

        self.decrypt_thread = DecryptThread(self.qq_music_dir, self.output_dir, del_enabled, wheel_enabled)
        self.decrypt_thread.log_signal.connect(self._add_log)
        self.decrypt_thread.finished_signal.connect(self._on_decrypt_finished)

        self._start_progress_simulation()
        self.decrypt_thread.start()

    def stop_decrypt(self):
        """停止解密"""
        if self.decrypt_thread and self.decrypt_thread.isRunning():
            self.decrypt_thread.terminate()
            self.decrypt_thread.wait()

        self._add_log("解密过程已停止")
        self._reset_ui()

    def _start_progress_simulation(self):
        """模拟进度更新"""
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self._update_progress)
        self.progress_timer.start(100)
        self.current_progress = 0

    def _update_progress(self):
        """更新进度条"""
        if self.current_progress < 100:
            self.current_progress += 1
            self.progress_bar.setValue(self.current_progress)
        else:
            self.progress_timer.stop()

    def _on_decrypt_finished(self, success, message):
        """解密完成回调"""
        self.progress_timer.stop()
        self.progress_bar.setValue(100)

        if success:
            self._add_log(f"✓ {message}")
            self.status_bar.showMessage("解密完成")
        else:
            self._add_log(f"✗ {message}")
            self.status_bar.showMessage("解密失败")

        QTimer.singleShot(2000, self._reset_ui)

    def _reset_ui(self):
        """重置UI状态"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self._update_ui_state()

    def closeEvent(self, event):
        """窗口关闭事件"""
        if self.decrypt_thread and self.decrypt_thread.isRunning():
            self.decrypt_thread.terminate()
            self.decrypt_thread.wait()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("QQ音乐解密工具")
    app.setApplicationVersion("1.0.0")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
