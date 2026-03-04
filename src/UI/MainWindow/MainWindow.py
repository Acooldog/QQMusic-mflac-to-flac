import logging
import os
import time
from typing import Dict, Optional

from PyQt5.QtCore import QThread, QTimer, QUrl, pyqtSignal
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QComboBox,
)

from src.Application.config_service import ConfigService
from src.Application.decrypt_job_service import DecryptJobService
from src.Application.format_policy_service import FormatPolicyService
from src.Helper.runtime_logging import get_plugins_config_path
from src.Infrastructure.ffmpeg_transcoder import FfmpegTranscoder
from src.Infrastructure.filesystem_adapter import FileSystemAdapter
from src.Infrastructure.frida_decrypt_gateway import FridaDecryptGateway
from src.Infrastructure.local_config_repository import LocalConfigRepository


logger = logging.getLogger("qqmusic_decrypt.ui.main_window")


class SettingsWindow(QDialog):
    """Settings dialog."""

    def __init__(self, settings: Dict, policy: FormatPolicyService, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.setFixedSize(420, 260)

        self.policy = policy
        self.settings = dict(settings)
        self.updated_settings: Optional[Dict] = None
        self.format_combos: Dict[str, QComboBox] = {}

        self._init_ui()
        self._load_settings()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)

        self.del_checkbox = QCheckBox("解密成功后删除原始加密文件")
        layout.addWidget(self.del_checkbox)

        self.wheel_checkbox = QCheckBox("循环运行")
        layout.addWidget(self.wheel_checkbox)

        format_group = QGroupBox("输出格式规则")
        format_layout = QFormLayout()

        for src_ext in self.policy.supported_sources():
            combo = QComboBox()
            for fmt in sorted(self.policy.FORMAT_WHITELIST):
                combo.addItem(fmt)
            self.format_combos[src_ext] = combo
            format_layout.addRow(f"{src_ext} ->", combo)

        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        button_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._on_save_clicked)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

    def _load_settings(self) -> None:
        self.del_checkbox.setChecked(bool(self.settings.get("del", False)))
        self.wheel_checkbox.setChecked(bool(self.settings.get("wheel", False)))

        normalized_rules = self.policy.normalize_rules(self.settings.get("format_rules", {}))
        for src_ext, combo in self.format_combos.items():
            target_fmt = normalized_rules.get(src_ext, self.policy.default_format(src_ext))
            idx = combo.findText(target_fmt)
            combo.setCurrentIndex(idx if idx >= 0 else 0)

    def _on_save_clicked(self) -> None:
        merged = dict(self.settings)
        merged["del"] = self.del_checkbox.isChecked()
        merged["wheel"] = self.wheel_checkbox.isChecked()

        rules = dict(merged.get("format_rules", {}))
        for src_ext, combo in self.format_combos.items():
            rules[src_ext] = combo.currentText().strip().lower()

        merged["format_rules"] = self.policy.normalize_rules(rules)
        self.updated_settings = merged
        self.accept()


class DecryptThread(QThread):
    """Worker thread to keep GUI responsive."""

    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(
        self,
        qq_music_dir: str,
        output_dir: str,
        del_flag: bool,
        wheel_flag: bool,
        format_rules: Dict[str, str],
        ffmpeg_missing_action: str,
    ):
        super().__init__()
        self.qq_music_dir = qq_music_dir
        self.output_dir = output_dir
        self.del_flag = del_flag
        self.wheel_flag = wheel_flag
        self.ffmpeg_missing_action = ffmpeg_missing_action

        self.policy = FormatPolicyService()
        self.format_rules = self.policy.normalize_rules(format_rules or {})

        self.job_service = DecryptJobService(
            decrypt_gateway=FridaDecryptGateway(),
            transcoder=FfmpegTranscoder(),
            fs_adapter=FileSystemAdapter(),
            format_policy=self.policy,
        )

    def _ffmpeg_missing_callback(self) -> str:
        return self.ffmpeg_missing_action

    def _run_once(self):
        return self.job_service.run(
            input_dir=self.qq_music_dir,
            output_dir=self.output_dir,
            del_original=self.del_flag,
            format_rules=self.format_rules,
            on_ffmpeg_missing=self._ffmpeg_missing_callback,
            on_log=self.log_signal.emit,
        )

    def run(self):
        last_success = True
        last_message = "未执行任务"

        while not self.isInterruptionRequested():
            try:
                last_success, last_message = self._run_once()
            except Exception as exc:
                logger.exception("解密线程发生异常")
                last_success = False
                last_message = f"线程错误: {exc}"

            if not self.wheel_flag:
                break

            if not last_success and self.ffmpeg_missing_action == "download_exit":
                break

            if self.isInterruptionRequested():
                break

            self.log_signal.emit("[*] 循环模式：3 秒后继续下一轮")
            for _ in range(30):
                if self.isInterruptionRequested():
                    break
                self.msleep(100)

        if self.isInterruptionRequested():
            self.finished_signal.emit(False, "任务已停止")
        else:
            self.finished_signal.emit(last_success, last_message)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.policy = FormatPolicyService()
        self.config_repo = LocalConfigRepository(get_plugins_config_path())
        self.config_service = ConfigService(self.config_repo, self.policy)

        self.settings = self.config_service.load()
        self.config_service.save(self.settings)

        self.qq_music_dir = self.settings.get("input", "")
        self.output_dir = self.settings.get("output", "")
        self.decrypt_thread: Optional[DecryptThread] = None

        self.progress_timer: Optional[QTimer] = None
        self.current_progress = 0

        self.setWindowTitle("QQ音乐解密工具")
        self.setFixedSize(720, 500)

        self._show_disclaimer()
        self._init_ui()

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")

        self._apply_loaded_paths()
        self._log_bootstrap_info()

    def _show_disclaimer(self) -> None:
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setWindowTitle("免责声明")
        msg_box.setText(
            "本软件仅供学习与研究使用。\n\n"
            "请勿用于任何商业用途。"
        )

        msg_box.addButton("收到", QMessageBox.AcceptRole)
        contact_btn = msg_box.addButton("联系作者", QMessageBox.ActionRole)
        source_btn = msg_box.addButton("打开仓库", QMessageBox.ActionRole)

        msg_box.exec_()

        if msg_box.clickedButton() == contact_btn:
            QDesktopServices.openUrl(QUrl("https://qm.qq.com/q/AgXshwMoMw"))
        elif msg_box.clickedButton() == source_btn:
            QDesktopServices.openUrl(QUrl("https://github.com/Acooldog/QQMusic-mflac-to-flac"))

    def _init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        title_label = QLabel("QQ音乐加密音频解密工具")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        main_layout.addWidget(title_label)

        self._create_directory_selection(main_layout)
        self._create_log_area(main_layout)
        self._create_control_buttons(main_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

    def _create_directory_selection(self, parent_layout: QVBoxLayout) -> None:
        qq_music_group = QGroupBox("QQ音乐下载目录")
        qq_music_layout = QHBoxLayout()

        self.qq_music_label = QLabel("未选择")
        self.qq_music_label.setStyleSheet("border: 1px solid gray; padding: 5px;")
        qq_music_layout.addWidget(self.qq_music_label)

        open_qq_music_btn = QPushButton("浏览")
        open_qq_music_btn.clicked.connect(self.open_qq_music_dialog)
        qq_music_layout.addWidget(open_qq_music_btn)

        qq_music_group.setLayout(qq_music_layout)
        parent_layout.addWidget(qq_music_group)

        output_group = QGroupBox("输出目录")
        output_layout = QHBoxLayout()

        self.output_label = QLabel("未选择")
        self.output_label.setStyleSheet("border: 1px solid gray; padding: 5px;")
        output_layout.addWidget(self.output_label)

        open_output_btn = QPushButton("浏览")
        open_output_btn.clicked.connect(self.open_output_dialog)
        output_layout.addWidget(open_output_btn)

        output_group.setLayout(output_layout)
        parent_layout.addWidget(output_group)

    def _create_log_area(self, parent_layout: QVBoxLayout) -> None:
        log_group = QGroupBox("处理日志")
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(210)
        log_layout.addWidget(self.log_text)

        clear_log_btn = QPushButton("清空日志")
        clear_log_btn.clicked.connect(self.log_text.clear)
        log_layout.addWidget(clear_log_btn)

        log_group.setLayout(log_layout)
        parent_layout.addWidget(log_group)

    def _create_control_buttons(self, parent_layout: QVBoxLayout) -> None:
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("开始")
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

    def _log_bootstrap_info(self) -> None:
        root_logger = logging.getLogger("qqmusic_decrypt")
        log_path = getattr(root_logger, "log_file_path", "")
        self._add_log(f"[*] 配置文件: {get_plugins_config_path()}")
        if log_path:
            self._add_log(f"[*] 日志文件: {log_path}")
        self._add_log(f"[*] 运行目录: {os.getcwd()}")

    def _apply_loaded_paths(self) -> None:
        if self.qq_music_dir:
            self.qq_music_label.setText(self.qq_music_dir)
        if self.output_dir:
            self.output_label.setText(self.output_dir)
        self._update_ui_state()

        if self.qq_music_dir and self.output_dir:
            self._add_log(f"[*] 已加载路径: 输入={self.qq_music_dir}, 输出={self.output_dir}")

    def _save_settings(self) -> None:
        self.config_service.save(self.settings)

    def _update_path_settings(self) -> None:
        self.settings["input"] = self.qq_music_dir
        self.settings["output"] = self.output_dir
        self._save_settings()

    def open_settings(self) -> None:
        dialog = SettingsWindow(self.settings, self.policy, self)
        if dialog.exec_() == QDialog.Accepted and dialog.updated_settings:
            self.settings = dialog.updated_settings
            self._save_settings()
            self._add_log(
                "[*] 设置已更新: "
                f"del={self.settings.get('del', False)}, "
                f"wheel={self.settings.get('wheel', False)}, "
                f"format_rules={self.settings.get('format_rules', {})}"
            )

    def open_qq_music_dialog(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "选择 QQ音乐 下载目录",
            "",
            QFileDialog.ShowDirsOnly,
        )
        if directory:
            self.qq_music_dir = directory
            self.qq_music_label.setText(directory)
            self._update_ui_state()
            self._add_log(f"[*] 输入目录: {directory}")
            self._update_path_settings()

    def open_output_dialog(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "选择输出目录",
            "",
            QFileDialog.ShowDirsOnly,
        )
        if directory:
            self.output_dir = directory
            self.output_label.setText(directory)
            self._update_ui_state()
            self._add_log(f"[*] 输出目录: {directory}")
            self._update_path_settings()

    def _update_ui_state(self) -> None:
        has_qq_music_dir = bool(self.qq_music_dir)
        has_output_dir = bool(self.output_dir)

        self.start_btn.setEnabled(has_qq_music_dir and has_output_dir)

        if has_qq_music_dir and has_output_dir:
            self.status_bar.showMessage("就绪，可开始解密")
        else:
            self.status_bar.showMessage("请选择输入和输出目录")

    def _add_log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())

    def _ask_ffmpeg_missing_action(self) -> str:
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("未检测到 FFmpeg")
        msg_box.setText(
            "当前格式规则需要转码，但系统未检测到 FFmpeg。\n\n"
            "请选择后续操作："
        )

        download_btn = msg_box.addButton("打开 FFmpeg 下载页并退出", QMessageBox.AcceptRole)
        fallback_btn = msg_box.addButton("仅本次只解密不转码", QMessageBox.ActionRole)
        msg_box.addButton("取消", QMessageBox.RejectRole)

        msg_box.exec_()
        clicked = msg_box.clickedButton()

        if clicked == download_btn:
            return "download_exit"
        if clicked == fallback_btn:
            return "decrypt_only"
        return "cancel"

    def _prepare_ffmpeg_action(self, format_rules: Dict[str, str]) -> Optional[str]:
        precheck_service = DecryptJobService(
            decrypt_gateway=FridaDecryptGateway(),
            transcoder=FfmpegTranscoder(),
            fs_adapter=FileSystemAdapter(),
            format_policy=self.policy,
        )

        if not precheck_service.requires_transcode(self.qq_music_dir, format_rules):
            return "decrypt_only"

        if precheck_service.transcoder.available:
            return "decrypt_only"

        action = self._ask_ffmpeg_missing_action()
        if action == "download_exit":
            QDesktopServices.openUrl(QUrl(FfmpegTranscoder.DOWNLOAD_URL))
            self._add_log("[!] FFmpeg 未安装，已打开下载页面并取消本次任务")
            return None
        if action == "cancel":
            self._add_log("[!] 用户已取消任务")
            return None

        self._add_log("[!] FFmpeg 未安装，本次任务仅解密不转码")
        return "decrypt_only"

    def start_decrypt(self) -> None:
        if not self.qq_music_dir or not self.output_dir:
            self._add_log("[!] 请先选择输入和输出目录")
            return

        if not os.path.isdir(self.qq_music_dir):
            self._add_log(f"[!] 输入目录不存在: {self.qq_music_dir}")
            return

        del_enabled = bool(self.settings.get("del", False))
        wheel_enabled = bool(self.settings.get("wheel", False))
        format_rules = self.settings.get("format_rules", self.policy.DEFAULT_RULES)

        ffmpeg_action = self._prepare_ffmpeg_action(format_rules)
        if ffmpeg_action is None:
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setRange(0, 100)

        self._add_log("[*] 开始解密任务")
        self._add_log(
            f"[*] 任务参数: del={del_enabled}, wheel={wheel_enabled}, format_rules={format_rules}"
        )
        self.status_bar.showMessage("正在运行...")

        if wheel_enabled:
            self._add_log("[*] 已启用循环模式")
            self.progress_bar.setRange(0, 0)

        self.decrypt_thread = DecryptThread(
            qq_music_dir=self.qq_music_dir,
            output_dir=self.output_dir,
            del_flag=del_enabled,
            wheel_flag=wheel_enabled,
            format_rules=format_rules,
            ffmpeg_missing_action=ffmpeg_action,
        )
        self.decrypt_thread.log_signal.connect(self._add_log)
        self.decrypt_thread.finished_signal.connect(self._on_decrypt_finished)

        if not wheel_enabled:
            self._start_progress_simulation()
        self.decrypt_thread.start()

    def stop_decrypt(self) -> None:
        if self.decrypt_thread and self.decrypt_thread.isRunning():
            self.decrypt_thread.requestInterruption()
            self.decrypt_thread.wait(3000)

        self._add_log("[!] 任务已停止")
        self._reset_ui()

    def _start_progress_simulation(self) -> None:
        self.current_progress = 0
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self._update_progress)
        self.progress_timer.start(100)

    def _update_progress(self) -> None:
        if self.current_progress < 99:
            self.current_progress += 1
            self.progress_bar.setValue(self.current_progress)
        elif self.progress_timer:
            self.progress_timer.stop()

    def _on_decrypt_finished(self, success: bool, message: str) -> None:
        if self.progress_timer:
            self.progress_timer.stop()

        if self.progress_bar.maximum() != 0:
            self.progress_bar.setValue(100)

        if success:
            self._add_log(f"[*] 任务完成: {message}")
            self.status_bar.showMessage("已完成")
        else:
            self._add_log(f"[!] 任务失败: {message}")
            self.status_bar.showMessage("失败")

        QTimer.singleShot(1200, self._reset_ui)

    def _reset_ui(self) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self._update_ui_state()

    def closeEvent(self, event):
        if self.decrypt_thread and self.decrypt_thread.isRunning():
            self.decrypt_thread.requestInterruption()
            self.decrypt_thread.wait(3000)
        event.accept()
