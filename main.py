from src.UI.MainWindow.MainWindow import MainWindow

from PyQt5.QtWidgets import *
import sys



if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("QQ音乐解密工具")
    app.setApplicationVersion("1.0.0")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
