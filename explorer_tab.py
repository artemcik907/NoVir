import os
import shutil
import string
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, 
                             QPushButton, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMessageBox, QMenu, QAbstractItemView, QStyle)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon

try:
    import novir_native
except ImportError:
    novir_native = None

class ExplorerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_path = "Компьютер"
        self.history = []
        self.init_ui()
        self.refresh_files()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Top bar
        top_bar = QWidget()
        top_bar.setStyleSheet("background-color: #000000; border-bottom: 1px solid #000000;")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(10, 10, 10, 10)
        top_layout.setSpacing(10)

        self.btn_back = QPushButton("◀")
        self.btn_back.setFixedSize(30, 30)
        self.btn_back.setStyleSheet("QPushButton { background-color: transparent; border: none; color: #ffffff; font-size: 16px; font-weight: bold; } QPushButton:hover { background-color: #4a4a5a; border-radius: 0px; }")
        self.btn_back.clicked.connect(self.go_back)
        top_layout.addWidget(self.btn_back)

        self.btn_refresh = QPushButton("↻")
        self.btn_refresh.setFixedSize(30, 30)
        self.btn_refresh.setStyleSheet("QPushButton { background-color: transparent; border: none; color: #ffffff; font-size: 16px; font-weight: bold; } QPushButton:hover { background-color: #4a4a5a; border-radius: 0px; }")
        self.btn_refresh.clicked.connect(self.refresh_files)
        top_layout.addWidget(self.btn_refresh)

        self.path_edit = QLineEdit()
        self.path_edit.setFixedHeight(30)
        self.path_edit.setStyleSheet("QLineEdit { background-color: #000000; border: 1px solid #333333; border-radius: 0px; padding: 0 10px; color: #ffffff; }")
        self.path_edit.returnPressed.connect(self.navigate_to_path)
        top_layout.addWidget(self.path_edit)

        self.layout.addWidget(top_bar)

        # Table
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(["Имя", "Тип", "Размер", "Атрибуты"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.file_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.setShowGrid(False)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.file_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.file_table.setAlternatingRowColors(True)

        self.file_table.setStyleSheet("""
            QTableWidget {
                background-color: #000000;
                color: #ffffff;
                border: none;
                alternate-background-color: #000000;
            }
            QHeaderView::section {
                background-color: #000000;
                color: #ffffff;
                padding: 5px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background-color: #000000;
            }
        """)

        self.file_table.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.file_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self.show_context_menu)

        self.layout.addWidget(self.file_table)

    def get_logical_drives(self):
        drives = []
        bitmask = 0
        if novir_native and hasattr(novir_native, 'ctypes'):
            try:
                bitmask = novir_native.ctypes.windll.kernel32.GetLogicalDrives()
            except:
                pass
        
        if bitmask == 0:
            for letter in string.ascii_uppercase:
                if os.path.exists(f"{letter}:\\"):
                    drives.append(f"{letter}:\\")
        else:
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
        return drives

    def refresh_files(self):
        self.file_table.setRowCount(0)
        self.path_edit.setText(self.current_path)

        if self.current_path == "Компьютер":
            drives = self.get_logical_drives()
            for row, drive in enumerate(drives):
                self.file_table.insertRow(row)
                item = QTableWidgetItem(drive)
                item.setIcon(self.style().standardIcon(QStyle.SP_DriveHDIcon))
                self.file_table.setItem(row, 0, item)
                self.file_table.setItem(row, 1, QTableWidgetItem("Локальный диск"))
                self.file_table.setItem(row, 2, QTableWidgetItem(""))
                self.file_table.setItem(row, 3, QTableWidgetItem(""))
            return

        if not os.path.exists(self.current_path):
            self.current_path = "Компьютер"
            self.refresh_files()
            return

        try:
            with os.scandir(self.current_path) as it:
                dirs = []
                files = []
                for entry in it:
                    try:
                        if entry.is_dir():
                            dirs.append(entry.name)
                        else:
                            try:
                                stat = entry.stat()
                                size = stat.st_size
                            except:
                                size = -1
                            files.append((entry.name, size))
                    except:
                        pass
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Нет доступа:\n{e}")
            self.go_back()
            return

        dirs.sort(key=str.lower)
        files.sort(key=lambda x: str.lower(x[0]))

        row = 0
        for d in dirs:
            self.file_table.insertRow(row)
            item = QTableWidgetItem(d)
            item.setIcon(self.style().standardIcon(QStyle.SP_DirIcon))
            item.setData(Qt.UserRole, os.path.join(self.current_path, d))
            self.file_table.setItem(row, 0, item)
            self.file_table.setItem(row, 1, QTableWidgetItem("Папка"))
            self.file_table.setItem(row, 2, QTableWidgetItem(""))
            self.file_table.setItem(row, 3, QTableWidgetItem(""))
            row += 1

        for f_tuple in files:
            f, size = f_tuple
            self.file_table.insertRow(row)
            item = QTableWidgetItem(f)
            item.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
            full_path = os.path.join(self.current_path, f)
            item.setData(Qt.UserRole, full_path)
            self.file_table.setItem(row, 0, item)
            
            ext = os.path.splitext(f)[1].upper()
            self.file_table.setItem(row, 1, QTableWidgetItem(f"Файл {ext}" if ext else "Файл"))
            
            if size >= 0:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = ""
            self.file_table.setItem(row, 2, QTableWidgetItem(size_str))
            self.file_table.setItem(row, 3, QTableWidgetItem(""))
            row += 1

    def go_back(self):
        if self.current_path == "Компьютер":
            return
        parent_dir = os.path.dirname(self.current_path)
        if parent_dir == self.current_path:
            self.current_path = "Компьютер"
        else:
            self.current_path = parent_dir
        self.refresh_files()

    def navigate_to_path(self):
        new_path = self.path_edit.text().strip()
        if new_path.lower() == "компьютер" or new_path == "":
            self.current_path = "Компьютер"
        elif os.path.isdir(new_path):
            self.current_path = new_path
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный путь")
            self.path_edit.setText(self.current_path)
            return
        self.refresh_files()

    def on_item_double_clicked(self, item):
        row = item.row()
        name_item = self.file_table.item(row, 0)
        if self.current_path == "Компьютер":
            self.current_path = name_item.text()
            self.refresh_files()
            return
        
        path = name_item.data(Qt.UserRole)
        if os.path.isdir(path):
            self.current_path = path
            self.refresh_files()
        else:
            try:
                os.startfile(path)
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", str(e))

    def show_context_menu(self, pos):
        item = self.file_table.itemAt(pos)
        if not item: return
        
        row = item.row()
        name_item = self.file_table.item(row, 0)
        
        if self.current_path == "Компьютер":
            path = name_item.text()
        else:
            path = name_item.data(Qt.UserRole)
            
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #000000; color: white; border: 1px solid #333333; } QMenu::item:selected { background-color: #4a4a5a; }")
        
        action_open = menu.addAction("Открыть")
        menu.addSeparator()
        
        if self.current_path != "Компьютер":
            action_unlock = menu.addAction("Разблокировать (Unlocker)")
            action_own = menu.addAction("Стать владельцем (Take Ownership)")
            action_del = menu.addAction("Удалить принудительно (Force Delete)")
            
            action = menu.exec(self.file_table.viewport().mapToGlobal(pos))
            
            if action == action_open:
                self.on_item_double_clicked(name_item)
            elif action == action_unlock:
                if novir_native and hasattr(novir_native, 'unlock_file'):
                    res = novir_native.unlock_file(path)
                    QMessageBox.information(self, "Разблокировка", "Файл разблокирован!" if res else "Не удалось разблокировать или файл не заблокирован.")
                else:
                    QMessageBox.warning(self, "Ошибка", "Модуль novir_native недоступен.")
            elif action == action_own:
                if novir_native and hasattr(novir_native, 'take_ownership'):
                    res = novir_native.take_ownership(path)
                    QMessageBox.information(self, "Владелец", "Права получены!" if res else "Не удалось получить права.")
                else:
                    QMessageBox.warning(self, "Ошибка", "Модуль novir_native недоступен.")
            elif action == action_del:
                reply = QMessageBox.question(self, "Удаление", f"Удалить безвозвратно?\n{path}", QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.Yes:
                    try:
                        from virus_recovery import safe_remove, safe_rmtree

                        if os.path.isdir(path):
                            deleted = safe_rmtree(path, self)
                        else:
                            deleted = safe_remove(path)
                        if deleted:
                            self.refresh_files()
                        else:
                            QMessageBox.warning(self, "Удаление заблокировано", "Путь не прошел проверку безопасности.")
                    except Exception as e:
                        QMessageBox.warning(self, "Ошибка", f"Обычное удаление не удалось: {e}\nПопробуйте сначала разблокировать.")
        else:
            action = menu.exec(self.file_table.viewport().mapToGlobal(pos))
            if action == action_open:
                self.on_item_double_clicked(name_item)
