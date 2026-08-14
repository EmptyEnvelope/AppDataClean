# AppData Cleaner GUI (Advanced Safe Version v12)
# Requires: PySide6, humanize (pip install PySide6 humanize)

import os
import sys
import time
import ctypes
import re
from pathlib import Path
from threading import Event
from humanize import naturalsize

from PySide6.QtCore import Qt, QThread, Signal, QSortFilterProxyModel, QRect
from PySide6.QtGui import QStandardItem, QStandardItemModel, QColor, QPainter, QFontMetrics, QPen, QPalette, QMouseEvent
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QPushButton, QProgressBar, QTableView, QVBoxLayout,
    QWidget, QHeaderView, QDoubleSpinBox, QComboBox, QSizePolicy,
    QStyledItemDelegate, QStyle, QStyleOptionViewItem
)

# ==============================================================================
# 规则库引擎与系统设置
# ==============================================================================
SAFE_PATTERN = re.compile(r'\b(cache|temp|tmp|crash|dump|logs)\b', re.IGNORECASE)

CHROME_CACHES = {
    "gpucache", "dawncache", "code cache", "cache_data", 
    "network persistent state", "shadercache", "grshadercache"
}

DEV_CACHES = {
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", 
    ".vs", "ipch", ".gradle", ".idea_cache", "npm-cache", "yarn-cache"
}

EXCLUDE_KEYWORDS = {
    "package cache",       
    "windows\\installer",  
    "system32",            
    "winsxs"               
}

def run_as_admin():
    if sys.platform.startswith("win"):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False

        if not is_admin:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}" {params}', None, 1
            )
            sys.exit(0)

def empty_folder_to_recycle_bin(path: str) -> bool:
    try:
        from ctypes import wintypes
        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [('hwnd', wintypes.HWND), ('wFunc', wintypes.UINT), ('pFrom', wintypes.LPCWSTR),
                        ('pTo', wintypes.LPCWSTR), ('fFlags', wintypes.DWORD), ('fAnyOperationsAborted', wintypes.BOOL),
                        ('hNameMappings', wintypes.LPVOID), ('lpszProgressTitle', wintypes.LPCWSTR)]
        
        wildcard_path = path.rstrip('\\/') + '\\*\0\0'
        
        fileop = SHFILEOPSTRUCTW()
        fileop.wFunc = 3 
        fileop.pFrom = wildcard_path
        fileop.fFlags = 0x0040 | 0x0010 | 0x0004 | 0x0400 
        res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(fileop))
        return res == 0
    except Exception:
        return False

# ==============================================================================
# 智能缩略标签组件
# ==============================================================================
class ElidedLabel(QLabel):
    def __init__(self, text=""):
        super().__init__(text)
        self._text = text

    def setText(self, text):
        self._text = text
        self.update()  

    def text(self):
        return self._text

    def paintEvent(self, event):
        painter = QPainter(self)
        metrics = QFontMetrics(self.font())
        elided = metrics.elidedText(self._text, Qt.ElideRight, self.width())
        painter.drawText(self.rect(), self.alignment(), elided)

# ==============================================================================
# 路径列智能缩略 delegate：弹性三明治省略
# ==============================================================================
class SmartPathDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        self.initStyleOption(option, index)
        text = option.text
        fm = QFontMetrics(option.font)
        cell_w = option.rect.width()
        margin = 6
        available_w = cell_w - margin * 2

        draw_opt = QStyleOptionViewItem(option)
        draw_opt.text = "" 
        QApplication.style().drawControl(QStyle.CE_ItemViewItem, draw_opt, painter, option.widget)

        if not text: return

        fg_data = index.data(Qt.ForegroundRole)
        if fg_data is not None:
            pen = QPen(fg_data if isinstance(fg_data, QColor) else fg_data.color())
        else:
            pen = option.palette.color(QPalette.Text)

        painter.save()
        painter.setPen(pen)
        painter.setFont(option.font)

        display_text = text
        text_w = fm.horizontalAdvance(text)

        if text_w > available_w:
            parts = text.replace('/', '\\').split('\\')
            if len(parts) >= 3:
                drive = parts[0] + '\\'
                final_folder = '\\' + parts[-1]
                middle_text = '\\'.join(parts[1:-1])
                
                rem_w = available_w - fm.horizontalAdvance(drive) - fm.horizontalAdvance(final_folder)
                
                if rem_w > fm.horizontalAdvance("..."):
                    elided_mid = fm.elidedText(middle_text, Qt.ElideMiddle, rem_w)
                    display_text = f"{drive}{elided_mid}{final_folder}"
                else:
                    display_text = fm.elidedText(text, Qt.ElideMiddle, available_w)
            else:
                display_text = fm.elidedText(text, Qt.ElideMiddle, available_w)

        rect = option.rect.adjusted(margin, 0, -margin, 0)
        painter.drawText(rect, Qt.AlignLeft | Qt.AlignVCenter, display_text)
        painter.restore()

# ==============================================================================
# 工作线程与模型代理
# ==============================================================================
class ScanWorker(QThread):
    progress = Signal(int)
    current_path = Signal(str)
    folder_found = Signal(str, str, str, str)
    finished = Signal(int)

    def __init__(self, base_paths):
        super().__init__()
        self.base_paths = base_paths
        self._stop_event = Event()
        self.now = time.time()

    def stop(self): self._stop_event.set()

    def _assess_safety(self, path: Path) -> str:
        try: os.rename(str(path), str(path))
        except OSError: return "🔴 正在使用"
        
        try:
            mtime = path.stat().st_mtime
            age_days = (self.now - mtime) / 86400
        except OSError:
            return "🔴 无法访问权限"

        if age_days < 1: return "🔴 活跃数据 (<24小时)"
        
        is_sys_temp = "temp" in str(path).lower() or "download" in str(path).lower()
        days_int = int(age_days)
        
        if age_days > 3:
            if is_sys_temp: return f"🟢 极度安全 (系统区, {days_int}天前修改)"
            return f"🟢 较高安全 ({days_int}天前修改)"
        return f"🟡 中等风险 ({days_int}天前修改)"

    def run(self):
        self.results_count = 0
        for base_str in self.base_paths:
            if self._stop_event.is_set(): break
            base = Path(base_str)
            if not base.exists(): continue

            base_lower = base_str.lower()
            if base_lower.endswith("windows\\temp") or base_lower.endswith("softwaredistribution\\download"):
                size = self._dir_size(base)
                if size > 0:
                    self.results_count += 1
                    size_human = naturalsize(size, binary=True)
                    safety_rating = self._assess_safety(base)
                    self.folder_found.emit(str(base), size_human, str(size), safety_rating)
                    self.progress.emit(self.results_count)
                continue 
            self._scan_path(base)
        self.finished.emit(self.results_count)

    def _scan_path(self, path: Path):
        if self._stop_event.is_set(): return
        if any(black_kw in str(path).lower() for black_kw in EXCLUDE_KEYWORDS): return

        try:
            self.current_path.emit(f"正在扫描: {path}")
            for entry in path.iterdir():
                if not entry.is_dir(): continue
                if any(black_kw in str(entry).lower() for black_kw in EXCLUDE_KEYWORDS): continue
                
                name = entry.name.lower()
                is_target = SAFE_PATTERN.search(name) or name in CHROME_CACHES or name in DEV_CACHES

                if is_target:
                    size = self._dir_size(entry)
                    if size > 0:
                        self.results_count += 1
                        size_human = naturalsize(size, binary=True)
                        safety_rating = self._assess_safety(entry)
                        self.folder_found.emit(str(entry), size_human, str(size), safety_rating)
                        self.progress.emit(self.results_count)
                        continue 
                self._scan_path(entry)
        except PermissionError: pass

    def _dir_size(self, directory: Path) -> int:
        total = 0
        try:
            for root, _, files in os.walk(directory, topdown=True):
                for f in files:
                    try: total += (Path(root) / f).stat().st_size
                    except (OSError, PermissionError): pass
        except (OSError, PermissionError): pass
        return total

class RecycleWorker(QThread):
    progress = Signal(int)
    finished = Signal()

    def __init__(self, paths):
        super().__init__()
        self.paths = paths

    def run(self):
        for idx, p in enumerate(self.paths, 1):
            empty_folder_to_recycle_bin(p)
            self.progress.emit(idx)
        self.finished.emit()

class SortFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.min_size_bytes = 0

    def set_min_size(self, min_bytes: int):
        self.min_size_bytes = min_bytes
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if self.min_size_bytes > 0:
            size_item = self.sourceModel().item(source_row, 3)
            if size_item:
                size_bytes = size_item.data(Qt.UserRole)
                if size_bytes is not None and size_bytes < self.min_size_bytes:
                    return False
        return True

    def lessThan(self, left, right):
        if left.column() == 3: 
            left_data = self.sourceModel().data(left, Qt.UserRole)
            right_data = self.sourceModel().data(right, Qt.UserRole)
            if left_data is not None and right_data is not None:
                return left_data < right_data
        return super().lessThan(left, right)

# ==============================================================================
# 核心科技：接管鼠标左右键与框选不消失逻辑的专属 TableView
# ==============================================================================
class CustomTableView(QTableView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._drag_button = None

    def mousePressEvent(self, event):
        self._drag_button = event.button()
        index = self.indexAt(event.pos())
        
        # 1. 保护选中框不消失：如果点击的是已经蓝框选中的区域，拦截原生的重置行为！
        if index.isValid() and event.modifiers() == Qt.NoModifier and self.selectionModel().isSelected(index):
            self._update_checks()
            return  # 吃掉事件，阻断 Qt 默认的“点击即清空其它选中项”操作
            
        # 2. 伪造事件：如果你点击了右键，在底层把它包装成一个左键事件交给原生控件，
        # 这样就能骗过 Qt，用右键也能划出选中蓝框！
        if self._drag_button == Qt.RightButton:
            fake_event = QMouseEvent(
                event.type(), event.position(), event.globalPosition(), 
                Qt.LeftButton, event.buttons() | Qt.LeftButton, event.modifiers()
            )
            super().mousePressEvent(fake_event)
        else:
            super().mousePressEvent(event)
            
        self._update_checks()

    def mouseMoveEvent(self, event):
        # 同样，拖拽时也欺骗 Qt，让它误以为右键拖拽也是合法的框选操作
        if self._drag_button == Qt.RightButton:
            fake_event = QMouseEvent(
                event.type(), event.position(), event.globalPosition(), 
                Qt.LeftButton, event.buttons() | Qt.LeftButton, event.modifiers()
            )
            super().mouseMoveEvent(fake_event)
        else:
            super().mouseMoveEvent(event)
            
        if self._drag_button in (Qt.LeftButton, Qt.RightButton):
            self._update_checks()

    def mouseReleaseEvent(self, event):
        if self._drag_button == Qt.RightButton:
            fake_event = QMouseEvent(
                event.type(), event.position(), event.globalPosition(), 
                Qt.LeftButton, event.buttons() & ~Qt.RightButton, event.modifiers()
            )
            super().mouseReleaseEvent(fake_event)
        else:
            super().mouseReleaseEvent(event)
        self._drag_button = None

    def _update_checks(self):
        """精准打击：左键赋 Checked，右键赋 Unchecked"""
        if self._drag_button not in (Qt.LeftButton, Qt.RightButton): return
        state = Qt.Checked if self._drag_button == Qt.LeftButton else Qt.Unchecked
        
        proxy = self.model()
        if not proxy: return
        source = proxy.sourceModel()
        
        # 将选中区域内所有的行状态全部暴力同步
        for idx in self.selectionModel().selectedRows():
            src_idx = proxy.mapToSource(idx)
            item = source.item(src_idx.row(), 1)  # 第 1 列是复选框
            if item and item.checkState() != state:
                item.setCheckState(state)

# ==============================================================================
# UI 主窗口
# ==============================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AppData清理")
        self.resize(1100, 650)

        self.scan_btn = QPushButton("开始智能扫描")
        self.select_all_btn = QPushButton("全选安全项")
        self.deselect_all_btn = QPushButton("取消全选")
        
        self.delete_btn = QPushButton("安全清空至回收站")
        self.delete_btn.setStyleSheet("QPushButton { background:#d9534f; color:white; font-weight:bold; }")
        self.delete_btn.setFixedSize(140, 32)
        self.delete_btn.setEnabled(False)

        self.filter_label = QLabel("过滤小于:")
        self.filter_spin = QDoubleSpinBox()
        self.filter_spin.setRange(0, 102400)
        self.filter_spin.setSingleStep(1)
        self.filter_spin.setMinimumWidth(85)
        self.filter_spin.setMaximumWidth(120)
        
        self.filter_unit = QComboBox()
        self.filter_unit.addItems(["MB", "GB", "KB"])
        self.filter_unit.setMinimumWidth(60)
        self.filter_unit.setMaximumWidth(80)

        self.filter_spin.setValue(1.0)
        self.filter_unit.setCurrentText("MB")

        self.filter_spin.valueChanged.connect(self.on_filter_changed)
        self.filter_unit.currentIndexChanged.connect(self.on_filter_changed)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        # 接入自定义强化版 TableView
        self.table = CustomTableView()
        
        self.table.verticalHeader().setVisible(False)
        
        self.source_model = QStandardItemModel(0, 5) 
        self.source_model.setHorizontalHeaderLabels(["序号", "✔", "路径 (双击打开)", "体积", "安全评级"])
        
        self.proxy_model = SortFilterProxyModel()
        self.proxy_model.setSourceModel(self.source_model)
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        
        self.table.setColumnWidth(0, 50)  
        self.table.setColumnWidth(1, 40)  
        self.table.setColumnWidth(3, 110) 
        self.table.setColumnWidth(4, 220) 
        
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        header.setSectionResizeMode(4, QHeaderView.Fixed)

        self.path_delegate = SmartPathDelegate(self.table)
        self.table.setItemDelegateForColumn(2, self.path_delegate)
        
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.sortByColumn(3, Qt.DescendingOrder)
        self.table.doubleClicked.connect(self.on_table_double_clicked)

        self.status_label = ElidedLabel("就绪")
        self.status_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.status_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        
        self.size_info_label = QLabel("")
        self.size_info_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        self.size_info_label.setMinimumWidth(220) 
        self.size_info_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.status_label, 1) 
        bottom_layout.addWidget(self.size_info_label, 0)
        bottom_layout.addSpacing(15)
        bottom_layout.addWidget(self.delete_btn, 0)

        top_layout = QHBoxLayout()
        top_layout.addWidget(self.scan_btn)
        top_layout.addWidget(self.select_all_btn)
        top_layout.addWidget(self.deselect_all_btn)
        top_layout.addSpacing(20)
        top_layout.addWidget(self.filter_label)
        top_layout.addWidget(self.filter_spin)
        top_layout.addWidget(self.filter_unit)
        top_layout.addStretch()
        top_layout.addWidget(self.progress_bar)

        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addWidget(self.table)
        main_layout.addLayout(bottom_layout)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.scan_btn.clicked.connect(self.start_scan)
        self.select_all_btn.clicked.connect(self.select_safe_only)
        self.deselect_all_btn.clicked.connect(self.deselect_all)
        self.delete_btn.clicked.connect(self.start_delete)
        
        self._updating_checks = False
        self.source_model.itemChanged.connect(self.on_item_changed)

        self.scan_worker = None
        self.delete_worker = None
        self._rows_to_delete = [] 

        self.on_filter_changed()

    def on_filter_changed(self):
        val = self.filter_spin.value()
        unit = self.filter_unit.currentText()
        multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
        self.proxy_model.set_min_size(int(val * multipliers.get(unit, 1024**2)))
        self.update_totals()

    def on_table_double_clicked(self, index):
        if index.column() == 2: 
            source_idx = self.proxy_model.mapToSource(index)
            path = self.source_model.item(source_idx.row(), 2).text()
            if os.path.exists(path):
                os.startfile(path)

    def on_item_changed(self, item):
        # 兼容传统键盘操作：如果用户按空格键/直接点单个复选框触发的事件，依然进行全选中框同步
        if getattr(self, '_updating_checks', False): return

        if item.column() == 1:
            selection_model = self.table.selectionModel()
            
            if selection_model.hasSelection():
                selected_proxy_rows = set(idx.row() for idx in selection_model.selectedIndexes())
                source_rows = [self.proxy_model.mapToSource(self.proxy_model.index(r, 0)).row() for r in selected_proxy_rows]
                
                if item.row() in source_rows:
                    new_state = item.checkState()
                    self._updating_checks = True
                    for r in source_rows:
                        if r != item.row():
                            cb_item = self.source_model.item(r, 1)
                            if cb_item and cb_item.checkState() != new_state:
                                cb_item.setCheckState(new_state)
                    self._updating_checks = False

        self.update_totals()

    def start_scan(self):
        if self.scan_worker and self.scan_worker.isRunning(): return
        self.source_model.removeRows(0, self.source_model.rowCount())
        
        self.progress_bar.setVisible(False)
        self.status_label.setText("正在智能扫描中...")
        self.size_info_label.setText("")
        self.delete_btn.setEnabled(False)
        self.scan_btn.setEnabled(False)
        
        windir = os.environ.get("WINDIR")
        bases = [
            os.environ.get("APPDATA"),
            os.environ.get("LOCALAPPDATA"),
            os.environ.get("LOCALAPPDATA").replace("Local", "LocalLow") if os.environ.get("LOCALAPPDATA") else None,
            os.environ.get("PROGRAMDATA"),
            windir + "\\Temp" if windir else None,
            windir + "\\SoftwareDistribution\\Download" if windir else None
        ]
        bases = [b for b in bases if b and os.path.exists(b)]
        
        self.scan_worker = ScanWorker(bases)
        self.scan_worker.progress.connect(lambda n: self.status_label.setText(f"已找到 {n} 个候选文件夹"))
        self.scan_worker.current_path.connect(self.status_label.setText)
        self.scan_worker.folder_found.connect(self.add_folder_to_table)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.start()

    def add_folder_to_table(self, path, size_human, size_bytes_str, rating):
        row_idx = self.source_model.rowCount() + 1
        index_item = QStandardItem(str(row_idx))
        index_item.setTextAlignment(Qt.AlignCenter)
        index_item.setEditable(False)

        checkbox_item = QStandardItem()
        checkbox_item.setCheckable(True)
        checkbox_item.setCheckState(Qt.Unchecked) 
        checkbox_item.setEditable(False)
        
        path_item = QStandardItem(path)
        path_item.setForeground(QColor("#0066cc"))
        font = path_item.font()
        font.setUnderline(True)
        path_item.setFont(font)
        path_item.setToolTip(f"双击即可在 Windows 资源管理器中打开此文件夹:\n{path}")
        
        size_item = QStandardItem(size_human)
        size_item.setData(int(size_bytes_str), Qt.UserRole)
        
        rating_item = QStandardItem(rating)
        if "🟢" in rating: rating_item.setForeground(QColor("green"))
        elif "🟡" in rating: rating_item.setForeground(QColor("darkGoldenrod"))
        elif "🔴" in rating: rating_item.setForeground(QColor("red"))

        self.source_model.appendRow([index_item, checkbox_item, path_item, size_item, rating_item])
        self.update_totals()

    def scan_finished(self, total_count):
        self.status_label.setText(f"智能扫描完成，共拦截 {total_count} 个目标")
        self.scan_btn.setEnabled(True)
        self.table.sortByColumn(3, Qt.DescendingOrder)
        self.update_totals()

    def select_safe_only(self):
        for proxy_row in range(self.proxy_model.rowCount()):
            source_idx = self.proxy_model.mapToSource(self.proxy_model.index(proxy_row, 0))
            row = source_idx.row()
            rating_text = self.source_model.item(row, 4).text()
            if "🟢" in rating_text:
                self.source_model.item(row, 1).setCheckState(Qt.Checked)

    def deselect_all(self):
        for proxy_row in range(self.proxy_model.rowCount()):
            source_idx = self.proxy_model.mapToSource(self.proxy_model.index(proxy_row, 0))
            self.source_model.item(source_idx.row(), 1).setCheckState(Qt.Unchecked)

    def update_totals(self, *_):
        total_found = 0
        total_selected = 0
        selected_count = 0
        
        for proxy_row in range(self.proxy_model.rowCount()):
            row = self.proxy_model.mapToSource(self.proxy_model.index(proxy_row, 0)).row()
            size_bytes = self.source_model.item(row, 3).data(Qt.UserRole) or 0
            
            total_found += size_bytes
            if self.source_model.item(row, 1).checkState() == Qt.Checked:
                total_selected += size_bytes
                selected_count += 1
        
        found_h = naturalsize(total_found, binary=True)
        selected_h = naturalsize(total_selected, binary=True)
        
        if self.proxy_model.rowCount() > 0:
            self.size_info_label.setText(f"已选: [{selected_h} / 显示总计: {found_h}]")
        else:
            self.size_info_label.setText("")
        
        self.delete_btn.setEnabled(total_selected > 0 and selected_count > 0)

    def start_delete(self):
        paths_to_delete = []
        self._rows_to_delete = [] 
        has_warning = False

        for proxy_row in range(self.proxy_model.rowCount()):
            row = self.proxy_model.mapToSource(self.proxy_model.index(proxy_row, 0)).row()
            if self.source_model.item(row, 1).checkState() == Qt.Checked:
                rating = self.source_model.item(row, 4).text()
                if "🔴" in rating: has_warning = True
                paths_to_delete.append(self.source_model.item(row, 2).text())
                self._rows_to_delete.append(row) 

        if not paths_to_delete: return

        warn_msg = "\n\n⚠️ 注意：您勾选了带有红色危险警告的活跃项，清理可能导致正在运行的软件出错。" if has_warning else ""
        
        reply = QMessageBox.question(
            self, "确认清空",
            f"确定要将选中的 {len(paths_to_delete)} 个文件夹中的【所有内部文件】移至回收站吗？\n（清理完毕后，这些文件夹的原有结构将原封不动地保留）{warn_msg}",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes: return

        self.delete_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(paths_to_delete))
        self.status_label.setText("正在执行安全粉碎(移至回收站)…")

        self.delete_worker = RecycleWorker(paths_to_delete)
        self.delete_worker.progress.connect(self.progress_bar.setValue)
        self.delete_worker.finished.connect(self.deletion_finished)
        self.delete_worker.start()

    def deletion_finished(self):
        QMessageBox.information(self, "清理完成", "选中目标内的垃圾缓存已清空，安全移至回收站，并成功保留了原目录结构。")
        
        for row in sorted(self._rows_to_delete, reverse=True):
            self.source_model.removeRow(row)
            
        self._rows_to_delete = [] 
        
        self.progress_bar.setVisible(False)
        self.status_label.setText("清理操作完成")
        self.delete_btn.setEnabled(False)
        self.update_totals()
        
        for proxy_row in range(self.proxy_model.rowCount()):
            source_row = self.proxy_model.mapToSource(self.proxy_model.index(proxy_row, 0)).row()
            self.source_model.item(source_row, 0).setText(str(proxy_row + 1))

if __name__ == "__main__":
    run_as_admin()

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())