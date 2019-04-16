#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

# -----------------------------------------------------------------------
class TTable(QtWidgets.QTableWidget):
    def __init__(self, labels, parent=None):
        super(TTable, self).__init__(parent)
        self.labels = labels
        self.setColumnCount(len(labels))
        self.setHorizontalHeaderLabels(labels)
        self.verticalHeader().hide()
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.horizontalHeader().model().setHeaderData(0, Qt.Horizontal, 
            Qt.AlignJustify, Qt.TextAlignmentRole)    
        self.horizontalHeader().setStretchLastSection(1)
        self.setSelectionMode(QtWidgets.QTableView.SingleSelection)
        self.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

    def copy_selected_value(self):
        item = self.currentItem()
        if item is not None:
            QtWidgets.QApplication.clipboard().setText(item.text())

    def copy_selected_row(self):
        selection = self.selectionModel()
        indexes = selection.selectedRows()
        if len(indexes) < 1:
            return
        text = ''
        for idx in indexes:
            row = idx.row()
            for col in range(0, self.columnCount()):
                item = self.item(row, col)
                if item:
                    text += item.text()
                text += '\t'
            text += '\n'
        QtWidgets.QApplication.clipboard().setText(text)

    def dump_table_as_csv(self):
        result = ''
        result += ';'.join(self.labels) + "\n"
        for i in range(0, self.rowCount()):
            columns = []
            for j in range(0, self.columnCount()):
                item = self.item(i, j).text()
                columns.append(item)
            result += ';'.join(columns) + "\n"
        return result

    def resize_columns(self, widths):
        for i, val in enumerate(widths):
            self.setColumnWidth(i, val)

    def resize_to_contents(self):
        self.resizeRowsToContents()
        self.resizeColumnsToContents()

    def set_row_color(self, num_row, color):
        for i in range(self.columnCount()):
            self.item(num_row, i).setBackground(color)

    def clear_table(self):
        self.setRowCount(0)

# -----------------------------------------------------------------------
class CustomWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(CustomWidget, self).__init__()
        self.parent = parent

    @property
    def heap(self):
        return self.parent.heap

    @property
    def cur_arena(self):
        return self.parent.cur_arena

    def _create_gui(self):
        raise NotImplementedError

# -----------------------------------------------------------------------
class InfoDialog(QtWidgets.QDialog):
    def __init__(self, info, parent=None):
        super(InfoDialog, self).__init__()
        self.parent = parent
        self.info = info
        self._create_gui()
        self.setModal(False)

    def _create_gui(self):
        self.t_info = QtWidgets.QTextEdit()
        self.t_info.setReadOnly(True)
        self.t_info.setFixedHeight(300)
        self.t_info.setFixedWidth(600)
        self.t_info.insertHtml(self.info)

        hbox = QtWidgets.QHBoxLayout()
        hbox.addWidget(self.t_info)
        self.setLayout(hbox)

# -----------------------------------------------------------------------

