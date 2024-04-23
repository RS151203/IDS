import datetime
import multiprocessing
import os
import subprocess
import sys
import psutil
from PySide2 import QtCore, QtGui, QtWidgets
from PySide2.QtCharts import QtCharts
from PySide2.QtCore import (QCoreApplication, QPropertyAnimation, QDate, QDateTime, QMetaObject, QObject, QPoint, QRect,
                            QSize, QTime, QUrl, Qt, QEvent, Signal, QTimer, QEasingCurve)
from PySide2.QtGui import (QBrush, QColor, QConicalGradient, QCursor, QFont, QFontDatabase, QIcon, QKeySequence,
                           QLinearGradient, QPalette, QPainter, QPixmap, QRadialGradient)
from PySide2.QtWidgets import *
from email_validator import validate_email, EmailNotValidError
from tensorflow.keras.models import load_model
from worker import start_live_feed, start_log_and_alert, stop_live_feed, stop_log_and_alert
from gui import Ui_MainWindow
from user_auth import create_connection, check_user, change_user_credentials, add_email, get_email, delete_email
from graphs import CPUGraph, MemoryGraph, NetworkGraph

WINDOW_SIZE = 0
TOGGLE_STATUS = 80
model = None


def load_model_process():
    global model
    model = load_model("aegis.h5")


def open_log_folder():
    if os.name == 'nt':  # Windows
        log_folder_path = r"C:\Aegis IDS\Log Files"
        if not os.path.exists(log_folder_path):
            os.makedirs(log_folder_path)
        subprocess.Popen(f'explorer "{log_folder_path}"')
    elif os.name == 'posix':  # Linux
        log_folder_path = "/Aegis_IDS/Log_Files"
        if not os.path.exists(log_folder_path):
            os.makedirs(log_folder_path)
        subprocess.Popen(['xdg-open', log_folder_path])
    else:
        print("Unsupported operating system")


class MainWindow(QMainWindow, Ui_MainWindow):
    stackSignal = Signal()
    data_updated = Signal(object)  # Define the signal at the class level

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setupUi(self)
        self.show()
        self.center()
        self.ui = Ui_MainWindow()
        global window_obj
        window_obj = self.ui

        # LOADING MODEL
        load_model_process()

        # LOGIN
        self.login_button.clicked.connect(self.verification_login)
        self.error_popup_area.hide()
        self.cancel_error_popup.clicked.connect(lambda: self.error_popup_area.hide())
        self.show_password_check_box.stateChanged.connect(self.show_password)

        self.stackedWidget.setCurrentIndex(1)

        # WORKER PROCESS
        self.network_data_queue = multiprocessing.Queue()
        # Use QTimer to periodically check for updates
        self.worker_timer = QTimer(self)
        self.worker_timer.timeout.connect(self.check_network_data_queue)
        self.worker_timer.start(1000)

        self.network_log_data_queue = multiprocessing.Queue()

        self.alert_queue = multiprocessing.Queue()
        self.worker_timer_alert = QTimer(self)
        self.worker_timer_alert.timeout.connect(self.check_alert_queue)
        self.worker_timer_alert.start(1000)

        # MAIN
        # Window_Control_Buttons
        self.exit.clicked.connect(self.close_all)
        self.minimize.clicked.connect(lambda: self.showMinimized())
        self.maxmize.clicked.connect(lambda: self.restore_or_maximize_window())

        # Menu
        self.menu_button.clicked.connect(self.toggleMenu)
        self.home_button.clicked.connect(lambda: self.stackedWidget_2.setCurrentIndex(0))
        self.settings_button.clicked.connect(lambda: self.stackedWidget_2.setCurrentIndex(1))
        self.logout_button.clicked.connect(self.logging_out)  # lambda needs to add bracket after function name
        self.home_button.clicked.connect(lambda: self.page_indicator.move(0, self.home_button.pos().y()))
        self.settings_button.clicked.connect(lambda: self.page_indicator.move(0, self.settings_button.pos().y()))
        self.exit_button.clicked.connect(self.close_all)
        self.logs_button.clicked.connect(open_log_folder)

        # Time
        self.timer = QTimer()
        self.timer.timeout.connect(self.updateTime)
        self.timer.start(1000)
        self.updateTime()  # Call updateTime initially to set the label to current time

        # Graphs
        # CPU Usage Graph
        self.cpu_layout = QVBoxLayout()
        self.cpu_graph_area.setLayout(self.cpu_layout)
        self.cpu_usage_canvas = CPUGraph()
        self.cpu_layout.addWidget(self.cpu_usage_canvas.canvas)
        # Memory Usage Graph
        self.memory_layout = QVBoxLayout()
        self.memory_graph_area.setLayout(self.memory_layout)
        self.memory_usage_canvas = MemoryGraph()
        self.memory_layout.addWidget(self.memory_usage_canvas.canvas)
        self.total_memory = round(psutil.virtual_memory().total / (1024 * 1024 * 1024), 1)
        self.memory_usage_label.setText(f"0/{self.total_memory} GB (0%)")
        # Network Usage Graph
        self.network_layout = QVBoxLayout()
        self.network_graph_area.setLayout(self.network_layout)
        self.network_usage_canvas = NetworkGraph()
        self.network_layout.addWidget(self.network_usage_canvas.canvas)
        # Graph Area Labels
        self.labels_timer = QTimer()
        self.labels_timer.timeout.connect(self.memory_usage)
        self.labels_timer.timeout.connect(self.cpu_usage)
        self.prev_sent_bytes = psutil.net_io_counters().bytes_sent
        self.prev_recv_bytes = psutil.net_io_counters().bytes_recv
        self.labels_timer.timeout.connect(self.network_usage)
        self.labels_updating = False
        # Button
        self.power_button.clicked.connect(lambda: self.cpu_usage_canvas.toggle_update())
        self.power_button.clicked.connect(lambda: self.memory_usage_canvas.toggle_update())
        self.power_button.clicked.connect(lambda: self.network_usage_canvas.toggle_update())
        self.power_button.clicked.connect(lambda: self.toggle_update_labels())
        self.power_button.clicked.connect(lambda: self.add_alert_to_table(risk_level="High"))

        # Live Table
        self.table = self.tableWidget
        # self.table.horizontalHeader().setVisible(True)
        # Columns Sizes
        self.table.setColumnWidth(0, 300)
        self.table.setColumnWidth(1, 300)
        self.table.setColumnWidth(2, 150)
        self.table.setColumnWidth(3, 170)
        self.table.setColumnWidth(4, 140)
        self.table.setColumnWidth(5, 160)
        # Adding Data in Rows
        self.power_button.clicked.connect(lambda: self.network_live_feed_process())
        self.power_button.clicked.connect(lambda: self.alert_check())
        self.network_feed_is_running = False
        self.log_and_alert_is_running = False

        # Alert Table
        self.alert_table.horizontalHeader().setVisible(True)
        self.alert_table.setColumnWidth(0, 300)
        self.alert_table.setColumnWidth(1, 900)

        # SETTINGS
        self.update_user_config_button.clicked.connect(lambda: self.update_user_config(user=self.user_name_info.text()))
        self.error_popup_2.hide()
        self.cancel_error_popup_2.clicked.connect(lambda: self.error_popup_2.hide())
        self.add_email_address_button_4.clicked.connect(self.email_add)

        if os.name == 'nt':  # Windows
            self.log_folder_path = r"C:\Aegis IDS\Log Files"
        elif os.name == 'posix':  # Linux
            self.log_folder_path = "/Aegis_IDS/Log_Files"

    def center(self):
        qr = self.frameGeometry()
        cp = QApplication.primaryScreen().availableGeometry()
        qr.moveCenter(cp.center())
        self.move(qr.topLeft())

    def verification_login(self):

        conn = create_connection("user.db")

        username = self.user_name.text()
        password = self.password.text()

        result = check_user(conn, username, password)

        if result:
            self.stackedWidget.setCurrentIndex(1)
            self.stackedWidget_2.setCurrentIndex(0)
            self.page_indicator.move(0, self.home_button.pos().y())
            self.user_name_info.setText(username)
            self.current_username.setText(username)
            self.email_address_area_4.setText(get_email(conn, username))
        else:
            self.show_error("Username or Password incorrect")

    def show_error(self, message):
        self.error_text.setText(message)
        self.error_popup_area.show()

    def show_password(self, state):
        if state == Qt.Checked:
            self.password.setEchoMode(QLineEdit.Normal)
        else:
            self.password.setEchoMode(QLineEdit.Password)

    def restore_or_maximize_window(self):
        # global variable for window size
        global WINDOW_SIZE
        win_status = WINDOW_SIZE
        if win_status == 0:
            WINDOW_SIZE = 1
            self.showFullScreen()
        else:
            WINDOW_SIZE = 0
            self.showNormal()

    def logging_out(self):
        if self.power_button.isChecked():
            self.power_button.setChecked(False)
            self.cpu_usage_canvas.toggle_update()
            self.memory_usage_canvas.toggle_update()
            self.network_usage_canvas.toggle_update()
            self.toggle_update_labels()
            self.network_live_feed_process()
        self.stackedWidget.setCurrentIndex(0)
        self.user_name_info.clear()
        self.user_name.clear()
        self.password.clear()

    def updateTime(self):
        current_time = QTime.currentTime()
        time_str = current_time.toString('hh:mm:ss')
        self.label_42.setText(time_str)

    def toggleMenu(self):
        global TOGGLE_STATUS
        STATUS = TOGGLE_STATUS
        duration = 500
        if STATUS == 80:

            # TODO EXPANDING ANIMATION
            self.animation = QPropertyAnimation(self.menu, b"minimumWidth")
            self.animation.setDuration(duration)
            self.animation.setStartValue(80)
            self.animation.setEndValue(250)
            self.animation.setEasingCurve(QEasingCurve.OutExpo)
            self.animation.start()

            TOGGLE_STATUS = 150

        else:  # TODO COLLAPSING ANIMATION minimumHeight
            self.animation = QPropertyAnimation(self.menu, b"minimumWidth")
            self.animation.setDuration(duration)
            self.animation.setStartValue(250)
            self.animation.setEndValue(80)
            self.animation.setEasingCurve(QEasingCurve.OutExpo)
            self.animation.start()
            TOGGLE_STATUS = 80

    def update_user_config(self, user):
        current_username = self.current_username.text()
        current_password = self.current_password.text()
        new_username = self.new_username.text()
        new_password = self.new_password.text()

        conn = create_connection("user.db")
        if new_username or new_password:
            result = check_user(conn, current_username, current_password)
            if result:
                username = change_user_credentials(conn, current_username, current_password, new_username, new_password)
                self.current_username.setText(username)
                self.user_name_info.setText(username)
                self.email_address_area_4.setText(get_email(conn, username))
                self.current_password.setText("")
                self.new_username.setText("")
                self.new_password.setText("")
            else:
                self.error_text_2.setText("Current Username or Password is incorrect.")
                self.error_popup_2.show()
                self.current_username.setText(user)
                self.current_password.setText("")
        else:
            self.error_text_2.setText("Add new username or new password.")
            self.error_popup_2.show()
            self.current_username.setText(user)
            self.current_password.setText("")

    def email_add(self):
        conn = create_connection("user.db")
        emails = self.email_address_area_4.toPlainText().replace(" ", "")
        if emails:
            email_array = emails.split(",")
            all_valid = True
            for email in email_array:
                try:
                    validate_email(email)
                except EmailNotValidError:
                    all_valid = False
                    break
            if all_valid:
                add_email(conn, username=self.current_username.text(), email=emails)
                self.email_address_area_4.setText(get_email(conn, username=self.current_username.text()))
            else:
                self.error_text_2.setText("Email or Emails not valid.")
                self.error_popup_2.show()
                self.email_address_area_4.setText(get_email(conn, username=self.current_username.text()))
        else:
            delete_email(conn, username=self.current_username.text())
            self.email_address_area_4.setText("")

    def cpu_usage(self):
        cpu_use_per = psutil.cpu_percent()
        cpu_freq = psutil.cpu_freq()
        cpu_freq_ghz = cpu_freq.current / 1000 if cpu_freq is not None else 0
        self.cpu_usage_label.setText(f"{cpu_use_per:.0f}% Usage")
        self.cpu_frequency_label.setText(f"{cpu_freq_ghz:.2f} GHz")

    def memory_usage(self):
        memory_use_per = psutil.virtual_memory().percent
        memory_use = psutil.virtual_memory().used / (1024 * 1024 * 1024)
        self.memory_usage_label.setText(f"{memory_use:.1f}/{self.total_memory} GB ({memory_use_per:.0f}%)")

    def network_usage(self):
        current_sent = psutil.net_io_counters().bytes_sent
        current_recv = psutil.net_io_counters().bytes_recv

        sent_speed = current_sent - self.prev_sent_bytes
        recv_speed = current_recv - self.prev_recv_bytes

        self.prev_sent_bytes = current_sent
        self.prev_recv_bytes = current_recv

        sent_speed, sent_unit = (sent_speed / (1024 * 1024), "Mbps") if sent_speed > 99999 else (
            sent_speed / 1024, "kbps")
        recv_speed, recv_unit = (recv_speed / (1024 * 1024), "Mbps") if recv_speed > 99999 else (
            recv_speed / 1024, "kbps")

        self.network_throughput_label.setText(f"S: {sent_speed:.2f} {sent_unit}")
        self.network_throughput_label_2.setText(f"R: {recv_speed:.2f} {recv_unit}")

    def toggle_update_labels(self):
        if self.labels_updating:
            self.labels_timer.stop()
        else:
            self.labels_timer.start(500)
        self.labels_updating = not self.labels_updating

    def network_live_feed_process(self):
        if self.network_feed_is_running:
            stop_live_feed()
            self.process.terminate()
        else:
            self.table.horizontalHeader().setVisible(True)
            self.process = multiprocessing.Process(target=start_live_feed, args=(self.network_data_queue,))
            self.process.start()
        self.network_feed_is_running = not self.network_feed_is_running

    def check_network_data_queue(self):
        while not self.network_data_queue.empty():
            network_data = self.network_data_queue.get()  # Retrieve data from the network_data_queue
            self.update_table(network_data)  # Process the retrieved data

    def alert_check(self):
        global log_folder_path
        if self.log_and_alert_is_running:
            stop_log_and_alert()
            self.log_and_alert_process.terminate()
        else:
            self.log_and_alert_process = multiprocessing.Process(target=start_log_and_alert,
                                                                 args=(
                                                                     os.name, self.log_folder_path, model,
                                                                     self.network_log_data_queue,
                                                                     self.alert_queue,))
            self.log_and_alert_process.start()
        self.log_and_alert_is_running = not self.log_and_alert_is_running
        pass

    def check_alert_queue(self):
        while not self.network_log_data_queue.empty():
            alert_data = self.alert_queue.get()  # Retrieve data from the queue
            if int(alert_data) == 0:
                print("Not Alert")
            else:
                print("Alert")
            # self.update_table(network_data)  # Process the retrieved data
        pass

    def update_table(self, network_data):
        self.tableWidget.setRowCount(0)  # Clear existing rows
        for row_index, row_data in enumerate(network_data.values):
            self.tableWidget.insertRow(row_index)  # Insert new row
            for col_index, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.tableWidget.setItem(row_index, col_index, item)
                item.setTextAlignment(Qt.AlignCenter)

    def add_alert_to_table(self, risk_level):
        QMessageBox.warning(self, 'Alert', 'A Suspicious activity is detected')
        self.live_area_chart.setCurrentIndex(1)
        timestamp = datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        risk_message = "Aegis has detected suspicious activity on the network. Immediate action is recommended."
        row_position = self.alert_table.rowCount()
        self.alert_table.insertRow(row_position)

        timestamp_item = QTableWidgetItem(timestamp)
        timestamp_item.setTextAlignment(Qt.AlignCenter)
        self.alert_table.setItem(row_position, 0, timestamp_item)

        risk_message_item = QTableWidgetItem(risk_message)
        risk_message_item.setTextAlignment(Qt.AlignCenter)
        self.alert_table.setItem(row_position, 1, risk_message_item)

        risk_level_item = QTableWidgetItem(risk_level)
        risk_level_item.setTextAlignment(Qt.AlignCenter)
        self.alert_table.setItem(row_position, 2, risk_level_item)

    def close_all(self):
        if self.network_feed_is_running:
            self.network_live_feed_process()
            self.close()
        if self.log_and_alert_is_running:
            self.alert_check()
            self.close()
        else:
            self.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
