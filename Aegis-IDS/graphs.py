import math
import psutil
import numpy as np
import time
from PySide2.QtCore import QTimer
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas


class ResourceGraph:
    def __init__(self, title):
        self.data = []
        self.max_data_points = 60
        self.x_index = 0

        self.fig = plt.figure(facecolor='None')
        self.canvas = FigureCanvas(self.fig)
        self.ax = self.canvas.figure.subplots()

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.is_running = False

        # All the Decoration
        self.ax.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=False)
        self.ax.tick_params(axis='y', which='both', left=False, right=False, labelleft=False)
        self.ax.spines['top'].set_visible(False)
        self.ax.spines['right'].set_visible(False)
        self.ax.set_facecolor('None')
        self.fig.suptitle(title, fontsize=10, color='white', fontname='Calibri')

    def toggle_update(self):
        if self.is_running:
            self.timer.stop()
            self.clear_graph()
        else:
            self.timer.start(500)  # Update every 500 milliseconds
        self.is_running = not self.is_running

    def clear_graph(self):
        self.ax.clear()
        self.data.clear()
        self.x_index = 0

    def update_graph(self):
        resource_percent = self.get_resource_percent()
        self.data.append(resource_percent)

        if len(self.data) > self.max_data_points:
            self.data.pop(0)
        x = np.arange(len(self.data))

        self.ax.clear()
        self.ax.fill_between(x, self.data, color='#001CCE', alpha=0.3)
        self.ax.set_ylim(0, 100)

        if len(self.data) > self.max_data_points:
            self.ax.set_xlim(self.x_index - self.max_data_points, self.x_index)
        else:
            self.ax.set_xlim(0, self.max_data_points)

        self.canvas.draw()
        self.x_index += 1

    def get_resource_percent(self):
        raise NotImplementedError("Subclasses must implement get_resource_percent method")


class CPUGraph(ResourceGraph):
    def __init__(self):
        super().__init__('CPU Usage')

    def get_resource_percent(self):
        return psutil.cpu_percent()


class MemoryGraph(ResourceGraph):
    def __init__(self):
        super().__init__('Memory Usage')

    def get_resource_percent(self):
        return psutil.virtual_memory().percent


class NetworkGraph(ResourceGraph):
    def __init__(self):
        super().__init__('Network Throughput')
        self.max_y_limit = 100
        self.y_limit_countdown = 0

    def get_resource_percent(self):
        net_io_start = psutil.net_io_counters()
        time.sleep(1)
        net_io_end = psutil.net_io_counters()
        total_per_sec = ((net_io_end.bytes_sent - net_io_start.bytes_sent) +
                         (net_io_end.bytes_recv - net_io_start.bytes_recv))
        total_per_sec = (total_per_sec/500) if total_per_sec > 99999 else total_per_sec/5000

        new_y_limit = calculate_y_limit(total_per_sec)

        if new_y_limit > self.max_y_limit:
            self.max_y_limit = new_y_limit
            self.y_limit_countdown = 60

        # Decrease the countdown
        if self.y_limit_countdown > 0:
            self.y_limit_countdown -= 1
            if self.y_limit_countdown == 0:
                self.ax.set_ylim(0, self.max_y_limit)

        return total_per_sec


def calculate_y_limit(total_per_sec):
    if total_per_sec <= 0:
        return 1
    else:
        order_of_magnitude = math.floor(math.log10(total_per_sec))
        if order_of_magnitude < 0:
            new_y_limit = 10 ** (order_of_magnitude + 2)
        else:
            new_y_limit = 10 ** (order_of_magnitude + 1)
        return new_y_limit
